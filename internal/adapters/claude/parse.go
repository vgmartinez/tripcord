package claude

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/pathx"
)

// redacted replaces env and header values. They commonly hold credentials,
// and config payloads reach rule excerpts and output sinks.
const redacted = "[REDACTED]"

// settingKinds is the curated set of Claude Code settings that run a
// program, reach the network, or decide which of those run. Each present
// key becomes one item. Unknown keys are not emitted.
//
// Reviewed against https://code.claude.com/docs/en/settings on 2026-10-31.
var settingKinds = map[string]model.ConfigKind{
	"permissions":                       model.ConfigKindPermissions,
	"sandbox":                           model.ConfigKindPermissions,
	"disableAllHooks":                   model.ConfigKindPermissions,
	"allowManagedHooksOnly":             model.ConfigKindPermissions,
	"allowManagedMcpServersOnly":        model.ConfigKindPermissions,
	"allowedMcpServers":                 model.ConfigKindPermissions,
	"deniedMcpServers":                  model.ConfigKindPermissions,
	"enableAllProjectMcpServers":        model.ConfigKindPermissions,
	"enabledMcpjsonServers":             model.ConfigKindPermissions,
	"disabledMcpjsonServers":            model.ConfigKindPermissions,
	"strictKnownMarketplaces":           model.ConfigKindPermissions,
	"skipDangerousModePermissionPrompt": model.ConfigKindPermissions,
	"enabledPlugins":                    model.ConfigKindPlugin,
	"extraKnownMarketplaces":            model.ConfigKindPlugin,
	"env":                               model.ConfigKindEnvSetup,
	"apiKeyHelper":                      model.ConfigKindEnvSetup,
	"statusLine":                        model.ConfigKindEnvSetup,
	"subagentStatusLine":                model.ConfigKindEnvSetup,
	"otelHeadersHelper":                 model.ConfigKindEnvSetup,
	"awsAuthRefresh":                    model.ConfigKindEnvSetup,
	"awsCredentialExport":               model.ConfigKindEnvSetup,
	"gcpAuthRefresh":                    model.ConfigKindEnvSetup,
	"fileSuggestion":                    model.ConfigKindEnvSetup,
}

// collector accumulates items and diagnostics for one Discover call.
type collector struct {
	harness model.Harness
	home    string
	items   []model.ConfigItem
	diags   []adapters.Diagnostic
	// key selects kit's k1 discriminator; nil selects s1.
	key *fpkey.Key
}

func newCollector(key *fpkey.Key) *collector {
	return &collector{harness: model.HarnessClaude, key: key}
}

func (c *collector) warn(scope model.Scope, path, format string, args ...any) {
	c.note(scope, path, false, format, args...)
}

func (c *collector) note(scope model.Scope, path string, informational bool, format string, args ...any) {
	c.diags = append(c.diags, adapters.Diagnostic{
		Harness:       c.harness,
		Scope:         scope,
		Path:          path,
		Message:       fmt.Sprintf(format, args...),
		Informational: informational,
	})
}

// src is one file being normalized.
type src struct {
	c     *collector
	scope model.Scope
	path  string
	sha   string
	// sanitized memoizes sanitizeString, which is pure: an entry's key
	// re-sanitizes strings its payload already did, such as a command.
	sanitized map[string]sanitizeResult
	// outputs is every string sanitizeString returned. kit's
	// sanitization is the same pipeline, so signer trusts them rather
	// than redacting each one a second time.
	outputs map[string]bool
	// signer computes every entry's kit.Source.EntryKey, one source per
	// file so its Sanitize memo and s1 ordinals span the file's entries.
	signer *kit.Source
}

func newSrc(c *collector, scope model.Scope, path string, raw []byte) *src {
	sum := sha256.Sum256(raw)
	return &src{c: c, scope: scope, path: path, sha: hex.EncodeToString(sum[:])}
}

func (s *src) warn(format string, args ...any) { s.c.warn(s.scope, s.path, format, args...) }

func (s *src) warnAll(warnings []string) {
	for _, w := range warnings {
		s.warn("%s", w)
	}
}

// add emits one item. payload["key"] is the content-derived evidence key
// from kit.Source.EntryKey: the sanitized key, a digest of the payload as
// kit sanitizes it (so a value this adapter keeps raw never feeds the
// fingerprint), and a discriminator over removed, every raw value this
// adapter's own sanitization removed while building the entry, tagged
// with its payload field, plus what kit's removed. Two entries whose caller-supplied key parts match, but whose
// other fields differ, even only in redacted text, never share a key
// (and therefore never share a fingerprint): see kit.Source.Add, which
// this mirrors.
func (s *src) add(kind model.ConfigKind, key []string, payload map[string]any, removed []kit.Removal) {
	s.addDetect(kind, key, payload, removed, nil)
}

// addDetect is add with the entry as the file wrote it, for rules to
// evaluate: see kit.Source.AddDetect, whose raw and keep it takes.
func (s *src) addDetect(kind model.ConfigKind, key []string, payload map[string]any, removed []kit.Removal, raw map[string]any, keep ...string) {
	if s.signer == nil {
		c := kit.NewCollector(s.c.harness, "Claude Code")
		c.SetHome(s.c.home)
		c.SetFingerprintKey(s.c.key)
		s.signer = c.SourceSHA(s.scope, s.path, s.sha).TrustSanitized(func(v string) bool { return s.outputs[v] })
	}
	payload["key"] = evidenceKey(s.signer.EntryKey(kind, s.safeKey(key), payload, removed))
	encoded, err := json.Marshal(payload)
	if err != nil {
		s.warn("cannot encode %s entry: %v", kind, err)
		return
	}
	item := model.ConfigItem{Harness: s.c.harness, Scope: s.scope, Path: s.path, SHA256: s.sha, Kind: kind, Payload: encoded}
	if raw != nil {
		item.Detect = kit.DetectView(payload, raw, append(keep, "key"))
	}
	if err := item.Validate(); err != nil {
		s.warn("cannot represent entry: %v", err)
		return
	}
	s.c.items = append(s.c.items, item)
}

func (s *src) safeKey(parts []string) []string {
	out := make([]string, len(parts))
	for i, part := range parts {
		out[i] = s.safeString(part)
	}
	return out
}

// secretFlagNamePattern matches a CLI flag whose value is a credential,
// shared between commandSecretFlag (the flag and its value in one string,
// "--token X" or "--token=X") and secretFlagName (the bare flag name,
// used when a flag and its value are two separate argv elements, as in an
// MCP server's "args" array). It is built from output.SecretFlags, the
// same list the second-line DefaultRedactor uses, so this first-line
// adapter redaction and that second line recognize exactly the same
// flags instead of the two lists drifting apart.
var secretFlagNamePattern = output.SecretFlagAlternation()

var (
	secretFlagName = regexp.MustCompile(`(?i)^(?:` + secretFlagNamePattern + `)$`)
	// userFlagName matches a bare curl user/password flag name
	// (output.UserFlagAlternation), used the same way secretFlagName is:
	// to recognize the flag in its own MCP "args" array element, so the
	// next element can be checked and, if it has "user:pass" shape,
	// redacted (see safePayloadValue).
	userFlagName = regexp.MustCompile(`(?i)^(?:` + output.UserFlagAlternation + `)$`)
	// bearerToken matches "Bearer <token>" in a single string, such as
	// an "Authorization: Bearer x" header value. The token stops at a
	// quote as well as whitespace, so it does not swallow a trailing
	// shell quote (as \S+ would) when the whole string is itself quoted,
	// for example a command embedding "'Authorization: Bearer x'".
	bearerToken = regexp.MustCompile(`(?i)\b(bearer)\s+([^\s'"]+)`)
	// bearerWord matches an array element that is the word "Bearer" or
	// ends in ": Bearer", used the same way secretFlagName is: to
	// recognize an MCP "args" element such as ["Bearer", "X"],
	// ["--header", "Authorization: Bearer", "X"], or
	// ["--header=Authorization: Bearer", "X"] (the token in a separate
	// element, rather than one "Bearer X" string bearerToken above
	// matches) so the next element is redacted unconditionally.
	bearerWord = regexp.MustCompile(`(?i)(?:^|:)\s*bearer\s*$`)
	// embeddedURL finds an absolute URL anywhere inside a larger string,
	// such as the command of "curl 'https://host/x?sig=y' | sh". It stops
	// at whitespace and quotes so the match does not swallow a trailing
	// shell quote or the rest of a pipeline. It runs on through ")" and
	// a backtick, so a query that contains one is still stripped whole;
	// kit.StripEmbeddedURL keeps the shell text that closes there.
	embeddedURL = regexp.MustCompile(`["']?[A-Za-z][A-Za-z0-9+.-]*://[^\s'"<>]+`)
)

// redactCommandSecrets redacts "Bearer <token>" and then everything
// output.RedactCommand covers (secret flags, curl user flags,
// tool-specific flags, URL userinfo, credential assignments) inside
// value, using the same table as the output-side DefaultRedactor. It
// returns the redacted text and the raw secret substrings it removed,
// for the k1 discriminator.
func redactCommandSecrets(value string) (string, []string) {
	var removed []string
	value = bearerToken.ReplaceAllStringFunc(value, func(m string) string {
		g := bearerToken.FindStringSubmatch(m)
		removed = append(removed, g[2])
		return g[1] + " " + redacted
	})
	value, commandRemoved := output.RedactCommand(value)
	return value, append(removed, commandRemoved...)
}

// stripEmbeddedURLSecrets applies stripURLSecrets to every URL found
// anywhere inside value, not only when the whole value is one URL (so a
// command such as "curl '<url>?sig=...' | sh" is covered, not just a bare
// "url" hook field). It returns the rewritten text and the raw removed
// substrings, for the k1 discriminator.
func stripEmbeddedURLSecrets(value string) (string, []string) {
	var removed []string
	value = embeddedURL.ReplaceAllStringFunc(value, func(m string) string {
		stripped, raw := kit.StripEmbeddedURL(m)
		if raw != "" {
			removed = append(removed, raw)
		}
		return stripped
	})
	return value, removed
}

// sanitizeResult is the outcome of sanitizing one string: the safe text to
// store or display, and the raw secret substrings that were removed to
// produce it (never stored; only HMAC'd by the k1 discriminator).
type sanitizeResult struct {
	value   string
	removed []string
}

// sanitizeString strips URL secrets and CLI/header credentials from value,
// then rewrites a home-directory prefix to "~" (user scope only; see
// tildeHome), and finally redacts any credential shape
// output.DefaultRedactor recognizes (a ghp_ token in an apiKeyHelper
// command, for example), recording the whole value as removed, as
// kit.Source.Sanitize does. Unlike the old implementation, it never
// blanket-converts backslashes to slashes: only the home-directory
// prefix it actually matches is rewritten, so two commands that differ
// only by `\` vs `/` outside that prefix stay distinct.
func (s *src) sanitizeString(value string) sanitizeResult {
	if r, ok := s.sanitized[value]; ok {
		return sanitizeResult{value: r.value, removed: slices.Clone(r.removed)}
	}
	r := s.sanitizeUncached(value)
	if s.sanitized == nil {
		s.sanitized, s.outputs = map[string]sanitizeResult{}, map[string]bool{}
	}
	s.sanitized[value] = sanitizeResult{value: r.value, removed: slices.Clone(r.removed)}
	s.outputs[r.value] = true
	return r
}

func (s *src) sanitizeUncached(value string) sanitizeResult {
	value, removed := stripEmbeddedURLSecrets(value)
	value, removedFlags := redactCommandSecrets(value)
	removed = append(removed, removedFlags...)
	value = s.tildeHome(value)
	if out := output.DefaultRedactor(value); out != value {
		removed = append(removed, value)
		value = out
	}
	return sanitizeResult{value: value, removed: removed}
}

// tildeHome rewrites every path-segment-bounded occurrence of the home
// directory in value as "~", using the same pathx.TildeHome rule the scan
// CLI's git error messages use. It never touches repo- or managed-scope
// content: Claude Code's own config can legitimately contain a path that
// happens to match the scanning machine's home directory, and rewriting
// it would make a repo-scope fingerprint depend on who ran the scan.
func (s *src) tildeHome(value string) string {
	if s.scope != model.ScopeUser {
		return value
	}
	return pathx.TildeHome(s.c.home, value)
}

func (s *src) safeString(value string) string {
	return s.sanitizeString(value).value
}

// evidenceKey encodes parts as a compact JSON array, so no choice of
// separator inside a matcher or command can make two keys collide.
func evidenceKey(parts []string) string {
	raw, _ := json.Marshal(parts)
	return string(raw)
}

func (s *src) settings(raw []byte) {
	tree, warnings, err := decodeJSON(raw)
	s.warnAll(warnings)
	if err != nil {
		s.warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		s.warn("settings must be a JSON object")
		return
	}
	s.settingsObject(obj)
}

func (s *src) settingsObject(obj map[string]any) {
	if hooks, ok := obj["hooks"]; ok {
		s.hooks(hooks)
	}
	if servers, ok := obj["mcpServers"]; ok {
		s.mcpServers(servers, "")
	}
	for _, name := range sortedKeys(obj) {
		kind, ok := settingKinds[name]
		if !ok {
			continue
		}
		value := obj[name]
		payload := map[string]any{"setting": name}
		var removed []string
		var raw map[string]any
		switch name {
		case "env":
			envObj, ok := value.(map[string]any)
			if !ok {
				s.warn("env must be an object")
				continue
			}
			payload["env_keys"] = sortedKeys(envObj)
			value, removed = redactValues(envObj)
		default:
			// Every other curated setting's value can itself be, or
			// contain, a credential (apiKeyHelper's command, a
			// --token flag in awsAuthRefresh, a marketplace URL with
			// userinfo in extraKnownMarketplaces, ...). Sanitize it
			// the same way a hook's fields are sanitized.
			raw = map[string]any{"value": value}
			if command := commandOf(value); command != "" {
				raw["command"] = command
			}
			value, removed = s.safePayloadValue(name, value)
		}
		switch name {
		case "permissions":
			raw["skip_dangerous_mode_prompt"] = obj["skipDangerousModePermissionPrompt"] == true
		case "skipDangerousModePermissionPrompt":
			raw["bypass_permissions"] = bypassPermissions(obj["permissions"])
		}
		payload["value"] = value
		if command := commandOf(value); command != "" {
			payload["command"] = s.safeString(command)
		}
		s.addDetect(kind, []string{"setting", name}, payload, kit.Removed("value", removed...), raw)
	}
}

// bypassPermissions reports whether a permissions value sets
// defaultMode "bypassPermissions". The permissions item's Detect view
// carries skip_dangerous_mode_prompt and the
// skipDangerousModePermissionPrompt item's carries bypass_permissions, so
// a rule can report the pair once; neither feeds the evidence key.
func bypassPermissions(value any) bool {
	perms, ok := value.(map[string]any)
	return ok && perms["defaultMode"] == "bypassPermissions"
}

// commandOf returns the shell command a setting runs: the string itself
// (apiKeyHelper and friends) or the "command" field of an object
// (statusLine).
func commandOf(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]any:
		if command, ok := v["command"].(string); ok {
			return command
		}
	}
	return ""
}

// hooks normalizes {"<Event>": [{"matcher": "...", "hooks": [{...}]}]}.
// Every hook field is kept (type, command, url, headers, prompt, agent,
// mcp_tool, timeout, and any added later); header values are redacted.
func (s *src) hooks(value any) {
	events, ok := value.(map[string]any)
	if !ok {
		s.warn("hooks must be an object keyed by event")
		return
	}
	for _, event := range sortedKeys(events) {
		groups, ok := events[event].([]any)
		if !ok {
			s.warn("hooks.%s must be an array", event)
			continue
		}
		for _, g := range groups {
			group, ok := g.(map[string]any)
			if !ok {
				s.warn("hooks.%s entry must be an object", event)
				continue
			}
			matcher := ""
			if m, present := group["matcher"]; present {
				matcher, ok = m.(string)
				if !ok {
					s.warn("hooks.%s matcher must be a string", event)
				}
			}
			list, ok := group["hooks"].([]any)
			if !ok {
				s.warn("hooks.%s entry has no hooks array", event)
				continue
			}
			for _, h := range list {
				hook, ok := h.(map[string]any)
				if !ok {
					s.warn("hooks.%s hook must be an object", event)
					continue
				}
				s.hook(event, matcher, hook)
			}
		}
	}
}

func (s *src) hook(event, matcher string, hook map[string]any) {
	payload := map[string]any{}
	var removed []kit.Removal
	// Sorted so removed is the same on every run. Every field's removed
	// text counts, not only the action's: two hooks may differ only in a
	// redacted secondary field.
	for _, k := range sortedKeys(hook) {
		sanitized, itemRemoved := s.safePayloadValue(k, hook[k])
		payload[k] = sanitized
		removed = append(removed, kit.Removed(k, itemRemoved...)...)
	}
	if headers, ok := hook["headers"].(map[string]any); ok {
		var headerRemoved []string
		payload["headers"], headerRemoved = redactValues(headers)
		payload["header_keys"] = sortedKeys(headers)
		removed = append(removed, kit.Removed("headers", headerRemoved...)...)
	}
	payload["event"] = event
	payload["matcher"] = matcher
	hookType, _ := hook["type"].(string)
	field, action := hookAction(payload)
	// safeKey sanitizes the key: given the raw command it reuses the
	// payload's memoized result instead of redacting it a second time.
	if raw, ok := hook[field].(string); ok && raw != "" {
		action = raw
	}
	s.addDetect(model.ConfigKindHook, []string{"hook", event, matcher, hookType, action}, payload, removed, hook, "headers", "header_keys", "event", "matcher")
}

// safePayloadValue sanitizes value and returns the raw secret substrings
// it removed, for the k1 discriminator. For an array (an MCP server's
// "args", for example), three two-element shapes are recognized, since
// neither element alone carries both the flag and its value for
// commandSecretFlag or bearerToken to match on a single string:
//   - ["--token", "X"]: a bare secret flag name (secretFlagName)
//     unconditionally redacts the next element.
//   - ["-u", "user:pass"] or ["--user", "user:pass"]: a bare user flag
//     name (userFlagName) redacts the next element only when it has
//     "user:pass" shape (output.LooksLikeUserPass), so ["-u", "root"]
//     (no colon, as in "sudo -u root") is left alone.
//   - ["Bearer", "X"]: the literal word "Bearer" on its own
//     unconditionally redacts the next element, the array equivalent of
//     bearerToken matching "Bearer X" within one string.
func (s *src) safePayloadValue(key string, value any) (any, []string) {
	switch v := value.(type) {
	case string:
		result := s.sanitizeString(v)
		return result.value, result.removed
	case []any:
		out := make([]any, len(v))
		var removed []string
		redactNext := false
		gateUserPass := false
		for i, item := range v {
			if redactNext {
				name, isString := item.(string)
				if gateUserPass && (!isString || !output.LooksLikeUserPass(name)) {
					sanitized, itemRemoved := s.safePayloadValue(key, item)
					out[i] = sanitized
					removed = append(removed, itemRemoved...)
				} else {
					out[i] = redacted
					if isString {
						removed = append(removed, name)
					}
				}
				redactNext = false
				gateUserPass = false
				continue
			}
			sanitized, itemRemoved := s.safePayloadValue(key, item)
			out[i] = sanitized
			removed = append(removed, itemRemoved...)
			if name, ok := item.(string); ok {
				switch {
				case secretFlagName.MatchString(name), bearerWord.MatchString(name):
					redactNext = true
				case userFlagName.MatchString(name):
					redactNext = true
					gateUserPass = true
				}
			}
		}
		return out, removed
	case map[string]any:
		out := make(map[string]any, len(v))
		var removed []string
		// Sorted so removed, and therefore the discriminator, is the same
		// on every run despite Go's randomized map iteration order.
		for _, name := range sortedKeys(v) {
			sanitized, itemRemoved := s.safePayloadValue(name, v[name])
			out[name] = sanitized
			removed = append(removed, itemRemoved...)
		}
		return out, removed
	default:
		return value, nil
	}
}

// hookAction is the part of a hook that says what it does, and the field
// it came from ("" for the fallback). It falls back to the canonical JSON
// of the whole (already-sanitized) hook for unknown shapes.
func hookAction(hook map[string]any) (field, text string) {
	for _, name := range []string{"command", "url", "prompt", "agent", "mcp_tool", "tool"} {
		switch v := hook[name].(type) {
		case string:
			if v != "" {
				return name, v
			}
		case nil:
		default:
			raw, _ := json.Marshal(v)
			return name, string(raw)
		}
	}
	copied := map[string]any{}
	for k, v := range hook {
		if k != "event" && k != "matcher" && k != "timeout" {
			copied[k] = v
		}
	}
	raw, _ := json.Marshal(copied)
	return "", string(raw)
}

// mcpFile normalizes .mcp.json and managed-mcp.json: {"mcpServers": {...}}.
func (s *src) mcpFile(raw []byte) {
	tree, warnings, err := decodeJSON(raw)
	s.warnAll(warnings)
	if err != nil {
		s.warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		s.warn("MCP config must be a JSON object")
		return
	}
	servers, ok := obj["mcpServers"]
	if !ok {
		return
	}
	s.mcpServers(servers, "")
}

// mcpServers emits one item per server. project names the ~/.claude.json
// project entry the servers belong to, or is empty.
func (s *src) mcpServers(value any, project string) {
	servers, ok := value.(map[string]any)
	if !ok {
		s.warn("mcpServers must be an object")
		return
	}
	for _, name := range sortedKeys(servers) {
		server, ok := servers[name].(map[string]any)
		if !ok {
			s.warn("MCP server %q must be an object", name)
			continue
		}
		payload := map[string]any{}
		var removed []kit.Removal
		for _, k := range sortedKeys(server) {
			sanitized, itemRemoved := s.safePayloadValue(k, server[k])
			payload[k] = sanitized
			removed = append(removed, kit.Removed(k, itemRemoved...)...)
		}
		removed = append(removed, kit.Removed("args", redactToolArgs(payload)...)...)
		if env, ok := server["env"].(map[string]any); ok {
			var envRemoved []string
			payload["env"], envRemoved = redactValues(env)
			payload["env_keys"] = sortedKeys(env)
			removed = append(removed, kit.Removed("env", envRemoved...)...)
		}
		if headers, ok := server["headers"].(map[string]any); ok {
			var headerRemoved []string
			payload["headers"], headerRemoved = redactValues(headers)
			payload["header_keys"] = sortedKeys(headers)
			removed = append(removed, kit.Removed("headers", headerRemoved...)...)
		}
		payload["name"] = name
		key := []string{"mcp", name}
		if project != "" {
			payload["project"] = project
			key = []string{"mcp", project, name}
		}
		s.addDetect(model.ConfigKindMCPServer, key, payload, removed, server, "env", "env_keys", "headers", "header_keys", "name", "project")
	}
}

// redactToolArgs applies output.RedactToolArgv to an MCP server's command
// and args, where a tool-specific flag and its value are separate array
// elements (["deploy", "-t", "X"] for command "vercel"). It rewrites
// payload["args"] in place and returns the raw values it removed.
func redactToolArgs(payload map[string]any) []string {
	command, ok := payload["command"].(string)
	if !ok {
		return nil
	}
	args, _ := payload["args"].([]any)
	argv := make([]string, 0, len(args)+1)
	argv = append(argv, command)
	for _, arg := range args {
		text, _ := arg.(string)
		argv = append(argv, text)
	}
	redactedArgv, removed := output.RedactToolArgv(argv)
	if len(removed) == 0 {
		return nil
	}
	out := make([]any, len(args))
	for i, arg := range args {
		if _, isString := arg.(string); isString {
			out[i] = redactedArgv[i+1]
		} else {
			out[i] = arg
		}
	}
	payload["args"] = out
	return removed
}

// markdown normalizes an instruction, rule, agent, command, or skill file.
// The raw content is kept for Unicode checks; frontmatter hooks and
// mcpServers become their own items.
func (s *src) markdown(kind model.ConfigKind, role string, raw []byte) {
	payload := map[string]any{"role": role, "content": s.tildeHome(string(raw))}
	front, found, err := splitFrontmatter(raw)
	if err != nil {
		s.warn("%v", err)
	}
	var meta map[string]any
	if found && err == nil {
		tree, warnings, err := decodeYAML(front)
		s.warnAll(warnings)
		switch {
		case err != nil:
			s.warn("invalid frontmatter: %v", err)
		default:
			var ok bool
			meta, ok = tree.(map[string]any)
			if !ok && tree != nil {
				s.warn("frontmatter must be a YAML mapping")
			}
		}
	}
	if meta != nil {
		frontmatter := map[string]any{}
		for k, v := range meta {
			if k != "hooks" && k != "mcpServers" {
				frontmatter[k] = v
			}
		}
		payload["frontmatter"] = frontmatter
	}
	s.add(kind, []string{role}, payload, nil)
	if meta == nil {
		return
	}
	if hooks, ok := meta["hooks"]; ok {
		s.hooks(hooks)
	}
	if servers, ok := meta["mcpServers"]; ok {
		s.mcpServers(servers, "")
	}
}

// secretKeyFragments are case-insensitive substrings of an env or header
// name whose value is always redacted. "key" matches API_KEY and also the
// standalone key KEY; it does not match BASE_URL.
var secretKeyFragments = []string{"token", "key", "secret", "password", "authorization", "cookie"}

// secretKey also accepts an env-style credential name such as DB_PASS
// or DB_PWD (output.CredentialName), the rule command-string
// assignments use.
func secretKey(name string) bool {
	if output.CredentialName(name) {
		return true
	}
	n := strings.ToLower(name)
	for _, fragment := range secretKeyFragments {
		if strings.Contains(n, fragment) {
			return true
		}
	}
	return false
}

// redactValues keeps values rules need to see: URLs (userinfo and query
// removed), hosts, booleans, numbers, and other non-secrets. A value is
// replaced with [REDACTED] when its name looks like a secret or the value
// matches output.DefaultRedactor. Sinks redact again. It also returns
// the raw text it removed, in key order, for the k1 discriminator.
func redactValues(m map[string]any) (map[string]any, []string) {
	out := make(map[string]any, len(m))
	var removed []string
	for _, k := range sortedKeys(m) {
		out[k] = redactValue(k, m[k], &removed)
	}
	return out, removed
}

func redactValue(key string, value any, removed *[]string) any {
	if key != "" && secretKey(key) {
		*removed = append(*removed, removedText(value))
		return redacted
	}
	switch v := value.(type) {
	case map[string]any:
		out, inner := redactValues(v)
		*removed = append(*removed, inner...)
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValue("", item, removed)
		}
		return out
	case string:
		return redactString(v, removed)
	case bool, json.Number, float64, nil:
		return v
	default:
		return redactString(fmt.Sprint(v), removed)
	}
}

func redactString(value string, removed *[]string) string {
	if stripped, raw, ok := stripURLSecrets(value); ok {
		if raw != "" {
			*removed = append(*removed, raw)
		}
		value = stripped
	}
	if output.DefaultRedactor(value) != value {
		*removed = append(*removed, value)
		return redacted
	}
	return value
}

// removedText is the text a whole redacted value contributes to the k1
// discriminator.
func removedText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

// stripURLSecrets reports whether raw parses as an absolute URL (any
// scheme with a host, not only http/https/socks: a database or queue URL
// such as "postgres://admin:pw@host/db" carries a credential in its
// userinfo too) and, if so, returns it without userinfo, query, or
// fragment. The host and path stay so a rule can see where a proxy or
// base URL points. removedRaw is the exact userinfo, query, and fragment
// text that was removed (NUL-joined), used only by the k1 discriminator; it
// is never stored or displayed.
func stripURLSecrets(raw string) (stripped, removedRaw string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	var removed []string
	if u.User != nil {
		removed = append(removed, u.User.String())
		u.User = nil
	}
	if u.RawQuery != "" || u.ForceQuery {
		removed = append(removed, u.RawQuery)
		u.RawQuery = ""
		u.ForceQuery = false
	}
	if u.Fragment != "" {
		removed = append(removed, u.Fragment)
		u.Fragment = ""
	}
	return u.String(), strings.Join(removed, "\x00"), true
}

// NormalizeSkill parses a SKILL.md file into items attributed to harness
// and scope, which are not Claude Code configuration: the generic adapter
// uses it for repo-scope .agents/skills and .github/skills, and for the
// user-scope ~/.agents/skills every harness that follows the agent
// skills standard shares. home is the scanning machine's home directory,
// used to rewrite it as "~" in content when scope is ScopeUser (see
// src.tildeHome); callers outside user scope may pass "". key selects
// the k1 discriminator, nil the s1 one.
func NormalizeSkill(harness model.Harness, scope model.Scope, path, home string, key *fpkey.Key, raw []byte) ([]model.ConfigItem, []adapters.Diagnostic) {
	c := &collector{harness: harness, home: home, key: key}
	newSrc(c, scope, path, raw).markdown(model.ConfigKindSkill, "skill", raw)
	return c.items, c.diags
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// tildePath rewrites an absolute path under home as "~/...". home is
// cleaned with the "path" package (always "/"-separated, regardless of
// the OS tripcord itself runs on, since home and p are both normalized
// to "/" just above) after the backslash-to-slash conversion, so a home
// such as "/x/victor/." is treated the same as "/x/victor" instead of
// being left with a trailing "/." that would then never match a "p"
// that does not also happen to carry that exact literal suffix.
func tildePath(home, p string) string {
	home = strings.ReplaceAll(home, `\`, "/")
	home = strings.TrimSuffix(path.Clean(home), "/")
	p = strings.ReplaceAll(p, `\`, "/")
	if home != "" && home != "." && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}
