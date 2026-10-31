package claude

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
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
	"permissions":                model.ConfigKindPermissions,
	"sandbox":                    model.ConfigKindPermissions,
	"disableAllHooks":            model.ConfigKindPermissions,
	"allowManagedHooksOnly":      model.ConfigKindPermissions,
	"allowManagedMcpServersOnly": model.ConfigKindPermissions,
	"allowedMcpServers":          model.ConfigKindPermissions,
	"deniedMcpServers":           model.ConfigKindPermissions,
	"enableAllProjectMcpServers": model.ConfigKindPermissions,
	"enabledMcpjsonServers":      model.ConfigKindPermissions,
	"disabledMcpjsonServers":     model.ConfigKindPermissions,
	"strictKnownMarketplaces":    model.ConfigKindPermissions,
	"enabledPlugins":             model.ConfigKindPlugin,
	"extraKnownMarketplaces":     model.ConfigKindPlugin,
	"env":                        model.ConfigKindEnvSetup,
	"apiKeyHelper":               model.ConfigKindEnvSetup,
	"statusLine":                 model.ConfigKindEnvSetup,
	"subagentStatusLine":         model.ConfigKindEnvSetup,
	"otelHeadersHelper":          model.ConfigKindEnvSetup,
	"awsAuthRefresh":             model.ConfigKindEnvSetup,
	"awsCredentialExport":        model.ConfigKindEnvSetup,
	"gcpAuthRefresh":             model.ConfigKindEnvSetup,
	"fileSuggestion":             model.ConfigKindEnvSetup,
}

// collector accumulates items and diagnostics for one Discover call.
type collector struct {
	harness model.Harness
	home    string
	items   []model.ConfigItem
	diags   []adapters.Diagnostic
}

func newCollector() *collector {
	return &collector{harness: model.HarnessClaude}
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

// add emits one item. payload["key"] is the content-derived evidence key;
// it never encodes a position in the file. kit.Source.EntrySignature's
// parts are always appended: a digest of the payload as kit sanitizes it
// (so a value this adapter keeps raw never feeds the fingerprint), and a
// discriminator over removed, every raw value this adapter's own
// sanitization removed while building the entry, plus what kit's
// removed. Two entries whose caller-supplied key parts match, but whose
// other fields differ, even only in redacted text, never share a key
// (and therefore never share a fingerprint): see kit.Source.Add, which
// this mirrors.
func (s *src) add(kind model.ConfigKind, key []string, payload map[string]any, removed []string) {
	c := kit.NewCollector(s.c.harness, "Claude Code")
	c.SetHome(s.c.home)
	sig := c.SourceSHA(s.scope, s.path, s.sha).EntrySignature(payload, removed)
	payload["key"] = evidenceKey(append(s.safeKey(key), sig...))
	raw, err := json.Marshal(payload)
	if err != nil {
		s.warn("cannot encode %s entry: %v", kind, err)
		return
	}
	item := model.ConfigItem{Harness: s.c.harness, Scope: s.scope, Path: s.path, SHA256: s.sha, Kind: kind, Payload: raw}
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
	// commandSecretFlag matches a secretFlagNamePattern flag and its
	// value within a larger command string. The leading (^|\s), kept in
	// group 1 and restored by redactCommandSecrets, is a left word
	// boundary: without it, SecretFlagAlternation's optional single
	// dash would also match a hyphen buried inside an unrelated
	// compound word, such as the "-password" inside "find-generic-
	// password -w" (not a flag at all, but a literal binary name),
	// wrongly treating the "-w" that happens to follow it as the
	// flag's value. An unquoted SPACE-separated value never starts with
	// "-", so "--token --verbose" does not eat the next flag; an "="
	// value has no such restriction, since a token can itself start
	// with "-" (base64url, for example), and "--token=" unambiguously
	// ends the flag name regardless of what follows.
	commandSecretFlag = regexp.MustCompile(`(?i)(^|\s)(` + secretFlagNamePattern + `)(?:=('[^']*'|"[^"]*"|\S*)|\s+('[^']*'|"[^"]*"|[^-\s]\S*))`)
	secretFlagName    = regexp.MustCompile(`(?i)^(?:` + secretFlagNamePattern + `)$`)
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
	// bearerWord matches "Bearer" as a whole array element on its own,
	// used the same way secretFlagName is: to recognize an MCP "args"
	// element such as ["Bearer", "X"] (two separate array elements,
	// rather than one "Bearer X" string bearerToken above matches) so
	// the next element is redacted unconditionally.
	bearerWord = regexp.MustCompile(`(?i)^bearer$`)
	// embeddedURL finds an absolute URL anywhere inside a larger string,
	// such as the command of "curl 'https://host/x?sig=y' | sh". It stops
	// at whitespace and quotes so the match does not swallow a trailing
	// shell quote or the rest of a pipeline.
	embeddedURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'"<>]+`)
)

// redactCommandSecrets redacts CLI secret flags ("--token X", "--token=X"),
// "Bearer <token>", curl-style "-u user:pass" (output.RedactUserFlags),
// tool-specific short flags such as "openssl -k X" or "vercel -t X"
// (output.RedactToolFlags), and credential-named assignments such as
// PGPASSWORD=X or npm's :_authToken=X (output.RedactAssignments) inside
// value. It returns the redacted text and the raw secret substrings it
// removed, for kit.KeyDiscriminator.
func redactCommandSecrets(value string) (string, []string) {
	var removed []string
	value = commandSecretFlag.ReplaceAllStringFunc(value, func(m string) string {
		g := commandSecretFlag.FindStringSubmatch(m)
		// g[3] is the "=" form's value, g[4] the space form's. Which
		// branch matched is read from the separator that actually
		// follows the flag name in m, not from whether g[3] is empty:
		// an "=" with an empty value ("--token=") is itself a valid,
		// if degenerate, match of the "=" branch. "--password=X" keeps
		// its "=" on redaction; the space form keeps its single space.
		if m[len(g[1])+len(g[2])] == '=' {
			removed = append(removed, g[3])
			return g[1] + g[2] + "=" + redacted
		}
		removed = append(removed, g[4])
		return g[1] + g[2] + " " + redacted
	})
	value = bearerToken.ReplaceAllStringFunc(value, func(m string) string {
		g := bearerToken.FindStringSubmatch(m)
		removed = append(removed, g[2])
		return g[1] + " " + redacted
	})
	value, userRemoved := output.RedactUserFlags(value)
	value, toolRemoved := output.RedactToolFlags(value)
	value, assignRemoved := output.RedactAssignments(value)
	removed = append(removed, userRemoved...)
	removed = append(removed, toolRemoved...)
	return value, append(removed, assignRemoved...)
}

// stripEmbeddedURLSecrets applies stripURLSecrets to every URL found
// anywhere inside value, not only when the whole value is one URL (so a
// command such as "curl '<url>?sig=...' | sh" is covered, not just a bare
// "url" hook field). It returns the rewritten text and the raw removed
// substrings, for kit.KeyDiscriminator.
func stripEmbeddedURLSecrets(value string) (string, []string) {
	var removed []string
	value = embeddedURL.ReplaceAllStringFunc(value, func(m string) string {
		stripped, raw, ok := stripURLSecrets(m)
		if !ok {
			return m
		}
		if raw != "" {
			removed = append(removed, raw)
		}
		return stripped
	})
	return value, removed
}

// sanitizeResult is the outcome of sanitizing one string: the safe text to
// store or display, and the raw secret substrings that were removed to
// produce it (never stored; only hashed by kit.KeyDiscriminator).
type sanitizeResult struct {
	value   string
	removed []string
}

// sanitizeString strips URL secrets and CLI/header credentials from value,
// then rewrites a home-directory prefix to "~" (user scope only; see
// tildeHome). Unlike the old implementation, it never blanket-converts
// backslashes to slashes: only the home-directory prefix it actually
// matches is rewritten, so two commands that differ only by `\` vs `/`
// outside that prefix stay distinct.
func (s *src) sanitizeString(value string) sanitizeResult {
	value, removedURLs := stripEmbeddedURLSecrets(value)
	value, removedFlags := redactCommandSecrets(value)
	value = s.tildeHome(value)
	return sanitizeResult{value: value, removed: append(removedURLs, removedFlags...)}
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
			value, removed = s.safePayloadValue(name, value)
		}
		payload["value"] = value
		if command := commandOf(value); command != "" {
			payload["command"] = s.safeString(command)
		}
		s.add(kind, []string{"setting", name}, payload, removed)
	}
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
	var removed []string
	// Sorted so removed is the same on every run. Every field's removed
	// text counts, not only the action's: two hooks may differ only in a
	// redacted secondary field.
	for _, k := range sortedKeys(hook) {
		sanitized, itemRemoved := s.safePayloadValue(k, hook[k])
		payload[k] = sanitized
		removed = append(removed, itemRemoved...)
	}
	if headers, ok := hook["headers"].(map[string]any); ok {
		var headerRemoved []string
		payload["headers"], headerRemoved = redactValues(headers)
		payload["header_keys"] = sortedKeys(headers)
		removed = append(removed, headerRemoved...)
	}
	payload["event"] = event
	payload["matcher"] = matcher
	hookType, _ := hook["type"].(string)
	_, action := hookAction(payload)
	s.add(model.ConfigKindHook, []string{"hook", event, matcher, hookType, action}, payload, removed)
}

// safePayloadValue sanitizes value and returns the raw secret substrings
// it removed, for kit.KeyDiscriminator. For an array (an MCP server's
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
		// Sorted so removed, and therefore kit.KeyDiscriminator, is the same
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
		var removed []string
		for _, k := range sortedKeys(server) {
			sanitized, itemRemoved := s.safePayloadValue(k, server[k])
			payload[k] = sanitized
			removed = append(removed, itemRemoved...)
		}
		removed = append(removed, redactToolArgs(payload)...)
		if env, ok := server["env"].(map[string]any); ok {
			var envRemoved []string
			payload["env"], envRemoved = redactValues(env)
			payload["env_keys"] = sortedKeys(env)
			removed = append(removed, envRemoved...)
		}
		if headers, ok := server["headers"].(map[string]any); ok {
			var headerRemoved []string
			payload["headers"], headerRemoved = redactValues(headers)
			payload["header_keys"] = sortedKeys(headers)
			removed = append(removed, headerRemoved...)
		}
		payload["name"] = name
		key := []string{"mcp", name}
		if project != "" {
			payload["project"] = project
			key = []string{"mcp", project, name}
		}
		s.add(model.ConfigKindMCPServer, key, payload, removed)
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

func secretKey(name string) bool {
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
// the raw text it removed, in key order, for kit.KeyDiscriminator.
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

// removedText is the text a whole redacted value contributes to
// kit.KeyDiscriminator.
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
// text that was removed (NUL-joined), used only by kit.KeyDiscriminator; it
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
// src.tildeHome); callers outside user scope may pass "".
func NormalizeSkill(harness model.Harness, scope model.Scope, path, home string, raw []byte) ([]model.ConfigItem, []adapters.Diagnostic) {
	c := &collector{harness: harness, home: home}
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
