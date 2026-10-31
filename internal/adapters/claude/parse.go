package claude

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
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
// it never encodes a position in the file.
func (s *src) add(kind model.ConfigKind, key []string, payload map[string]any) {
	payload["key"] = evidenceKey(s.safeKey(key))
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
	commandSecretFlag = regexp.MustCompile(`(?i)(` + secretFlagNamePattern + `)(?:=|\s+)('[^']*'|"[^"]*"|\S+)`)
	secretFlagName    = regexp.MustCompile(`(?i)^(?:` + secretFlagNamePattern + `)$`)
	bearerToken       = regexp.MustCompile(`(?i)\b(bearer)\s+(\S+)`)
	// embeddedURL finds an absolute URL anywhere inside a larger string,
	// such as the command of "curl 'https://host/x?sig=y' | sh". It stops
	// at whitespace and quotes so the match does not swallow a trailing
	// shell quote or the rest of a pipeline.
	embeddedURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'"<>]+`)
)

// redactCommandSecrets redacts CLI secret flags ("--token X", "--token=X")
// and "Bearer <token>" occurrences inside value. It returns the redacted
// text and the raw secret substrings it removed, for keyDiscriminator.
func redactCommandSecrets(value string) (string, []string) {
	var removed []string
	value = commandSecretFlag.ReplaceAllStringFunc(value, func(m string) string {
		g := commandSecretFlag.FindStringSubmatch(m)
		removed = append(removed, g[2])
		return g[1] + " " + redacted
	})
	value = bearerToken.ReplaceAllStringFunc(value, func(m string) string {
		g := bearerToken.FindStringSubmatch(m)
		removed = append(removed, g[2])
		return g[1] + " " + redacted
	})
	return value, removed
}

// stripEmbeddedURLSecrets applies stripURLSecrets to every URL found
// anywhere inside value, not only when the whole value is one URL (so a
// command such as "curl '<url>?sig=...' | sh" is covered, not just a bare
// "url" hook field). It returns the rewritten text and the raw removed
// substrings, for keyDiscriminator.
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
// produce it (never stored; only hashed by keyDiscriminator).
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

// keyDiscriminator is the first 8 hex characters of SHA-256 over removed,
// joined by NUL. Appending it to an evidence key keeps two entries whose
// only difference is a secret value (a signed URL's query, a --token
// value, ...) from colliding on the same key, and therefore the same
// fingerprint, once that secret is redacted: without it, suppressing one
// as a false positive would silently suppress the other too. It is
// computed from the raw value that was removed, never the sanitized
// text, so it stays the same across machines with different home
// directories (home substitution is not "removed"; see tildeHome) but
// differs whenever the underlying secret differs. This does let someone
// who has already guessed a low-entropy secret (a short shared token or
// signature) confirm that guess by recomputing the hash; that is accepted
// here because signatures and tokens are the values this guards, and the
// alternative -- two different secrets sharing one key -- is worse.
func keyDiscriminator(removed []string) string {
	sum := sha256.Sum256([]byte(strings.Join(removed, "\x00")))
	return hex.EncodeToString(sum[:])[:8]
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
		switch name {
		case "env":
			envObj, ok := value.(map[string]any)
			if !ok {
				s.warn("env must be an object")
				continue
			}
			payload["env_keys"] = sortedKeys(envObj)
			value = redactValues(envObj)
		default:
			// Every other curated setting's value can itself be, or
			// contain, a credential (apiKeyHelper's command, a
			// --token flag in awsAuthRefresh, a marketplace URL with
			// userinfo in extraKnownMarketplaces, ...). Sanitize it
			// the same way a hook's fields are sanitized.
			value = s.safePayloadValue(name, value)
		}
		payload["value"] = value
		if command := commandOf(value); command != "" {
			payload["command"] = s.safeString(command)
		}
		s.add(kind, []string{"setting", name}, payload)
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
	for k, v := range hook {
		payload[k] = s.safePayloadValue(k, v)
	}
	if headers, ok := hook["headers"].(map[string]any); ok {
		payload["headers"] = redactValues(headers)
		payload["header_keys"] = sortedKeys(headers)
	}
	payload["event"] = event
	payload["matcher"] = matcher
	hookType, _ := hook["type"].(string)
	field, action := hookAction(payload)
	key := []string{"hook", event, matcher, hookType, action}
	// The discriminator must come from the RAW field value, before
	// sanitization: by the time "action" above is computed, a secret
	// value has already been replaced with the constant string
	// redacted, so re-sanitizing it here could never recover what was
	// removed. See keyDiscriminator.
	if field != "" {
		if raw, ok := hook[field].(string); ok {
			if removed := s.sanitizeString(raw).removed; len(removed) > 0 {
				key = append(key, "sig:"+keyDiscriminator(removed))
			}
		}
	}
	s.add(model.ConfigKindHook, key, payload)
}

// secretFlagName matches a bare CLI flag whose value is a credential, used
// when the flag and its value are two separate elements of an array (an
// MCP server's "args", for example ["--token", "X"]), so neither element
// alone carries both the flag and its value for commandSecretFlag to
// match.
func (s *src) safePayloadValue(key string, value any) any {
	switch v := value.(type) {
	case string:
		return s.safeString(v)
	case []any:
		out := make([]any, len(v))
		redactNext := false
		for i, item := range v {
			if redactNext {
				out[i] = redacted
				redactNext = false
				continue
			}
			out[i] = s.safePayloadValue(key, item)
			if name, ok := item.(string); ok && secretFlagName.MatchString(name) {
				redactNext = true
			}
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for name, item := range v {
			out[name] = s.safePayloadValue(name, item)
		}
		return out
	default:
		return value
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
		for k, v := range server {
			payload[k] = s.safePayloadValue(k, v)
		}
		if env, ok := server["env"].(map[string]any); ok {
			payload["env"] = redactValues(env)
			payload["env_keys"] = sortedKeys(env)
		}
		if headers, ok := server["headers"].(map[string]any); ok {
			payload["headers"] = redactValues(headers)
			payload["header_keys"] = sortedKeys(headers)
		}
		payload["name"] = name
		key := []string{"mcp", name}
		if project != "" {
			payload["project"] = project
			key = []string{"mcp", project, name}
		}
		s.add(model.ConfigKindMCPServer, key, payload)
	}
}

// markdown normalizes an instruction, rule, agent, command, or skill file.
// The raw content is kept for Unicode checks; frontmatter hooks and
// mcpServers become their own items.
func (s *src) markdown(kind model.ConfigKind, role string, raw []byte) {
	payload := map[string]any{"role": role, "content": string(raw)}
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
	s.add(kind, []string{role}, payload)
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
// matches output.DefaultRedactor. Sinks redact again.
func redactValues(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for _, k := range sortedKeys(m) {
		out[k] = redactValue(k, m[k])
	}
	return out
}

func redactValue(key string, value any) any {
	if key != "" && secretKey(key) {
		return redacted
	}
	switch v := value.(type) {
	case map[string]any:
		return redactValues(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValue("", item)
		}
		return out
	case string:
		return redactString(v)
	case bool, json.Number, float64, nil:
		return v
	default:
		return redactString(fmt.Sprint(v))
	}
}

func redactString(value string) string {
	if stripped, _, ok := stripURLSecrets(value); ok {
		value = stripped
	}
	if output.DefaultRedactor(value) != value {
		return redacted
	}
	return value
}

// stripURLSecrets reports whether raw parses as an absolute URL (any
// scheme with a host, not only http/https/socks: a database or queue URL
// such as "postgres://admin:pw@host/db" carries a credential in its
// userinfo too) and, if so, returns it without userinfo, query, or
// fragment. The host and path stay so a rule can see where a proxy or
// base URL points. removedRaw is the exact userinfo, query, and fragment
// text that was removed (NUL-joined), used only by keyDiscriminator; it
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

// NormalizeSkill parses a SKILL.md file into items attributed to harness.
// The generic adapter uses it for .agents/skills and .github/skills, which
// share this file shape but are not Claude Code configuration.
func NormalizeSkill(harness model.Harness, path string, raw []byte) ([]model.ConfigItem, []adapters.Diagnostic) {
	c := &collector{harness: harness}
	newSrc(c, model.ScopeRepo, path, raw).markdown(model.ConfigKindSkill, "skill", raw)
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

// tildePath rewrites an absolute path under home as "~/...".
func tildePath(home, p string) string {
	home = strings.TrimSuffix(strings.ReplaceAll(home, `\`, "/"), "/")
	p = strings.ReplaceAll(p, `\`, "/")
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}
