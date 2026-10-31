package claude

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
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
	payload["key"] = evidenceKey(key)
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
		if name == "env" {
			envObj, ok := value.(map[string]any)
			if !ok {
				s.warn("env must be an object")
				continue
			}
			payload["env_keys"] = sortedKeys(envObj)
			value = redactValues(envObj)
		}
		payload["value"] = value
		if command := commandOf(value); command != "" {
			payload["command"] = command
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
		payload[k] = v
	}
	if headers, ok := hook["headers"].(map[string]any); ok {
		payload["headers"] = redactValues(headers)
		payload["header_keys"] = sortedKeys(headers)
	}
	payload["event"] = event
	payload["matcher"] = matcher
	hookType, _ := hook["type"].(string)
	s.add(model.ConfigKindHook, []string{"hook", event, matcher, hookType, hookAction(payload)}, payload)
}

// hookAction is the part of a hook that says what it does. It falls back to
// the canonical JSON of the whole (redacted) hook for unknown shapes.
func hookAction(hook map[string]any) string {
	for _, field := range []string{"command", "url", "prompt", "agent", "mcp_tool", "tool"} {
		switch v := hook[field].(type) {
		case string:
			if v != "" {
				return v
			}
		case nil:
		default:
			raw, _ := json.Marshal(v)
			return string(raw)
		}
	}
	copied := map[string]any{}
	for k, v := range hook {
		if k != "event" && k != "matcher" && k != "timeout" {
			copied[k] = v
		}
	}
	raw, _ := json.Marshal(copied)
	return string(raw)
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
			payload[k] = v
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
	if stripped, ok := stripURLSecrets(value); ok {
		value = stripped
	}
	if output.DefaultRedactor(value) != value {
		return redacted
	}
	return value
}

// stripURLSecrets reports whether raw is an http(s) or socks URL and
// returns it without userinfo, query, or fragment. The host and path stay
// so a rule can see where a proxy or base URL points.
func stripURLSecrets(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", false
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String(), true
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
