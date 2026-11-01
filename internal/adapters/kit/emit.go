package kit

import (
	"encoding/json"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
)

// HookShape is how a harness nests hook handlers under an event.
type HookShape int

const (
	// Grouped is Claude Code's and Codex's shape:
	// {"Event": [{"matcher": "...", "hooks": [{handler}, ...]}]}.
	Grouped HookShape = iota
	// Flat is Cursor's and Copilot's shape: {"event": [{handler}, ...]},
	// where a handler may carry its own "matcher".
	Flat
	// Either accepts both per entry: an entry with a "hooks" array is a
	// matcher group, anything else is a handler. Copilot reads Claude-format
	// plugin hooks next to its own.
	Either
)

// Hooks normalizes an event map of hook handlers. actionFields lists, in
// order of preference, the handler fields that say what it does (the
// command, URL, prompt, ...); the first present one is part of the
// evidence key.
func (s *Source) Hooks(value any, shape HookShape, actionFields []string) {
	events, ok := value.(map[string]any)
	if !ok {
		s.Warn("hooks must be an object keyed by event")
		return
	}
	for _, event := range SortedKeys(events) {
		entries, ok := events[event].([]any)
		if !ok {
			s.Warn("hooks.%s must be an array", event)
			continue
		}
		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				s.Warn("hooks.%s entry must be an object", event)
				continue
			}
			list, grouped := entry["hooks"].([]any)
			switch {
			case shape == Grouped && !grouped:
				s.Warn("hooks.%s entry has no hooks array", event)
				continue
			case shape == Flat || !grouped:
				s.Hook(event, matcherOf(s, event, entry), entry, actionFields)
				continue
			}
			matcher := matcherOf(s, event, entry)
			for _, h := range list {
				hook, ok := h.(map[string]any)
				if !ok {
					s.Warn("hooks.%s hook must be an object", event)
					continue
				}
				s.Hook(event, matcher, hook, actionFields)
			}
		}
	}
}

func matcherOf(s *Source, event string, entry map[string]any) string {
	m, present := entry["matcher"]
	if !present || m == nil {
		return ""
	}
	matcher, ok := m.(string)
	if !ok {
		s.Warn("hooks.%s matcher must be a string", event)
	}
	return matcher
}

// Hook emits one hook handler. Every field is kept and sanitized; header
// and env values are redacted. The key is event, matcher, type, and the
// action; Add appends the discriminator over everything sanitizing any
// field removed.
func (s *Source) Hook(event, matcher string, hook map[string]any, actionFields []string) {
	payload := s.SafeObject(hook)
	s.redactMaps(hook, payload, "headers", "env")
	payload["event"] = event
	payload["matcher"] = matcher
	hookType, _ := hook["type"].(string)
	_, action := hookAction(payload, actionFields)
	s.AddDetect(model.ConfigKindHook, []string{"hook", event, matcher, hookType, action}, payload, hook, hookKeep...)
}

// hookKeep and mcpKeep are the fields whose sanitized payload value
// stays in the detection view (see Source.AddDetect): the redacted maps
// and the fields Hook and MCPServers set themselves.
var (
	hookKeep = []string{"headers", "env", "header_keys", "env_keys", "event", "matcher"}
	mcpKeep  = []string{"env", "headers", "http_headers", "env_http_headers", "env_keys", "header_keys", "http_headers_keys", "env_http_headers_keys", "name"}
)

// redactMaps replaces each named object field of payload with its
// RedactValues form and records its key names as "<name>_keys" (env keys
// become "env_keys", header keys "header_keys").
func (s *Source) redactMaps(raw, payload map[string]any, names ...string) {
	for _, name := range names {
		m, ok := raw[name].(map[string]any)
		if !ok {
			continue
		}
		payload[name] = s.RedactValues(m)
		keysName := name + "_keys"
		if name == "headers" {
			keysName = "header_keys"
		}
		payload[keysName] = SortedKeys(m)
	}
}

// hookAction returns the first present action field and its text, or the
// canonical JSON of the sanitized handler for an unknown shape.
func hookAction(hook map[string]any, fields []string) (field, text string) {
	for _, name := range fields {
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
		if k != "event" && k != "matcher" && k != "timeout" && k != "timeoutSec" {
			copied[k] = v
		}
	}
	raw, _ := json.Marshal(copied)
	return "", string(raw)
}

// MCPServers emits one item per server of an object keyed by server
// name. Every field is sanitized; env and header values are redacted.
// what names the object in diagnostics.
func (s *Source) MCPServers(value any, what string) {
	servers, ok := value.(map[string]any)
	if !ok {
		s.Warn("%s must be an object", what)
		return
	}
	for _, name := range SortedKeys(servers) {
		server, ok := servers[name].(map[string]any)
		if !ok {
			s.Warn("MCP server %q must be an object", name)
			continue
		}
		payload := s.SafeObject(server)
		s.redactMaps(server, payload, "env", "headers", "http_headers", "env_http_headers")
		s.redactToolArgs(payload)
		payload["name"] = name
		s.AddDetect(model.ConfigKindMCPServer, []string{"mcp", name}, payload, server, mcpKeep...)
	}
}

// redactToolArgs applies output.RedactToolArgv to the already-sanitized
// command and args in payload. A tool-specific flag and its value can be
// separate array elements (["login", "-p", "X"] for command "docker"),
// which SafeValue's generic per-element scan does not redact because a
// short flag like -p or -t means something unrelated for most commands.
// Starting with the sanitized payload is critical: rewriting args from
// the raw server value would restore a different secret SafeObject or
// SafeValue already removed from another element.
func (s *Source) redactToolArgs(payload map[string]any) {
	command, ok := payload["command"].(string)
	if !ok {
		return
	}
	args, ok := payload["args"].([]any)
	if !ok {
		return
	}
	argv := make([]string, 0, len(args)+1)
	argv = append(argv, command)
	for _, arg := range args {
		text, _ := arg.(string)
		argv = append(argv, text)
	}
	redactedArgv, removed := output.RedactToolArgv(argv)
	if len(removed) == 0 {
		return
	}
	s.recordRemoved(removed...)
	out := make([]any, len(args))
	for i, arg := range args {
		if _, isString := arg.(string); isString {
			out[i] = redactedArgv[i+1]
		} else {
			out[i] = arg
		}
	}
	payload["args"] = out
}

// Frontmatter selects how Markdown frontmatter errors are treated.
type Frontmatter int

const (
	// StrictFrontmatter reports malformed frontmatter. Use it where
	// frontmatter can register hooks or MCP servers.
	StrictFrontmatter Frontmatter = iota
	// LooseFrontmatter falls back to "key: value" lines without a
	// diagnostic. Use it where frontmatter only scopes instructions
	// (globs, applyTo) and the harness itself parses it leniently.
	LooseFrontmatter
)

// Markdown emits an instruction, rule, or agent file. The content is kept
// for Unicode and instruction checks, with URL secrets stripped (and the
// home directory rewritten in user scope). When the file has a closed
// frontmatter block, content is the body only: the frontmatter is emitted
// sanitized as its own field, and its raw text can hold MCP server env
// values that content must not carry. It returns the parsed
// frontmatter, or nil, so the caller can emit hooks or servers it
// declares. folded is passed to DecodeYAML.
func (s *Source) Markdown(kind model.ConfigKind, role string, raw []byte, mode Frontmatter, folded ...string) map[string]any {
	text := raw
	if _, body, found, err := splitFrontmatter(raw); found && err == nil {
		text = body
	}
	content, removed := stripEmbeddedURLSecrets(string(text))
	s.recordRemoved(removed...)
	payload := map[string]any{"role": role, "content": s.tildeHome(content)}
	meta := s.frontmatter(raw, mode, folded)
	if meta != nil {
		front := map[string]any{}
		for _, k := range SortedKeys(meta) {
			switch k {
			case "hooks", "mcpServers", "mcp-servers":
			default:
				front[k] = s.SafeValue(k, meta[k])
			}
		}
		payload["frontmatter"] = front
	}
	s.Add(kind, []string{role}, payload)
	return meta
}

func (s *Source) frontmatter(raw []byte, mode Frontmatter, folded []string) map[string]any {
	front, found, err := SplitFrontmatter(raw)
	if err != nil {
		if mode == StrictFrontmatter {
			s.Warn("%v", err)
		}
		return nil
	}
	if !found {
		return nil
	}
	tree, warnings, err := DecodeYAML(front, s.c.product, folded...)
	if err != nil {
		if mode == LooseFrontmatter {
			return ParseLooseFrontmatter(front)
		}
		s.Warn("invalid frontmatter: %v", err)
		return nil
	}
	if mode == StrictFrontmatter {
		s.WarnAll(warnings)
	}
	meta, ok := tree.(map[string]any)
	if !ok {
		if tree != nil && mode == StrictFrontmatter {
			s.Warn("frontmatter must be a YAML mapping")
		}
		return nil
	}
	return meta
}
