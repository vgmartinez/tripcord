package gemini

import (
	"bytes"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// file is one Gemini CLI settings or context file being normalized.
type file struct {
	*kit.Source
}

// hookActions are the handler fields that say what a hook runs. Gemini
// CLI documents one handler type, "command".
var hookActions = []string{"command"}

// settingKinds is the curated set of settings.json keys that decide what
// runs, how it is sandboxed, what is approved, or which file supplies
// the model's context. Both the nested schema (tools, security, context,
// ...) and the older flat keys (sandbox, coreTools, contextFileName, ...)
// are listed, because Gemini CLI migrates the flat form and a stale file
// can still carry it. Each present key becomes one item. mcpServers and
// hooks have their own items; other keys are not emitted.
//
// Reviewed against https://geminicli.com/docs/ on 2026-10-31.
var settingKinds = map[string]model.ConfigKind{
	"hooksConfig":            model.ConfigKindPermissions,
	"tools":                  model.ConfigKindPermissions,
	"security":               model.ConfigKindPermissions,
	"general":                model.ConfigKindPermissions,
	"mcp":                    model.ConfigKindPermissions,
	"sandbox":                model.ConfigKindPermissions,
	"coreTools":              model.ConfigKindPermissions,
	"excludeTools":           model.ConfigKindPermissions,
	"allowedTools":           model.ConfigKindPermissions,
	"autoAccept":             model.ConfigKindPermissions,
	"allowMCPServers":        model.ConfigKindPermissions,
	"excludeMCPServers":      model.ConfigKindPermissions,
	"folderTrust":            model.ConfigKindPermissions,
	"folderTrustFeature":     model.ConfigKindPermissions,
	"toolDiscoveryCommand":   model.ConfigKindEnvSetup,
	"toolCallCommand":        model.ConfigKindEnvSetup,
	"mcpServerCommand":       model.ConfigKindEnvSetup,
	"telemetry":              model.ConfigKindEnvSetup,
	"advanced":               model.ConfigKindEnvSetup,
	"excludedProjectEnvVars": model.ConfigKindEnvSetup,
	"experimental":           model.ConfigKindEnvSetup,
	"extensions":             model.ConfigKindPlugin,
	"context":                model.ConfigKindInstructions,
	"contextFileName":        model.ConfigKindInstructions,
}

// settings normalizes a settings.json. Gemini CLI strips comments before
// JSON.parse, which rejects trailing commas, so a trailing comma is
// reported as a note and the file is still normalized: skipping it would
// hide the configuration Gemini would refuse to load.
func (f *file) settings(raw []byte) {
	if hasTrailingComma(raw) {
		f.Note("trailing comma; Gemini CLI strips comments and then JSON.parse, which rejects it")
	}
	tree, warnings, err := kit.DecodeJSON(raw, kit.JSONC, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		f.Warn("settings must be a JSON object")
		return
	}
	if servers, ok := obj["mcpServers"]; ok {
		f.MCPServers(servers, "mcpServers")
	}
	if hooks, ok := obj["hooks"]; ok {
		disabled, allDisabled := hooksConfigDisabled(obj["hooksConfig"])
		if allDisabled {
			f.Note("hooksConfig.enabled is false; hooks in this file are still reported, because a higher-precedence settings file can re-enable them")
		}
		f.hooks(hooks, disabled)
	}
	for _, name := range kit.SortedKeys(obj) {
		if kind, ok := settingKinds[name]; ok {
			f.setting(kind, name, obj[name])
		}
	}
}

func (f *file) setting(kind model.ConfigKind, name string, value any) {
	f.Add(kind, []string{"setting", name}, map[string]any{"setting": name, "value": f.SafeValue(name, value)})
}

// hooks normalizes the hooks object. The documented shape is
// {"Event": [{"matcher", "sequential", "hooks": [{"type": "command",
// "command", "name", "timeout", ...}]}]}. "command" is the only
// documented handler type, so any other type is a blocking diagnostic;
// the handler is still emitted. A non-array member (an older inline
// flag, say) is emitted as a setting, and an entry or handler of any
// other shape is emitted whole as an opaque hook item and reported,
// never dropped.
func (f *file) hooks(value any, disabled map[string]bool) {
	table, ok := value.(map[string]any)
	if !ok {
		f.opaque("", value)
		return
	}
	for _, event := range kit.SortedKeys(table) {
		entries, isArray := table[event].([]any)
		if !isArray {
			f.setting(model.ConfigKindPermissions, "hooks."+event, table[event])
			continue
		}
		for _, e := range entries {
			group, ok := e.(map[string]any)
			if !ok {
				f.opaque(event, e)
				continue
			}
			list, grouped := group["hooks"].([]any)
			if !grouped {
				f.opaque(event, e)
				continue
			}
			matcher, ok := matcherOf(group)
			if !ok {
				f.opaque(event, e)
				continue
			}
			for _, h := range list {
				f.handler(event, matcher, group, h, disabled)
			}
		}
	}
}

func matcherOf(group map[string]any) (string, bool) {
	switch m := group["matcher"].(type) {
	case nil:
		return "", true
	case string:
		return m, true
	default:
		return "", false
	}
}

// handler emits one handler of a matcher group. The group's sequential
// flag is copied onto the handler as group_sequential, since it decides
// how the handler runs relative to its siblings.
func (f *file) handler(event, matcher string, group map[string]any, h any, disabled map[string]bool) {
	hook, ok := h.(map[string]any)
	if !ok {
		f.opaque(event, h)
		return
	}
	if t, _ := hook["type"].(string); t != "command" {
		if t == "" {
			f.Warn("hooks.%s handler has no type; Gemini CLI documents only \"command\"", event)
		} else {
			f.Warn("hooks.%s handler type %q is not documented; Gemini CLI documents only \"command\"", event, t)
		}
	}
	if id, ok := hookIdentity(hook); ok && disabled[id] {
		// Redact before Hook so a secret removed from this name stays on
		// this handler's discriminator instead of the next item's.
		f.Note("hook %s is named in hooksConfig.disabled; it is still reported, because a higher-precedence settings file can re-enable it", f.SafeString(id))
	}
	if seq, present := group["sequential"]; present {
		copied := make(map[string]any, len(hook)+1)
		for k, v := range hook {
			copied[k] = v
		}
		copied["group_sequential"] = seq
		hook = copied
	}
	f.Hook(event, matcher, hook, hookActions)
}

// hookIdentity is the name Gemini CLI compares with hooksConfig.disabled.
// getHookName returns config.name, or config.command when name is missing
// or empty. An event name is not an identity.
func hookIdentity(hook map[string]any) (string, bool) {
	if name, ok := hook["name"].(string); ok && name != "" {
		return name, true
	}
	command, ok := hook["command"].(string)
	return command, ok && command != ""
}

// hooksConfigDisabled returns the names hooksConfig.disabled lists, plus
// whether hooksConfig.enabled is false. disabled is an array of hook
// names, not event names and not a boolean: Gemini CLI matches a handler
// by its name, or by its command when it has no name. A match is still
// emitted and noted.
func hooksConfigDisabled(value any) (map[string]bool, bool) {
	disabled := map[string]bool{}
	obj, ok := value.(map[string]any)
	if !ok {
		return disabled, false
	}
	enabled, hasEnabled := obj["enabled"].(bool)
	allDisabled := hasEnabled && !enabled
	if names, ok := obj["disabled"].([]any); ok {
		for _, name := range names {
			if text, ok := name.(string); ok {
				disabled[text] = true
			}
		}
	}
	return disabled, allDisabled
}

// hasTrailingComma reports whether raw, read as JSONC, has a comma
// immediately before a } or ] outside strings and comments. Gemini CLI
// strips comments and then JSON.parse, which rejects that comma.
func hasTrailingComma(raw []byte) bool {
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	inString := false
	lastComma := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if inString {
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			lastComma = false
		case c == '/' && i+1 < len(raw) && raw[i+1] == '/':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(raw) && raw[i+1] == '*':
			end := bytes.Index(raw[i+2:], []byte("*/"))
			if end < 0 {
				return false
			}
			i += 2 + end + 1
		case c == ',':
			lastComma = true
		case c == '}' || c == ']':
			if lastComma {
				return true
			}
			lastComma = false
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			lastComma = false
		}
	}
	return false
}

// opaque emits a hooks value whose shape is not the documented one, whole
// and sanitized, so a rule still sees it and a reviewer is told.
func (f *file) opaque(event string, value any) {
	where := "hooks"
	if event != "" {
		where += "." + event
	}
	f.Warn("%s has an unrecognized shape; it is reported as an opaque hook", where)
	f.AddDetect(model.ConfigKindHook, []string{"hook", event, "opaque"}, map[string]any{"event": event, "opaque": true, "value": f.SafeValue("", value)}, map[string]any{"value": value})
}
