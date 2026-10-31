package gemini

import (
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
// JSON.parse, so the file is read as JSONC.
func (f *file) settings(raw []byte) {
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
		f.hooks(hooks)
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

// hooks normalizes the hooks object. The documented shape is Claude
// Code's: {"Event": [{"matcher", "sequential", "hooks": [{"type":
// "command", "command", "name", "timeout", ...}]}]}. The schema is not
// verified against Gemini CLI releases, so it is read conservatively: a
// non-array member (an older inline enabled or disabled flag, say) is
// emitted as a setting, and an entry or handler of any other shape is
// emitted whole as an opaque hook item and reported, never dropped.
func (f *file) hooks(value any) {
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
				f.handler(event, matcher, group, h)
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
func (f *file) handler(event, matcher string, group map[string]any, h any) {
	hook, ok := h.(map[string]any)
	if !ok {
		f.opaque(event, h)
		return
	}
	switch t, _ := hook["type"].(string); t {
	case "command":
	case "":
		f.Warn("hooks.%s handler has no type; Gemini CLI documents only \"command\"", event)
	default:
		f.Warn("hooks.%s handler type %q is not documented; it is reported as written", event, t)
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

// opaque emits a hooks value whose shape is not the documented one, whole
// and sanitized, so a rule still sees it and a reviewer is told.
func (f *file) opaque(event string, value any) {
	where := "hooks"
	if event != "" {
		where += "." + event
	}
	f.Warn("%s has an unrecognized shape; it is reported as an opaque hook", where)
	f.Add(model.ConfigKindHook, []string{"hook", event, "opaque"}, map[string]any{"event": event, "opaque": true, "value": f.SafeValue("", value)})
}
