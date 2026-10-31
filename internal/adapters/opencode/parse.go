package opencode

import (
	"path"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// file is one OpenCode config, agent, command, plugin, or tool file
// being normalized.
type file struct {
	*kit.Source
}

// settingKinds is the curated set of opencode.json keys that decide what
// runs, what is approved, or what the model is told. mcp, plugin, agent,
// mode, and command have their own items; other keys are not emitted.
//
// Reviewed against https://opencode.ai/docs/config/ on 2026-10-31.
var settingKinds = map[string]model.ConfigKind{
	"permission":   model.ConfigKindPermissions,
	"tools":        model.ConfigKindPermissions,
	"share":        model.ConfigKindPermissions,
	"autoupdate":   model.ConfigKindPermissions,
	"instructions": model.ConfigKindInstructions,
	"formatter":    model.ConfigKindEnvSetup,
	"lsp":          model.ConfigKindEnvSetup,
	"provider":     model.ConfigKindEnvSetup,
	"experimental": model.ConfigKindEnvSetup,
}

// config normalizes an opencode.json or opencode.jsonc. OpenCode reads
// both as JSONC (comments and trailing commas). {env:NAME} and
// {file:path} placeholders are reported as written, never expanded.
func (f *file) config(raw []byte) {
	tree, warnings, err := kit.DecodeJSON(raw, kit.JSONC, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		f.Warn("config must be a JSON object")
		return
	}
	if servers, ok := obj["mcp"]; ok {
		f.mcp(servers)
	}
	if plugins, ok := obj["plugin"]; ok {
		f.plugins(plugins)
	}
	for _, name := range []string{"agent", "mode"} {
		if v, ok := obj[name]; ok {
			f.named(name, "agent", v)
		}
	}
	if v, ok := obj["command"]; ok {
		f.named("command", "command", v)
	}
	for _, name := range kit.SortedKeys(obj) {
		if kind, ok := settingKinds[name]; ok {
			f.Add(kind, []string{"setting", name}, map[string]any{"setting": name, "value": f.SafeValue(name, obj[name])})
		}
	}
}

// mcp emits one item per server. A local server's command is an argv
// array; its environment and a remote server's headers are redacted.
func (f *file) mcp(value any) {
	servers, ok := value.(map[string]any)
	if !ok {
		f.Warn("mcp must be an object")
		return
	}
	for _, name := range kit.SortedKeys(servers) {
		server, ok := servers[name].(map[string]any)
		if !ok {
			f.Warn("MCP server %q must be an object", name)
			continue
		}
		payload := f.SafeObject(server)
		for _, field := range []string{"environment", "headers"} {
			m, ok := server[field].(map[string]any)
			if !ok {
				continue
			}
			payload[field] = f.RedactValues(m)
			keysName := "env_keys"
			if field == "headers" {
				keysName = "header_keys"
			}
			payload[keysName] = kit.SortedKeys(m)
		}
		switch command := server["command"].(type) {
		case []any:
			payload["command"] = f.SafeValue("", f.SafeToolArgv(command))
		case string, nil:
		default:
			f.Warn("MCP server %q command must be an array of strings", name)
		}
		payload["name"] = name
		f.Add(model.ConfigKindMCPServer, []string{"mcp", name}, payload)
	}
}

// plugins emits one item per npm plugin specifier OpenCode installs and
// loads at startup.
func (f *file) plugins(value any) {
	list, ok := value.([]any)
	if !ok {
		f.Warn("plugin must be an array of package names")
		f.Add(model.ConfigKindPlugin, []string{"plugin"}, map[string]any{"setting": "plugin", "value": f.SafeValue("plugin", value)})
		return
	}
	for _, p := range list {
		spec, ok := p.(string)
		if !ok {
			f.Warn("plugin entries must be strings")
			f.Add(model.ConfigKindPlugin, []string{"plugin"}, map[string]any{"setting": "plugin", "value": f.SafeValue("", p)})
			continue
		}
		safe := f.SafeString(spec)
		f.Add(model.ConfigKindPlugin, []string{"plugin", safe}, map[string]any{"setting": "plugin", "plugin": safe})
	}
}

// named emits one instructions item per entry of an object keyed by
// agent, mode, or command name. Each entry is sanitized whole: it holds
// the prompt, the model, and the per-agent tool and permission overrides.
func (f *file) named(setting, role string, value any) {
	table, ok := value.(map[string]any)
	if !ok {
		f.Warn("%s must be an object", setting)
		return
	}
	for _, name := range kit.SortedKeys(table) {
		f.Add(model.ConfigKindInstructions, []string{setting, name}, map[string]any{
			"setting": setting,
			"role":    role,
			"name":    name,
			"value":   f.SafeValue("", table[name]),
		})
	}
}

// codeFile reports a plugin or custom tool module OpenCode imports and
// runs in its own process. The code is not parsed or kept: the item
// carries the file name and language, and the source sha256 lets a
// reviewer pin it.
func (f *file) codeFile(role, rel string) {
	base := path.Base(rel)
	f.Add(model.ConfigKindPlugin, []string{role, strings.ToLower(base)}, map[string]any{
		"role":       role,
		"name":       f.SafeString(base),
		"language":   strings.TrimPrefix(strings.ToLower(path.Ext(base)), "."),
		"executable": true,
	})
}
