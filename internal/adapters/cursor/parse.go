package cursor

import (
	"encoding/json"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// file is one Cursor config file being normalized. Cursor reads its JSON
// files with the VS Code JSONC parser (comments and trailing commas).
type file struct {
	*kit.Source
}

// hookActions are the handler fields that say what a hook does: a command
// hook runs command, a prompt hook sends prompt to a model.
var hookActions = []string{"command", "prompt"}

func (f *file) decode(raw []byte, what string) map[string]any {
	tree, warnings, err := kit.DecodeJSON(raw, kit.JSONC, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid JSON: %v", err)
		return nil
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		f.Warn("%s must be a JSON object", what)
		return nil
	}
	return obj
}

// hooksFile normalizes hooks.json: {"version": 1, "hooks": {"event":
// [{handler}, ...]}}. Handlers are flat: each carries its own matcher.
// A file without a positive integer version is still normalized, because
// a later Cursor may accept it, and reported.
func (f *file) hooksFile(raw []byte) {
	obj := f.decode(raw, "hooks.json")
	if obj == nil {
		return
	}
	switch v := obj["version"].(type) {
	case nil:
		f.Warn("hooks.json has no version; Cursor requires a positive integer version (1)")
	case json.Number:
		if n, err := v.Int64(); err != nil || n < 1 {
			f.Warn("hooks.json version %s is not a positive integer", v)
		}
	default:
		f.Warn("hooks.json version must be a number")
	}
	hooks, ok := obj["hooks"]
	if !ok {
		return
	}
	f.Hooks(hooks, kit.Flat, hookActions)
}

// mcpFile normalizes mcp.json: {"mcpServers": {...}}.
func (f *file) mcpFile(raw []byte) {
	obj := f.decode(raw, "mcp.json")
	if obj == nil {
		return
	}
	if servers, ok := obj["mcpServers"]; ok {
		f.MCPServers(servers, "mcpServers")
	}
}

// environment normalizes the cloud-agent .cursor/environment.json. Every
// top-level member is one env-setup item (install, start, build,
// snapshot, ...), because each decides what runs or which image boots;
// terminals become one item per terminal.
func (f *file) environment(raw []byte) {
	obj := f.decode(raw, "environment.json")
	if obj == nil {
		return
	}
	for _, name := range kit.SortedKeys(obj) {
		value := obj[name]
		if name == "terminals" {
			f.terminals(value)
			continue
		}
		var safe any
		if m, ok := value.(map[string]any); ok && name == "env" {
			safe = f.RedactValues(m)
		} else {
			safe = f.SafeValue(name, value)
		}
		payload := map[string]any{"setting": name, "value": safe}
		command, ok := value.(string)
		if !ok && (name == "install" || name == "start") {
			f.Warn("%s must be a string; it is reported as written", name)
		}
		if ok {
			f.AddDetect(model.ConfigKindEnvSetup, []string{"setting", name}, payload, map[string]any{"value": command})
			continue
		}
		f.Add(model.ConfigKindEnvSetup, []string{"setting", name}, payload)
	}
}

func (f *file) terminals(value any) {
	list, ok := value.([]any)
	if !ok {
		f.Warn("terminals must be an array")
		return
	}
	for _, t := range list {
		terminal, ok := t.(map[string]any)
		if !ok {
			f.Warn("terminals entry must be an object")
			continue
		}
		name, _ := terminal["name"].(string)
		command, isString := terminal["command"].(string)
		payload := f.SafeObject(terminal)
		payload["setting"] = "terminals"
		if !isString {
			if _, present := terminal["command"]; present {
				f.Warn("terminals command must be a string; it is reported as written")
			}
			f.Add(model.ConfigKindEnvSetup, []string{"terminal", name, command}, payload)
			continue
		}
		f.AddDetect(model.ConfigKindEnvSetup, []string{"terminal", name, command}, payload, map[string]any{"command": command})
	}
}
