package generic

import (
	"encoding/json"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// vscodeProduct names VS Code in decoder warnings: it reads exact key
// names, so a case variant is ignored.
const vscodeProduct = "VS Code"

// platformKeys are the per-OS override objects of a task or of the file.
var platformKeys = []string{"windows", "linux", "osx"}

// tasksFile normalizes .vscode/tasks.json (JSONC). Each task becomes one
// item; run_on and folder_open record runOptions.runOn, the setting that
// makes VS Code start a task when the folder opens. File-level options
// and per-OS overrides become one env-setup item each, because every task
// inherits them.
func tasksFile(s *kit.Source, raw []byte) {
	tree, warnings, err := kit.DecodeJSON(raw, kit.JSONC, vscodeProduct)
	s.WarnAll(warnings)
	if err != nil {
		s.Warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		s.Warn("tasks.json must be a JSON object")
		return
	}
	for _, name := range append([]string{"options"}, platformKeys...) {
		value, ok := obj[name].(map[string]any)
		if !ok {
			continue
		}
		s.Add(model.ConfigKindEnvSetup, []string{"setting", name}, map[string]any{"setting": name, "value": safeTaskObject(s, value)})
	}
	value, present := obj["tasks"]
	if !present {
		return
	}
	tasks, ok := value.([]any)
	if !ok {
		s.Warn("tasks must be an array")
		return
	}
	for _, t := range tasks {
		task, ok := t.(map[string]any)
		if !ok {
			s.Warn("tasks entry must be an object")
			continue
		}
		emitTask(s, task)
	}
}

func emitTask(s *kit.Source, task map[string]any) {
	payload := safeTaskObject(s, task)
	for _, name := range platformKeys {
		if override, ok := task[name].(map[string]any); ok {
			payload[name] = safeTaskObject(s, override)
		}
	}
	label := firstString(task, "label", "taskName", "script")
	runOn := "default"
	if options, ok := task["runOptions"].(map[string]any); ok {
		if v, ok := options["runOn"].(string); ok {
			runOn = v
		}
	}
	payload["label"] = s.SafeString(label)
	payload["run_on"] = runOn
	payload["folder_open"] = strings.EqualFold(runOn, "folderOpen")
	command := commandText(task["command"])
	s.AddDetect(model.ConfigKindTask, []string{"task", label, command}, payload, task, taskKeep...)
}

// taskKeep are the task fields whose sanitized value stays in the
// detection view (see kit.Source.AddDetect): the objects that carry
// redacted env values, and the fields emitTask sets itself.
var taskKeep = append([]string{"env", "env_keys", "options", "label", "run_on", "folder_open"}, platformKeys...)

// safeTaskObject sanitizes a task or options object and redacts the
// values of options.env, keeping its key names as env_keys.
func safeTaskObject(s *kit.Source, obj map[string]any) map[string]any {
	out := s.SafeObject(obj)
	if env, ok := obj["env"].(map[string]any); ok {
		out["env"] = s.RedactValues(env)
		out["env_keys"] = kit.SortedKeys(env)
	}
	options, ok := obj["options"].(map[string]any)
	if !ok {
		return out
	}
	if env, ok := options["env"].(map[string]any); ok {
		safe, _ := out["options"].(map[string]any)
		safe["env"] = s.RedactValues(env)
		safe["env_keys"] = kit.SortedKeys(env)
	}
	return out
}

func firstString(obj map[string]any, names ...string) string {
	for _, name := range names {
		if v, ok := obj[name].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// commandText is a task command as text: a string, the value of a
// {"value": ..., "quoting": ...} object, or canonical JSON otherwise.
func commandText(v any) string {
	switch c := v.(type) {
	case nil:
		return ""
	case string:
		return c
	case map[string]any:
		if value, ok := c["value"].(string); ok {
			return value
		}
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

// mcpFile normalizes .vscode/mcp.json (JSONC): {"servers": {...},
// "inputs": [...]}. inputs only declare prompts for values VS Code asks
// the user for and are not emitted.
func mcpFile(s *kit.Source, raw []byte) {
	tree, warnings, err := kit.DecodeJSON(raw, kit.JSONC, vscodeProduct)
	s.WarnAll(warnings)
	if err != nil {
		s.Warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		s.Warn("mcp.json must be a JSON object")
		return
	}
	if servers, ok := obj["servers"]; ok {
		s.MCPServers(servers, "servers")
	}
}
