package copilot

import (
	"encoding/json"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// file is one Copilot config file being normalized. Copilot CLI parses
// its JSON files strictly. Copilot accepts hook event names in camelCase
// and PascalCase (sessionStart and SessionStart) and runs both, so case
// variants in a hooks object are not reported.
type file struct {
	*kit.Source
}

// hookActions are the handler fields that say what a hook runs, in the
// order Copilot prefers them: bash (the only field the cloud agent
// honors), powershell, the cross-platform command, exec, an http hook's
// url, a prompt hook's prompt, and the per-OS overrides of agent hooks.
var hookActions = []string{"bash", "powershell", "command", "exec", "url", "prompt", "linux", "osx", "windows"}

// setupJob is the only job of copilot-setup-steps.yml the cloud agent
// runs before it starts.
const setupJob = "copilot-setup-steps"

func (f *file) decode(raw []byte, what string) map[string]any {
	tree, warnings, err := kit.DecodeJSON(raw, kit.StrictJSON, product, "hooks")
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

// hooksFile normalizes a hook file (.github/hooks/*.json, the user hooks
// directory, or policy.d): {"version": 1, "disableAllHooks": false,
// "hooks": {...}}. Entries are flat handlers or Claude-format matcher
// groups. Copilot rejects a file with a bad version; its hooks are still
// emitted, and the file is reported.
func (f *file) hooksFile(raw []byte) {
	obj := f.decode(raw, "hook file")
	if obj == nil {
		return
	}
	switch v := obj["version"].(type) {
	case nil:
		f.Warn("hook file has no version; Copilot requires version 1")
	case json.Number:
		if v.String() != "1" {
			f.Warn("hook file version %s is not 1; Copilot rejects the file", v)
		}
	default:
		f.Warn("hook file version must be the number 1")
	}
	f.disableAll(obj)
	if hooks, ok := obj["hooks"]; ok {
		f.Hooks(hooks, kit.Either, hookActions)
	}
}

// disableAll emits disableAllHooks as a permissions item and marks every
// hook of the file with hooks_disabled, so a rule can tell configured but
// disabled hooks apart.
func (f *file) disableAll(obj map[string]any) {
	value, ok := obj["disableAllHooks"]
	if !ok {
		return
	}
	f.Add(model.ConfigKindPermissions, []string{"setting", "disableAllHooks"}, map[string]any{"setting": "disableAllHooks", "value": f.SafeValue("", value)})
	if disabled, _ := value.(bool); disabled {
		f.WithField("hooks_disabled", true)
	}
}

// settings normalizes .github/copilot/settings.json, settings.local.json,
// and ~/.copilot/settings.json: the inline hooks block and
// disableAllHooks. Other settings are not emitted.
func (f *file) settings(raw []byte) {
	obj := f.decode(raw, "settings")
	if obj == nil {
		return
	}
	f.disableAll(obj)
	if hooks, ok := obj["hooks"]; ok {
		f.Hooks(hooks, kit.Either, hookActions)
	}
}

// mcpConfig normalizes ~/.copilot/mcp-config.json: {"mcpServers": {...}}.
func (f *file) mcpConfig(raw []byte) {
	obj := f.decode(raw, "mcp-config.json")
	if obj == nil {
		return
	}
	if servers, ok := obj["mcpServers"]; ok {
		f.MCPServers(servers, "mcpServers")
	}
}

// agent normalizes a custom agent (.github/agents/*.agent.md). Its
// frontmatter can declare hooks and MCP servers, so it is parsed strictly.
func (f *file) agent(raw []byte) {
	meta := f.Markdown(model.ConfigKindInstructions, "agent", raw, kit.StrictFrontmatter, "hooks")
	if meta == nil {
		return
	}
	if hooks, ok := meta["hooks"]; ok {
		f.Hooks(hooks, kit.Either, hookActions)
	}
	for _, name := range []string{"mcp-servers", "mcpServers"} {
		if servers, ok := meta[name]; ok {
			f.MCPServers(servers, name)
		}
	}
}

// setupSteps normalizes .github/workflows/copilot-setup-steps.yml. The
// cloud agent runs the copilot-setup-steps job, with the repository's
// secrets and outside its firewall, before the session starts. The job
// (without its steps) is one env-setup item and each step another; the
// workflow's triggers, permissions, and env are one more.
// setupStepsAliasLimits bounds anchor/alias expansion in
// copilot-setup-steps.yml. GitHub Actions supports anchors, and a
// legitimate workflow may reuse a handful of env or step blocks with
// one; these limits are generous for that while still failing closed,
// quickly, on a "billion laughs" style alias bomb.
var setupStepsAliasLimits = kit.AliasLimits{MaxAliases: 100, MaxNodes: 10_000}

func (f *file) setupSteps(raw []byte) {
	tree, warnings, err := kit.DecodeYAMLAliases(raw, "GitHub Actions", setupStepsAliasLimits)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid YAML: %v", err)
		return
	}
	workflow, ok := tree.(map[string]any)
	if !ok {
		f.Warn("workflow must be a YAML mapping")
		return
	}
	header := map[string]any{"setting": "workflow"}
	for _, name := range []string{"on", "permissions", "env", "defaults"} {
		if value, ok := workflow[name]; ok {
			header[name] = f.safeWithEnv(name, value)
		}
	}
	f.Add(model.ConfigKindEnvSetup, []string{"workflow"}, header)
	jobs, _ := workflow["jobs"].(map[string]any)
	job, ok := jobs[setupJob].(map[string]any)
	if !ok {
		f.Note("no %s job; the Copilot cloud agent does not run this workflow", setupJob)
		return
	}
	payload := map[string]any{"setting": "job", "job": setupJob}
	for _, name := range kit.SortedKeys(job) {
		if name != "steps" {
			payload[name] = f.safeWithEnv(name, job[name])
		}
	}
	f.Add(model.ConfigKindEnvSetup, []string{"job", setupJob}, payload)
	steps, present := job["steps"]
	if !present {
		return
	}
	list, ok := steps.([]any)
	if !ok {
		f.Warn("jobs.%s.steps must be a sequence", setupJob)
		return
	}
	for _, s := range list {
		step, ok := s.(map[string]any)
		if !ok {
			f.Warn("jobs.%s.steps entry must be a mapping", setupJob)
			continue
		}
		f.step(step)
	}
}

// step emits one setup step, keyed by its id, name, uses, or run (the
// first present). env values are redacted; with inputs are sanitized and
// secret-looking ones redacted.
func (f *file) step(step map[string]any) {
	payload := map[string]any{"setting": "step", "job": setupJob}
	for _, name := range kit.SortedKeys(step) {
		payload[name] = f.safeWithEnv(name, step[name])
	}
	label := ""
	for _, name := range []string{"id", "name", "uses", "run"} {
		if v, ok := step[name].(string); ok && v != "" {
			label = v
			break
		}
	}
	run, _ := step["run"].(string)
	key := []string{"step", setupJob, label}
	if run != "" && run != label {
		key = append(key, run)
	}
	f.Add(model.ConfigKindEnvSetup, key, payload)
}

func (f *file) safeWithEnv(name string, value any) any {
	if m, ok := value.(map[string]any); ok && name == "env" {
		return f.RedactValues(m)
	}
	return f.SafeValue(name, value)
}
