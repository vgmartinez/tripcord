package copilot

import (
	"encoding/json"
	"strings"

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
		f.step(step, job, workflow)
	}
}

// step emits one setup step, keyed by its id, name, uses, or run (the
// first present). env values are redacted; with inputs are sanitized and
// secret-looking ones redacted.
func (f *file) step(step, job, workflow map[string]any) {
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
	run, isString := step["run"].(string)
	key := []string{"step", setupJob, label}
	if run != "" && run != label {
		key = append(key, run)
	}
	if !isString {
		if _, present := step["run"]; present {
			f.Warn("%s step run must be a string; it is reported as written", setupJob)
		}
		f.Add(model.ConfigKindEnvSetup, key, payload)
		return
	}
	rawRun := run
	if shell, ok := effectiveShell(step, job, workflow); ok && shellErrexit(shell) {
		// GitHub runs the default, bash, and sh with errexit. The
		// Detect view shows that; set +e in the script turns it off
		// again when the command is read.
		rawRun = "set -e; " + run
	}
	detect := map[string]any{"run": rawRun}
	if dir, ok := workingDirectory(step, job, workflow); ok {
		// A relative path in the script, such as a sha256sum -c sums
		// file, is then not read from the repository root.
		detect["working-directory"] = dir
	}
	f.AddDetect(model.ConfigKindEnvSetup, key, payload, detect)
}

// workingDirectory is the step's working-directory, then the job's
// defaults.run.working-directory, then the workflow's, as GitHub picks
// it. ok is false when none sets one.
func workingDirectory(step, job, workflow map[string]any) (any, bool) {
	if dir, ok := step["working-directory"]; ok {
		return dir, true
	}
	for _, scope := range []map[string]any{job, workflow} {
		defaults, _ := scope["defaults"].(map[string]any)
		run, _ := defaults["run"].(map[string]any)
		if dir, ok := run["working-directory"]; ok {
			return dir, true
		}
	}
	return nil, false
}

// effectiveShell is the shell GitHub uses: the step's shell, then the
// job's defaults.run.shell, then the workflow's, then the platform
// default. ok is false when a shell key is present but not a string.
func effectiveShell(step, job, workflow map[string]any) (string, bool) {
	if shell, ok := step["shell"].(string); ok {
		return shell, true
	}
	if _, present := step["shell"]; present {
		return "", false
	}
	if shell, ok := defaultsRunShell(job); ok {
		return shell, true
	}
	if shell, ok := defaultsRunShell(workflow); ok {
		return shell, true
	}
	return "", true
}

func defaultsRunShell(scope map[string]any) (string, bool) {
	defaults, _ := scope["defaults"].(map[string]any)
	run, _ := defaults["run"].(map[string]any)
	shell, ok := run["shell"].(string)
	return shell, ok
}

// shellErrexit reports whether GitHub runs this shell with -e. The
// default and the built-in names bash and sh do. A custom template such
// as "bash {0}" does only when its command before {0} passes -e.
func shellErrexit(shell string) bool {
	shell = strings.TrimSpace(shell)
	switch shell {
	case "", "bash", "sh":
		return true
	case "pwsh", "powershell", "python", "cmd":
		return false
	}
	template := shell
	if !strings.Contains(template, "{0}") {
		template += " {0}"
	}
	before, _, _ := strings.Cut(template, "{0}")
	fields := strings.Fields(before)
	if len(fields) < 2 {
		return false
	}
	for _, arg := range fields[1:] {
		if arg == "-o" {
			continue
		}
		if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.Contains(arg, "e") {
			return true
		}
	}
	return false
}

func (f *file) safeWithEnv(name string, value any) any {
	if m, ok := value.(map[string]any); ok && name == "env" {
		return f.RedactValues(m)
	}
	return f.SafeValue(name, value)
}
