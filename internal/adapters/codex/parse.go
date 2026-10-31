package codex

import (
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// file is one Codex config file being normalized.
type file struct {
	*kit.Source
}

// settingKinds is the curated set of config.toml and requirements.toml
// keys that decide what runs, how it is sandboxed, what is approved, or
// where the network is reached. Each present key becomes one item.
// mcp_servers and hooks have their own items; other keys are not emitted.
//
// Reviewed against https://developers.openai.com/codex/config-reference
// on 2026-10-31.
var settingKinds = map[string]model.ConfigKind{
	"sandbox_mode":                      model.ConfigKindPermissions,
	"sandbox_workspace_write":           model.ConfigKindPermissions,
	"approval_policy":                   model.ConfigKindPermissions,
	"approvals_reviewer":                model.ConfigKindPermissions,
	"default_permissions":               model.ConfigKindPermissions,
	"permissions":                       model.ConfigKindPermissions,
	"features":                          model.ConfigKindPermissions,
	"web_search":                        model.ConfigKindPermissions,
	"tools":                             model.ConfigKindPermissions,
	"windows":                           model.ConfigKindPermissions,
	"allow_managed_hooks_only":          model.ConfigKindPermissions,
	"allowed_sandbox_modes":             model.ConfigKindPermissions,
	"allowed_approval_policies":         model.ConfigKindPermissions,
	"allowed_permission_profiles":       model.ConfigKindPermissions,
	"experimental_network":              model.ConfigKindPermissions,
	"remote_sandbox_config":             model.ConfigKindPermissions,
	"shell_environment_policy":          model.ConfigKindEnvSetup,
	"notify":                            model.ConfigKindEnvSetup,
	"model_providers":                   model.ConfigKindEnvSetup,
	"model_provider":                    model.ConfigKindEnvSetup,
	"apps_mcp_product_sku":              model.ConfigKindEnvSetup,
	"openai_base_url":                   model.ConfigKindEnvSetup,
	"chatgpt_base_url":                  model.ConfigKindEnvSetup,
	"experimental_realtime_ws_base_url": model.ConfigKindEnvSetup,
	"otel":                              model.ConfigKindEnvSetup,
	"plugins":                           model.ConfigKindPlugin,
	"marketplaces":                      model.ConfigKindPlugin,
	"profile":                           model.ConfigKindPermissions,
	// project_doc_fallback_filenames, model_instructions_file, and
	// experimental_instructions_file (the deprecated spelling of
	// model_instructions_file) decide which file supplies the model's
	// project instructions instead of AGENTS.md. Codex does not list
	// them in projectIgnored, so a trusted project's own config.toml can
	// set them, redirecting instructions to an attacker-chosen path.
	"project_doc_fallback_filenames": model.ConfigKindInstructions,
	"model_instructions_file":        model.ConfigKindInstructions,
	"experimental_instructions_file": model.ConfigKindInstructions,
}

// projectIgnored are keys Codex ignores in a project .codex/config.toml
// (https://developers.openai.com/codex/config-reference#configtoml).
// They are still emitted from a repository, marked ignored_in_project, so
// a rule can tell a planted key from an effective one; every key here
// must also have a settingKinds entry, or it is silently dropped instead
// (apps_mcp_product_sku, model_provider, and profile previously had no
// settingKinds entry and were never emitted despite being listed here).
var projectIgnored = map[string]bool{
	"openai_base_url":                   true,
	"chatgpt_base_url":                  true,
	"apps_mcp_product_sku":              true,
	"model_provider":                    true,
	"model_providers":                   true,
	"notify":                            true,
	"profile":                           true,
	"profiles":                          true,
	"experimental_realtime_ws_base_url": true,
	"otel":                              true,
}

// hookActions are the handler fields that name what a hook runs. An
// mcp_tool handler has none of them and is keyed by its whole sanitized
// definition (server, tool, and input).
var hookActions = []string{"command", "commandWindows", "command_windows", "url", "prompt", "agent"}

// config normalizes config.toml, a profile file, or requirements.toml and
// returns the decoded tree, or nil when it cannot be parsed.
func (f *file) config(raw []byte) map[string]any {
	tree, warnings, err := kit.DecodeTOML(raw, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid TOML: %v", err)
		return nil
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		f.Warn("config must be a TOML table")
		return nil
	}
	if hooks, ok := obj["hooks"]; ok {
		f.hooks(hooks)
	}
	if servers, ok := obj["mcp_servers"]; ok {
		f.MCPServers(servers, "mcp_servers")
	}
	for _, name := range kit.SortedKeys(obj) {
		if name == "profiles" {
			f.profiles(obj[name])
			continue
		}
		kind, ok := settingKinds[name]
		if !ok {
			continue
		}
		f.setting(kind, name, obj[name])
	}
	return obj
}

func (f *file) setting(kind model.ConfigKind, name string, value any) {
	payload := map[string]any{"setting": name, "value": f.SafeValue(name, value)}
	if f.Scope() == model.ScopeRepo && projectIgnored[name] {
		payload["ignored_in_project"] = true
	}
	f.Add(kind, []string{"setting", name}, payload)
}

// profiles emits one item per [profiles.<name>] table: a profile can set
// its own sandbox_mode and approval_policy.
func (f *file) profiles(value any) {
	profiles, ok := value.(map[string]any)
	if !ok {
		f.Warn("profiles must be a table")
		return
	}
	for _, name := range kit.SortedKeys(profiles) {
		payload := map[string]any{"setting": "profiles", "profile": name, "value": f.SafeValue("", profiles[name])}
		if f.Scope() == model.ScopeRepo {
			payload["ignored_in_project"] = true
		}
		f.Add(model.ConfigKindPermissions, []string{"setting", "profiles", name}, payload)
	}
}

// hooks normalizes the hooks table. Arrays are event matcher groups;
// any other member (managed_dir, windows_managed_dir, ...) is emitted as
// a setting so nothing under hooks is dropped silently.
func (f *file) hooks(value any) {
	table, ok := value.(map[string]any)
	if !ok {
		f.Warn("hooks must be a table keyed by event")
		return
	}
	events := map[string]any{}
	for _, name := range kit.SortedKeys(table) {
		if _, isArray := table[name].([]any); isArray {
			events[name] = table[name]
			continue
		}
		f.setting(model.ConfigKindPermissions, "hooks."+name, table[name])
	}
	f.Hooks(events, kit.Grouped, hookActions)
}

// hooksFile normalizes hooks.json: {"description": "...", "hooks": {...}}.
// Codex parses it as strict JSON.
func (f *file) hooksFile(raw []byte) {
	tree, warnings, err := kit.DecodeJSON(raw, kit.StrictJSON, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		f.Warn("hooks.json must be a JSON object")
		return
	}
	hooks, ok := obj["hooks"]
	if !ok {
		for _, name := range kit.SortedKeys(obj) {
			if name != "description" {
				f.Warn("hooks.json has no hooks object; top-level %q is not loaded by Codex", name)
				break
			}
		}
		return
	}
	if _, ok := hooks.(map[string]any); !ok {
		f.Warn("hooks.json hooks member is not an object")
		return
	}
	f.hooks(hooks)
}
