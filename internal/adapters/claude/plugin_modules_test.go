package claude

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// moduleItems returns the plugin items with setting "modules".
func moduleItems(t *testing.T, items []model.ConfigItem) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, item := range items {
		if item.Kind != model.ConfigKindPlugin {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal(item.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["setting"] == "modules" {
			payload["path"] = item.Path
			out = append(out, payload)
		}
	}
	return out
}

// TestPluginHooksModules covers the Claude Code mod shape of a plugin
// hooks file (issue #126): a well-formed modules value is one plugin
// item and no diagnostic; a file that declares nothing is an
// informational warning; anything else keeps the scan incomplete.
func TestPluginHooksModules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		manifest  string
		hooksPath string
		hooks     string
		module    string // module_path of the one modules item, if any
		diag      string
		info      bool
	}{
		{name: "mod", hooks: `{"modules": ["./register.tsx"]}`, module: "p/hooks/register.tsx"},
		{name: "mod no dot slash", hooks: `{"modules": ["lib/register.ts"]}`, module: "p/hooks/lib/register.ts"},
		{name: "mod and hooks", hooks: `{"modules": ["./register.tsx"], "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "true"}]}]}}`, module: "p/hooks/register.tsx"},
		{name: "mod up to plugin root", hooks: `{"modules": ["../register.tsx"]}`, module: "p/register.tsx"},
		{
			name:      "mod in a manifest-named hooks file",
			manifest:  `{"name": "p", "hooks": "./config/mod/hooks.json"}`,
			hooksPath: "p/config/mod/hooks.json",
			hooks:     `{"modules": ["../../register.tsx"]}`,
			module:    "p/register.tsx",
		},
		{name: "empty object", hooks: `{}`, diag: "plugin hooks.json declares no hooks", info: true},
		{name: "description only", hooks: `{"description": "x"}`, diag: "plugin hooks.json declares no hooks", info: true},
		{name: "unknown key", hooks: `{"unknown": 1}`, diag: `plugin hooks.json has no hooks object; unknown key "unknown"`},
		{name: "unknown keys with description", hooks: `{"description": "x", "b": 1, "a": 2}`, diag: `plugin hooks.json has no hooks object; unknown keys "a", "b"`},
		{name: "modules not array", hooks: `{"modules": "./register.tsx"}`, diag: "plugin hooks.json modules must be an array with one path"},
		{name: "modules empty", hooks: `{"modules": []}`, diag: "plugin hooks.json modules must be an array with one path"},
		{name: "modules two", hooks: `{"modules": ["./a.ts", "./b.ts"]}`, diag: "plugin hooks.json modules must be an array with one path"},
		{name: "modules not string", hooks: `{"modules": [1]}`, diag: "plugin hooks.json modules must be an array with one path"},
		{name: "modules blank", hooks: `{"modules": [" "]}`, diag: "plugin hooks.json modules must be an array with one path"},
		{name: "modules absolute", hooks: `{"modules": ["/opt/x.ts"]}`, diag: `plugin hooks.json module "/opt/x.ts" is not a relative path`},
		{name: "modules drive", hooks: `{"modules": ["C:\\x.ts"]}`, diag: "is not a relative path"},
		{name: "modules URL", hooks: `{"modules": ["https://example.invalid/x.ts"]}`, diag: "is not a relative path"},
		{name: "modules escapes plugin", hooks: `{"modules": ["../../x.ts"]}`, diag: `plugin hooks.json module "../../x.ts" is outside its plugin directory`},
		{name: "modules is the directory", hooks: `{"modules": ["."]}`, diag: "is outside its plugin directory"},
		{name: "modules with hooks not object", hooks: `{"modules": ["./r.ts"], "hooks": []}`, module: "p/hooks/r.ts", diag: "plugin hooks.json hooks member is not an object"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			manifest := tc.manifest
			if manifest == "" {
				manifest = `{"name": "p", "hooks": "./hooks/hooks.json"}`
			}
			hooksPath := tc.hooksPath
			if hooksPath == "" {
				hooksPath = "p/hooks/hooks.json"
			}
			writeFile(t, filepath.Join(root, "p", ".claude-plugin", "plugin.json"), manifest)
			writeFile(t, filepath.Join(root, filepath.FromSlash(hooksPath)), tc.hooks)
			got := discover(t, New(Options{}), root)
			mods := moduleItems(t, got.Items)
			if tc.module == "" && len(mods) != 0 {
				t.Fatalf("modules items %v", mods)
			}
			if tc.module != "" {
				if len(mods) != 1 || mods[0]["module_path"] != tc.module || mods[0]["plugin_root"] != "p" || mods[0]["path"] != hooksPath {
					t.Fatalf("modules items %v, want module_path %s", mods, tc.module)
				}
			}
			if tc.diag == "" {
				if len(got.Diagnostics) != 0 {
					t.Fatalf("diagnostics %v", got.Diagnostics)
				}
				return
			}
			if len(got.Diagnostics) != 1 || !strings.Contains(got.Diagnostics[0], tc.diag) {
				t.Fatalf("diagnostics %v, want one with %q", got.Diagnostics, tc.diag)
			}
		})
	}
}

// TestPluginHooksModulesInformational checks which diagnostics are
// informational: only the one for a file that declares nothing.
func TestPluginHooksModulesInformational(t *testing.T) {
	t.Parallel()
	for body, informational := range map[string]bool{
		`{}`:                     true,
		`{"description": "x"}`:   true,
		`{"unknown": 1}`:         false,
		`{"modules": "x.ts"}`:    false,
		`{"modules": ["/x.ts"]}`: false,
	} {
		c := newCollector(nil)
		s := newSrc(c, model.ScopeRepo, "p/hooks/hooks.json", []byte(body))
		s.pluginHooksIn([]byte(body), "p")
		if len(c.diags) != 1 || c.diags[0].Informational != informational {
			t.Fatalf("%s: diagnostics %+v, want one with informational %v", body, c.diags, informational)
		}
	}
}
