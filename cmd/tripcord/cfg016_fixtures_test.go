package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
)

const cfg016FixtureDir = "../../rules/TC-CFG-016.test"

// cfg016Fixture is a TC-CFG-016 raw fixture built from real init output:
// init runs with args (nil for no init), then edit changes the tree.
type cfg016Fixture struct {
	kind string
	args []string
	edit func(t *testing.T, dir string)
}

func removeFile(rel string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatal(err)
		}
	}
}

func replaceInFile(rel, old, replacement string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), old) {
			t.Fatalf("%s does not contain %q", rel, old)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(raw), old, replacement, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const userClaudeSettings = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "./scripts/lint.sh"
          }
        ]
      }
    ]
  }
}
`

func userRepo(t *testing.T, dir string) {
	t.Helper()
	writeTestFile(t, dir, embedded.ClaudeSettingsPath, userClaudeSettings)
	writeTestFile(t, dir, "scripts/lint.sh", "#!/bin/sh\nexit 0\n")
}

var cfg016Fixtures = map[string]cfg016Fixture{
	"embed-claude-wiring-removed": {kind: "positivos", args: embedArgs(), edit: removeFile(embedded.ClaudeSettingsPath)},
	"embed-claude-only-wiring-removed": {kind: "positivos", args: embedArgs("--harness", "claude"),
		edit: func(t *testing.T, dir string) {
			writeTestFile(t, dir, embedded.ClaudeSettingsPath, "{\n  \"hooks\": {}\n}\n")
		}},
	"embed-cursor-wiring-removed": {kind: "positivos", args: embedArgs(),
		edit: func(t *testing.T, dir string) {
			writeTestFile(t, dir, embedded.CursorHooksPath, "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n")
		}},
	"embed-copilot-wiring-removed": {kind: "positivos", args: embedArgs(), edit: removeFile(embedded.CopilotHooksPath)},
	"embed-claude-not-tripcord": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.ClaudeSettingsPath, `"command": "tripcord",`, `"command": "true",`)},
	"embed-cursor-not-tripcord": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.CursorHooksPath, `"command": "tripcord hook --harness cursor --event pre-tool",`, `"command": "true",`)},
	"embed-copilot-not-tripcord": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.CopilotHooksPath, `"bash": "tripcord hook --harness copilot --event pre-tool",`, `"bash": "exit 0",`)},
	"embed-claude-hook-loosened": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "continue"`)},
	"embed-claude-disable-all-hooks": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.ClaudeSettingsPath, "{\n  \"hooks\"", "{\n  \"disableAllHooks\": true,\n  \"hooks\"")},
	"embed-fresh":       {kind: "negativos", args: embedArgs()},
	"embed-claude-only": {kind: "negativos", args: embedArgs("--harness", "claude")},
	"no-embed":          {kind: "negativos", edit: userRepo},
	"init-policy-only":  {kind: "negativos", args: []string{"init"}, edit: userRepo},
}

// TestCFG016FixturesMatchInit keeps the TC-CFG-016 embed fixtures equal
// to what init writes today, plus each fixture's edit. UPDATE_GOLDEN=1
// rewrites them.
func TestCFG016FixturesMatchInit(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(cfg016Fixtures)) {
		fx := cfg016Fixtures[name]
		t.Run(name, func(t *testing.T) {
			dir := outsideGit(t)
			if fx.args != nil {
				if code, _, stderr := runCLI(t, append(slices.Clone(fx.args), dir)...); code != 0 {
					t.Fatalf("init: exit %d: %s", code, stderr)
				}
			}
			if fx.edit != nil {
				fx.edit(t, dir)
			}
			want := snapshot(t, dir)
			committed := filepath.Join(cfg016FixtureDir, fx.kind, name)
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.RemoveAll(committed); err != nil {
					t.Fatal(err)
				}
				for rel, content := range want {
					writeTestFile(t, committed, rel, content)
				}
			}
			got := snapshot(t, committed)
			for _, rel := range slices.Sorted(maps.Keys(want)) {
				if got[rel] != want[rel] {
					t.Errorf("%s/%s differs from init output; rerun with UPDATE_GOLDEN=1", committed, rel)
				}
			}
			for rel := range got {
				if _, ok := want[rel]; !ok {
					t.Errorf("%s/%s is not in init output", committed, rel)
				}
			}
		})
	}
}
