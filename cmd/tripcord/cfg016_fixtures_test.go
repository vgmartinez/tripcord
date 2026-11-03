package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/model"
)

const cfg016FixtureDir = "../../rules/TC-CFG-016.test"

// cfg016Fixture is a TC-CFG-016 fixture built from real init output.
// New raw fixtures select only the harnesses their case needs: every
// agent-config file they carry counts toward pr-context's per-pull-
// request path limit (TC-CFG-014).
//
// init runs with args (nil for no init), then edit changes the tree.
// With againstBase, the fixture is <name>.json instead: the config
// items embedded.Check reports for the edited tree compared with the
// tree before the edit, the way scan --since sees a pull request.
type cfg016Fixture struct {
	kind        string
	args        []string
	edit        func(t *testing.T, dir string)
	againstBase bool
}

func edits(steps ...func(*testing.T, string)) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		for _, step := range steps {
			step(t, dir)
		}
	}
}

func writeFile(rel, content string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		writeTestFile(t, dir, rel, content)
	}
}

const (
	claudeHookCommand  = `"command": "bash \"${CLAUDE_PROJECT_DIR}/.tripcord/bootstrap.sh\" hook --harness claude --event pre-tool",`
	cursorHookCommand  = `"command": "bash \"${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh\" hook --harness cursor --event pre-tool",`
	copilotHookCommand = `"bash": "bash .tripcord/bootstrap.sh hook --harness copilot --event pre-tool",`
	emptyClaudeHooks   = "{\n  \"hooks\": {}\n}\n"
	emptyCursorHooks   = "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n"
)

// removeGuard is the removal a reviewer would miss: the embed's own
// files and every hook go, and only the workflow is left.
var removeGuard = edits(
	removeFile(embedded.BootstrapPath),
	removeFile(embedded.ManifestPath),
	removeFile(embedded.CopilotHooksPath),
	writeFile(embedded.ClaudeSettingsPath, emptyClaudeHooks),
	writeFile(embedded.CursorHooksPath, emptyCursorHooks),
)

// forgeDigest edits bootstrap.sh and rewrites the digest embed.json
// records for it to match.
func forgeDigest(t *testing.T, dir string) {
	t.Helper()
	bootstrap := filepath.Join(dir, filepath.FromSlash(embedded.BootstrapPath))
	raw, err := os.ReadFile(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	before := sha256Hex(raw)
	replaceInFile(embedded.BootstrapPath, `[ "$got" = "$want" ]`, `true`)(t, dir)
	raw, err = os.ReadFile(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	replaceInFile(embedded.ManifestPath, before, sha256Hex(raw))(t, dir)
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
		edit: writeFile(embedded.ClaudeSettingsPath, emptyClaudeHooks)},
	"embed-cursor-wiring-removed":  {kind: "positivos", args: embedArgs(), edit: writeFile(embedded.CursorHooksPath, emptyCursorHooks)},
	"embed-copilot-wiring-removed": {kind: "positivos", args: embedArgs(), edit: removeFile(embedded.CopilotHooksPath)},
	"embed-claude-not-tripcord": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.ClaudeSettingsPath, claudeHookCommand, `"command": "true",`)},
	"embed-cursor-not-tripcord": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.CursorHooksPath, cursorHookCommand, `"command": "true",`)},
	"embed-copilot-not-tripcord": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.CopilotHooksPath, copilotHookCommand, `"bash": "exit 0",`)},
	"embed-claude-hook-loosened": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "continue"`)},
	"embed-claude-disable-all-hooks": {kind: "positivos", args: embedArgs(),
		edit: replaceInFile(embedded.ClaudeSettingsPath, "{\n  \"hooks\"", "{\n  \"disableAllHooks\": true,\n  \"hooks\"")},
	"embed-guard-removed-workflow-left": {kind: "positivos", args: embedArgs("--harness", "claude,copilot"),
		edit: edits(removeFile(embedded.BootstrapPath), removeFile(embedded.ManifestPath), removeFile(embedded.CopilotHooksPath),
			writeFile(embedded.ClaudeSettingsPath, emptyClaudeHooks))},
	"embed-leftover-claude-hook": {kind: "positivos", args: embedArgs("--harness", "claude"),
		edit: edits(removeFile(embedded.BootstrapPath), removeFile(embedded.ManifestPath), removeFile(embedded.WorkflowPath))},
	"embed-bootstrap-missing": {kind: "positivos", args: embedArgs("--harness", "claude"), edit: removeFile(embedded.BootstrapPath)},
	"embed-bootstrap-changed": {kind: "positivos", args: embedArgs("--harness", "claude"),
		edit: replaceInFile(embedded.BootstrapPath, `[ "$got" = "$want" ]`, `true`)},
	"embed-bootstrap-digest-forged": {kind: "positivos", args: embedArgs("--harness", "claude"), edit: forgeDigest},
	"embed-manifest-unreadable":     {kind: "positivos", args: embedArgs("--harness", "claude,cursor,copilot"), edit: writeFile(embedded.ManifestPath, "{\n")},
	"embed-workflow-changed": {kind: "positivos", args: embedArgs("--harness", "claude"),
		edit: replaceInFile(embedded.WorkflowPath, "fail-on: high", "fail-on: critical")},
	"embed-copilot-step-changed": {kind: "positivos", args: embedArgs("--harness", "copilot"),
		edit: replaceInFile(embedded.CopilotSetupStepsPath, "run: bash .tripcord/bootstrap.sh install", "run: bash .tripcord/bootstrap.sh install || true")},
	"base-guard-removed": {kind: "positivos", args: embedArgs(), edit: removeGuard, againstBase: true},
	"base-embed-removed": {kind: "positivos", args: embedArgs(), againstBase: true,
		edit: edits(removeGuard, removeFile(embedded.WorkflowPath), removeFile(embedded.CopilotSetupStepsPath))},
	"base-harness-dropped": {kind: "positivos", args: embedArgs(), againstBase: true,
		edit: replaceInFile(embedded.ManifestPath, "\"cursor\",\n", "")},
	"base-repinned": {kind: "positivos", args: embedArgs(), againstBase: true,
		edit: func(t *testing.T, dir string) {
			t.Helper()
			if code, _, stderr := runCLI(t, "init", "--embed", "--force", "--version", "0.1.1", "--sha256", "linux-x64="+strings.Repeat("e", 64), dir); code != 0 {
				t.Fatalf("re-pin: exit %d: %s", code, stderr)
			}
		}},
	"embed-fresh":       {kind: "negativos", args: embedArgs()},
	"embed-claude-only": {kind: "negativos", args: embedArgs("--harness", "claude")},
	"no-embed":          {kind: "negativos", edit: userRepo},
	"init-policy-only":  {kind: "negativos", args: []string{"init"}, edit: userRepo},
}

// checkAgainstBase is what scan --since reports for TC-CFG-016 when dir
// is the head and base the revision before it, as fixture JSON.
func checkAgainstBase(t *testing.T, base, dir string) map[string]string {
	t.Helper()
	items, err := embedded.Check(dir, embedded.CheckOptions{Base: func(rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(base, filepath.FromSlash(rel)))
	}})
	if err != nil {
		t.Fatal(err)
	}
	if items == nil {
		items = []model.ConfigItem{}
	}
	raw, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"": string(raw) + "\n"}
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
			var base string
			if fx.againstBase {
				base = outsideGit(t)
				copyTree(t, dir, base)
			}
			if fx.edit != nil {
				fx.edit(t, dir)
			}
			committed := filepath.Join(cfg016FixtureDir, fx.kind, name)
			want, read := snapshot(t, dir), snapshot
			if fx.againstBase {
				committed += ".json"
				want, read = checkAgainstBase(t, base, dir), readFixtureFile
			}
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.RemoveAll(committed); err != nil {
					t.Fatal(err)
				}
				for rel, content := range want {
					if rel == "" {
						writeTestFile(t, filepath.Dir(committed), filepath.Base(committed), content)
						continue
					}
					writeTestFile(t, committed, rel, content)
				}
			}
			got := read(t, committed)
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

func readFixtureFile(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"": string(raw)}
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// TestCFG016OtherRuleFixturesHaveNoGuardItems keeps the embed check from
// reporting on the other rules' fixtures: none of them is an embed, so
// a guard item there means the check reads a pattern that is not one.
func TestCFG016OtherRuleFixturesHaveNoGuardItems(t *testing.T) {
	dirs, err := filepath.Glob("../../rules/*.test/*/*")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, dir := range dirs {
		if strings.Contains(filepath.ToSlash(dir), "/TC-CFG-016.test/") {
			continue
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		checked++
		items, err := embedded.Check(dir, embedded.CheckOptions{})
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, item := range items {
			t.Errorf("%s: guard item %s %s", filepath.ToSlash(dir), item.Path, item.Payload)
		}
	}
	if checked == 0 {
		t.Fatal("no fixtures found")
	}
}
