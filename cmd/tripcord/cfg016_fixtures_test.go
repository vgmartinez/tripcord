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
	"github.com/vgmartinez/tripcord/internal/policy"
	"github.com/vgmartinez/tripcord/internal/txtar"
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
// tree before the edit, the way scan --since sees a pull request. With
// tracked, it is <name>.json too, with every file tracked by git: a raw
// fixture directory is not a repository, so its settings.local.json is
// personal.
type cfg016Fixture struct {
	kind        string
	args        []string
	edit        func(t *testing.T, dir string)
	againstBase bool
	tracked     bool
	// crlfTolerant compares content CRLF-normalized the way the embed
	// checker's own digest does, rather than byte-for-byte. When this
	// fixture was a plain directory, its own .gitattributes `text
	// eol=lf` lines made git store three of its files with LF, and the
	// archive keeps those committed bytes. The actual CRLF-bytes
	// behavior is pinned independently, without going through git at
	// all, by TestCheckCRLFCheckout in internal/embedded.
	crlfTolerant bool
}

func (fx cfg016Fixture) items() bool { return fx.againstBase || fx.tracked }

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
	claudeHookCommand  = `"command": "bash \"${CLAUDE_PROJECT_DIR:-.}/.tripcord/bootstrap.sh\" hook --harness claude --event pre-tool --on-failure block",`
	cursorHookCommand  = `"command": "bash \"${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh\" hook --harness cursor --event pre-tool --on-failure block",`
	copilotHookCommand = `"bash": "bash .tripcord/bootstrap.sh hook --harness copilot --event pre-tool --on-failure block",`
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
	replaceInFile(embedded.BootstrapPath, `[ "$got" != "$want" ]`, `false`)(t, dir)
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

func removeIfExists(rel string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		err := os.Remove(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

// crlf converts rel to CRLF line endings, the way a Windows checkout
// with core.autocrlf writes it.
func crlf(rel string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(raw), "\n", "\r\n")), 0o644); err != nil {
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

const (
	localDisableAllHooks = "{\n  \"disableAllHooks\": true\n}\n"
	localPreToolUse      = "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"true\"\n          }\n        ]\n      }\n    ]\n  }\n}\n"
)

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
		edit: replaceInFile(embedded.BootstrapPath, `[ "$got" != "$want" ]`, `false`)},
	"embed-bootstrap-digest-forged": {kind: "positivos", args: embedArgs("--harness", "claude"), edit: forgeDigest},
	"embed-manifest-unreadable":     {kind: "positivos", args: embedArgs("--harness", "claude,cursor,copilot"), edit: writeFile(embedded.ManifestPath, "{\n")},
	"embed-workflow-changed": {kind: "positivos", args: embedArgs("--harness", "claude"),
		edit: replaceInFile(embedded.WorkflowPath, "fail-on: high", "fail-on: critical")},
	"embed-copilot-step-changed": {kind: "positivos", args: embedArgs("--cloud-setup", "--harness", "copilot"),
		edit: replaceInFile(embedded.CopilotSetupStepsPath, "run: bash .tripcord/bootstrap.sh install", "run: bash .tripcord/bootstrap.sh install || true")},
	"base-guard-removed": {kind: "positivos", args: embedArgs(), edit: removeGuard, againstBase: true},
	"base-embed-removed": {kind: "positivos", args: embedArgs(), againstBase: true,
		edit: edits(removeGuard, removeFile(embedded.WorkflowPath), removeIfExists(embedded.CopilotSetupStepsPath))},
	"base-harness-dropped": {kind: "positivos", args: embedArgs(), againstBase: true,
		edit: replaceInFile(embedded.ManifestPath, "\"cursor\",\n", "")},
	"base-repinned": {kind: "positivos", args: embedArgs(), againstBase: true,
		edit: func(t *testing.T, dir string) {
			t.Helper()
			if code, _, stderr := runCLI(t, "init", "--embed", "--force", "--version", "0.1.1", "--sha256", "linux-x64="+strings.Repeat("e", 64), dir); code != 0 {
				t.Fatalf("re-pin: exit %d: %s", code, stderr)
			}
		}},
	// .gitattributes is kept as init writes it: this fixture is about the
	// digest's own CRLF leniency (a real autocrlf checkout converts
	// every line, so lf normalizes it), not about the guard on
	// .gitattributes itself (see embed-gitattributes-removed and
	// embed-gitattributes-weakened).
	"embed-crlf-checkout": {kind: "negativos", args: embedArgs("--harness", "claude"), crlfTolerant: true, edit: edits(
		crlf(embedded.BootstrapPath), crlf(embedded.ManifestPath), crlf(embedded.WorkflowPath), crlf(embedded.ClaudeSettingsPath))},
	"embed-gitattributes-removed": {kind: "positivos", args: embedArgs("--harness", "claude"), edit: removeFile(embedded.GitattributesPath)},
	"embed-gitattributes-weakened": {kind: "positivos", args: embedArgs("--harness", "claude"),
		edit: replaceInFile(embedded.GitattributesPath, "/"+embedded.BootstrapPath+" text eol=lf\n", "/"+embedded.BootstrapPath+" -text\n")},
	"local-claude-disable-all-hooks": {kind: "positivos", args: embedArgs("--harness", "claude"), tracked: true,
		edit: writeFile(embedded.ClaudeLocalSettingsPath, localDisableAllHooks)},
	"local-copilot-disable-all-hooks": {kind: "positivos", args: embedArgs("--harness", "copilot"), tracked: true,
		edit: writeFile(embedded.CopilotLocalSettingsPath, localDisableAllHooks)},
	"base-local-disable-all-hooks": {kind: "positivos", edit: writeFile(embedded.ClaudeLocalSettingsPath, localDisableAllHooks),
		againstBase: true, tracked: true},
	"local-policy-tracked": {kind: "positivos", args: embedArgs("--harness", "claude"), tracked: true,
		edit: writeFile(embedded.PolicyLocalPath, "version: 1\nmode: audit\n")},
	"base-local-policy-tracked": {kind: "positivos", edit: writeFile(embedded.PolicyLocalPath, "version: 1\nmode: audit\n"),
		againstBase: true, tracked: true},
	"embed-fresh":       {kind: "negativos", args: embedArgs()},
	"embed-claude-only": {kind: "negativos", args: embedArgs("--harness", "claude")},
	"no-embed":          {kind: "negativos", edit: userRepo},
	"init-policy-only":  {kind: "negativos", args: []string{"init"}, edit: userRepo},
}

// checkItems is what scan reports for TC-CFG-016 in dir, as fixture
// JSON: compared with base, the revision before it, when base is not
// empty, and with every file tracked when tracked is set.
func checkItems(t *testing.T, base, dir string, tracked bool) map[string]string {
	t.Helper()
	var opts embedded.CheckOptions
	if base != "" {
		opts.Base = func(rel string) ([]byte, error) {
			return os.ReadFile(filepath.Join(base, filepath.FromSlash(rel)))
		}
	}
	if tracked {
		opts.Tracked = func(string) bool { return true }
	}
	items, err := embedded.Check(dir, opts)
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
			dir := embedRoot(t)
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
			committed := filepath.Join(cfg016FixtureDir, fx.kind, name) + txtar.Ext
			want, read, format := snapshot(t, dir), readFixtureArchive, formatFixtureArchive
			if fx.items() {
				committed = strings.TrimSuffix(committed, txtar.Ext) + ".json"
				want, read, format = checkItems(t, base, dir, fx.tracked), readFixtureFile, func(m map[string]string) []byte { return []byte(m[""]) }
			}
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(committed, format(want), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := read(t, committed)
			equal := func(a, b string) bool { return a == b }
			if fx.crlfTolerant {
				equal = func(a, b string) bool {
					return string(embedded.NormalizeCRLF([]byte(a))) == string(embedded.NormalizeCRLF([]byte(b)))
				}
			}
			for _, rel := range slices.Sorted(maps.Keys(want)) {
				if !equal(got[rel], want[rel]) {
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

// readFixtureArchive maps every member of the raw fixture archive at
// path to its content, the way snapshot maps a directory.
func readFixtureArchive(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range txtar.Parse(raw).Files {
		files[f.Name] = string(f.Data)
	}
	return files
}

// formatFixtureArchive is the raw fixture archive of files, members in
// path order.
func formatFixtureArchive(files map[string]string) []byte {
	a := &txtar.Archive{}
	for _, rel := range slices.Sorted(maps.Keys(files)) {
		a.Files = append(a.Files, txtar.File{Name: rel, Data: []byte(files[rel])})
	}
	return txtar.Format(a)
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// TestCFG016OtherRuleFixturesHaveNoGuardItems keeps the embed check from
// reporting on the other rules' fixtures: none of them is an embed, so
// a guard item there means the check reads a pattern that is not one.
func TestCFG016OtherRuleFixturesHaveNoGuardItems(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(rulesTree(t), "*.test", "*", "*"))
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

// TestCFG016PolicyFixtureMatchesScan keeps base-policy-weakened.json
// equal to the items scan --since reports when a change sets the policy
// init writes to audit. UPDATE_GOLDEN=1 rewrites it.
func TestCFG016PolicyFixtureMatchesScan(t *testing.T) {
	env, catalog, err := loadRules(scanLimits())
	if err != nil {
		t.Fatal(err)
	}
	load := func(content string) *policy.Effective {
		dir := t.TempDir()
		writeTestFile(t, dir, policy.RepoFile, content)
		e, err := policy.Load(policy.Options{RepoRoot: dir, Surface: policy.SurfaceScan, Env: env, Catalog: catalog, SkipLocal: true, ManagedPolicy: filepath.Join(dir, "no-managed-policy")})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	const head = "version: 1\nmode: audit\nfail-on: high\n"
	items, err := embedded.PolicyWeakened(policy.Weakened(load(string(embedded.DefaultPolicy())), load(head), catalog), []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg016FixtureDir, "positivos", "base-policy-weakened.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := readFixtureFile(t, path)[""]; got != string(raw)+"\n" {
		t.Fatalf("%s differs from scan output; rerun with UPDATE_GOLDEN=1", path)
	}
}
