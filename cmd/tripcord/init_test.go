package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
)

var testSHA256 = strings.Repeat("0", 64)

func embedArgs(extra ...string) []string {
	return append([]string{"init", "--embed", "--version", "0.1.0", "--sha256", "linux-x64=" + testSHA256}, extra...)
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// snapshot maps every regular file under dir to its content.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func writeTestFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInitWithoutEmbedWritesPolicyOnly(t *testing.T) {
	dir := outsideGit(t)
	code, stdout, stderr := runCLI(t, "init", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	files := snapshot(t, dir)
	if len(files) != 1 || files[embedded.PolicyPath] == "" {
		t.Fatalf("files = %v", slices.Sorted(maps.Keys(files)))
	}
	if stdout != "created .tripcord/policy.yaml\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	if code, _, _ := runCLI(t, "init", "--harness", "claude", dir); code != int(exitcode.Config) {
		t.Fatalf("--harness without --embed: exit %d, want 3", code)
	}
}

func TestInitEmbedRequiresPin(t *testing.T) {
	for name, args := range map[string][]string{
		"no version":       {"init", "--embed", "--sha256", "linux-x64=" + testSHA256},
		"no sha256":        {"init", "--embed", "--version", "0.1.0"},
		"neither":          {"init", "--embed"},
		"short sha256":     {"init", "--embed", "--version", "0.1.0", "--sha256", "linux-x64=abc"},
		"unknown platform": {"init", "--embed", "--version", "0.1.0", "--sha256", "plan9-x64=" + testSHA256},
		"bad version":      {"init", "--embed", "--version", "latest", "--sha256", "linux-x64=" + testSHA256},
		"shell in version": {"init", "--embed", "--version", "0.1.0';id;'", "--sha256", "linux-x64=" + testSHA256},
		"duplicate sha256": {"init", "--embed", "--version", "0.1.0", "--sha256", "linux-x64=" + testSHA256, "--sha256", "linux-x64=" + testSHA256},
		"unknown harness":  {"init", "--embed", "--version", "0.1.0", "--sha256", "linux-x64=" + testSHA256, "--harness", "gemini"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := outsideGit(t)
			code, _, stderr := runCLI(t, append(args, dir)...)
			if code != int(exitcode.Config) {
				t.Fatalf("exit %d, want 3: %s", code, stderr)
			}
			if files := snapshot(t, dir); len(files) != 0 {
				t.Fatalf("wrote %v", slices.Sorted(maps.Keys(files)))
			}
		})
	}
}

func TestInitEmbedIdempotent(t *testing.T) {
	dir := outsideGit(t)
	if code, _, stderr := runCLI(t, embedArgs(dir)...); code != 0 {
		t.Fatalf("first run: exit %d: %s", code, stderr)
	}
	first := snapshot(t, dir)
	code, stdout, stderr := runCLI(t, embedArgs(dir)...)
	if code != 0 {
		t.Fatalf("second run: exit %d: %s", code, stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if !strings.HasPrefix(line, "unchanged ") {
			t.Errorf("second run: %q", line)
		}
	}
	second := snapshot(t, dir)
	if len(first) != len(second) {
		t.Fatalf("file count changed: %d then %d", len(first), len(second))
	}
	for path, content := range first {
		if second[path] != content {
			t.Errorf("%s changed on the second run", path)
		}
	}
	want := []string{
		embedded.AgentsPath, embedded.ClaudeSettingsPath, embedded.CursorEnvironmentPath, embedded.CursorHooksPath,
		embedded.DevinBlueprintPath, embedded.CopilotHooksPath, embedded.CopilotSetupStepsPath, embedded.WorkflowPath,
		embedded.BootstrapPath, embedded.ManifestPath, embedded.PolicyPath, embedded.GitattributesPath, embedded.GitignorePath,
	}
	if got := slices.Sorted(maps.Keys(first)); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("files = %v", got)
	}
}

// TestInitEmbedScanHasNoFindings is the end-to-end check that Tripcord's
// own wiring does not trip its rules: a freshly embedded repository, for
// every harness selection, scans clean.
func TestInitEmbedScanHasNoFindings(t *testing.T) {
	selections := [][]string{nil}
	for _, h := range embedded.Harnesses {
		selections = append(selections, []string{"--harness", string(h)})
	}
	for _, sel := range selections {
		t.Run(strings.Join(append([]string{"all"}, sel...), " "), func(t *testing.T) {
			dir := outsideGit(t)
			if code, _, stderr := runCLI(t, embedArgs(append(sel, dir)...)...); code != 0 {
				t.Fatalf("init: exit %d: %s", code, stderr)
			}
			code, stdout, stderr := runCLI(t, "scan", "--format", "json", "--fail-on", "low", dir)
			if code != 0 || stdout != "" {
				t.Fatalf("scan: exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
		})
	}
}

// TestInitWiringInvokesTripcordHook pins the hook command every
// harness's wiring runs: bash .tripcord/bootstrap.sh hook --harness <h>
// --event pre-tool, through the harness's project-directory variable
// where it has one, never a tripcord found on PATH, and failing closed
// where the harness has a field for it. The literals are written out so
// a change to embedded.HookArgs or the wiring fails here.
func TestInitWiringInvokesTripcordHook(t *testing.T) {
	dir := outsideGit(t)
	if code, _, stderr := runCLI(t, embedArgs(dir)...); code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	files := snapshot(t, dir)
	var claude struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type      string   `json:"type"`
				Command   string   `json:"command"`
				Args      []string `json:"args"`
				OnFailure string   `json:"onFailure"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	mustJSON(t, files[embedded.ClaudeSettingsPath], &claude)
	pre := claude.Hooks["PreToolUse"]
	if len(pre) != 1 || pre[0].Matcher != "*" || len(pre[0].Hooks) != 1 {
		t.Fatalf("claude PreToolUse = %+v", pre)
	}
	h := pre[0].Hooks[0]
	if h.Type != "command" || h.Command != `bash "${CLAUDE_PROJECT_DIR}/.tripcord/bootstrap.sh" hook --harness claude --event pre-tool` || h.Args != nil || h.OnFailure != "block" {
		t.Fatalf("claude pre-tool hook = %+v", h)
	}
	start := claude.Hooks["SessionStart"]
	if len(start) != 1 || start[0].Matcher != "startup|resume" || len(start[0].Hooks) != 1 ||
		start[0].Hooks[0].Command != `bash "${CLAUDE_PROJECT_DIR}/.tripcord/bootstrap.sh" session-start --harness claude` {
		t.Fatalf("claude SessionStart = %+v", start)
	}

	var cursor struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Command    string `json:"command"`
			FailClosed bool   `json:"failClosed"`
		} `json:"hooks"`
	}
	mustJSON(t, files[embedded.CursorHooksPath], &cursor)
	if c := cursor.Hooks["preToolUse"]; cursor.Version != 1 || len(c) != 1 || c[0].Command != `bash "${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh" hook --harness cursor --event pre-tool` || !c[0].FailClosed {
		t.Fatalf("cursor preToolUse = %+v", c)
	}
	if c := cursor.Hooks["sessionStart"]; len(c) != 1 || c[0].Command != `bash "${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh" session-start --harness cursor` {
		t.Fatalf("cursor sessionStart = %+v", c)
	}

	var copilot struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Type       string `json:"type"`
			Bash       string `json:"bash"`
			Cwd        string `json:"cwd"`
			TimeoutSec int    `json:"timeoutSec"`
		} `json:"hooks"`
	}
	mustJSON(t, files[embedded.CopilotHooksPath], &copilot)
	if c := copilot.Hooks["preToolUse"]; copilot.Version != 1 || len(c) != 1 || c[0].Type != "command" ||
		c[0].Bash != "bash .tripcord/bootstrap.sh hook --harness copilot --event pre-tool" || c[0].Cwd != "." || c[0].TimeoutSec != 60 {
		t.Fatalf("copilot preToolUse = %+v", c)
	}
	if c := copilot.Hooks["sessionStart"]; len(c) != 1 || c[0].Bash != "bash .tripcord/bootstrap.sh session-start --harness copilot" || c[0].Cwd != "." || c[0].TimeoutSec != 300 {
		t.Fatalf("copilot sessionStart = %+v", c)
	}
	for _, h := range embedded.HookHarnesses {
		line := embedded.HookCommandLine(h)
		if !strings.HasPrefix(line, "bash ") || !strings.Contains(line, embedded.BootstrapPath) || !strings.HasSuffix(line, " hook --harness "+string(h)+" --event pre-tool") {
			t.Errorf("HookCommandLine(%s) = %q", h, line)
		}
	}
}

// TestReleaseGateHookSubcommand is the release gate for embed mode: the
// wiring init writes runs bootstrap.sh, which execs the verified binary
// as `tripcord hook <HookArgs>`, so a build without that subcommand must
// not ship. It runs only with TRIPCORD_RELEASE_GATE=1 (make
// release-gate) and then fails, never skips, if hook mode is missing.
func TestReleaseGateHookSubcommand(t *testing.T) {
	for _, h := range embedded.HookHarnesses {
		if line, args := embedded.HookCommandLine(h), strings.Join(embedded.HookArgs(h), " "); !strings.HasSuffix(line, " "+args) {
			t.Fatalf("the %s wiring %q does not pass %q through bootstrap.sh", h, line, args)
		}
	}
	if os.Getenv("TRIPCORD_RELEASE_GATE") != "1" {
		t.Log("release gate not requested; set TRIPCORD_RELEASE_GATE=1 to run it")
		return
	}
	for _, h := range embedded.HookHarnesses {
		code, _, stderr := runCLI(t, embedded.HookArgs(h)...)
		if code == int(exitcode.Config) && strings.Contains(stderr, "unknown command") {
			t.Errorf("release gate: the %s wiring runs tripcord %q through bootstrap.sh, but this build has no hook subcommand", h, strings.Join(embedded.HookArgs(h), " "))
		}
	}
}

func TestInitHarnessLimitsWiring(t *testing.T) {
	dir := outsideGit(t)
	if code, _, stderr := runCLI(t, embedArgs("--harness", "claude", dir)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	files := snapshot(t, dir)
	got := slices.Sorted(maps.Keys(files))
	want := []string{".claude/settings.json", ".gitattributes", ".github/workflows/tripcord.yml", ".gitignore", ".tripcord/bootstrap.sh", ".tripcord/embed.json", ".tripcord/policy.yaml"}
	if !slices.Equal(got, want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
	var m embedded.Manifest
	mustJSON(t, files[embedded.ManifestPath], &m)
	if !slices.Equal(m.Harnesses, []string{"claude"}) {
		t.Fatalf("manifest harnesses = %v", m.Harnesses)
	}
	// A later run for another harness adds it to the manifest.
	if code, _, stderr := runCLI(t, embedArgs("--harness", "cursor", dir)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	mustJSON(t, snapshot(t, dir)[embedded.ManifestPath], &m)
	if !slices.Equal(m.Harnesses, []string{"claude", "cursor"}) {
		t.Fatalf("manifest harnesses = %v", m.Harnesses)
	}
}

func TestInitMergesExistingFiles(t *testing.T) {
	dir := outsideGit(t)
	claude := "{\n  \"model\": \"opus\",\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Bash\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"./scripts/lint.sh\"\n          }\n        ]\n      }\n    ]\n  },\n  \"permissions\": {\n    \"deny\": [\n      \"Read(.env)\"\n    ]\n  }\n}\n"
	writeTestFile(t, dir, embedded.ClaudeSettingsPath, claude)
	writeTestFile(t, dir, "scripts/lint.sh", "#!/bin/sh\nexit 0\n")
	writeTestFile(t, dir, embedded.CursorHooksPath, "{\n\t\"version\": 1,\n\t\"hooks\": {\n\t\t\"stop\": [\n\t\t\t{\n\t\t\t\t\"command\": \"./scripts/lint.sh\"\n\t\t\t}\n\t\t]\n\t}\n}\n")
	writeTestFile(t, dir, embedded.CursorEnvironmentPath, "{\n  \"snapshot\": \"snap-1\",\n  \"start\": \"make dev\"\n}\n")
	writeTestFile(t, dir, embedded.AgentsPath, "# Agents\n\nRun `make test` before you push.\n")
	writeTestFile(t, dir, embedded.DevinBlueprintPath, "initialize: make deps\nmaintenance:\n  - make tidy\n")
	writeTestFile(t, dir, embedded.CopilotSetupStepsPath, "name: Copilot Setup Steps\non: workflow_dispatch\njobs:\n  copilot-setup-steps:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - run: make deps\n")
	writeTestFile(t, dir, embedded.PolicyPath, "version: 1\nmode: warn\n")
	if code, _, stderr := runCLI(t, embedArgs(dir)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	files := snapshot(t, dir)
	if files[embedded.PolicyPath] != "version: 1\nmode: warn\n" {
		t.Errorf("policy was rewritten: %q", files[embedded.PolicyPath])
	}
	got := files[embedded.ClaudeSettingsPath]
	for _, want := range []string{`"model": "opus"`, `"./scripts/lint.sh"`, `"Read(.env)"`, `.tripcord/bootstrap.sh\" hook`, `"SessionStart"`} {
		if !strings.Contains(got, want) {
			t.Errorf("claude settings lost %s:\n%s", want, got)
		}
	}
	if strings.Index(got, `"model"`) > strings.Index(got, `"hooks"`) || strings.Index(got, `"hooks"`) > strings.Index(got, `"permissions"`) {
		t.Errorf("claude settings key order changed:\n%s", got)
	}
	if strings.Index(got, `"./scripts/lint.sh"`) > strings.Index(got, `bootstrap.sh\" hook`) {
		t.Errorf("existing PreToolUse entry was not kept first:\n%s", got)
	}
	cursor := files[embedded.CursorHooksPath]
	if !strings.Contains(cursor, "\t\t\"stop\": [") || !strings.Contains(cursor, "bootstrap.sh\\\" hook --harness cursor") {
		t.Errorf("cursor hooks not merged with tab indentation:\n%s", cursor)
	}
	if env := files[embedded.CursorEnvironmentPath]; env != "{\n  \"snapshot\": \"snap-1\",\n  \"start\": \"make dev\",\n  \"install\": \"bash .tripcord/bootstrap.sh install\"\n}\n" {
		t.Errorf("environment.json = %q", env)
	}
	if agents := files[embedded.AgentsPath]; !strings.HasPrefix(agents, "# Agents\n\nRun `make test` before you push.\n\n<!-- tripcord:begin -->") {
		t.Errorf("AGENTS.md = %q", agents)
	}
	if bp := files[embedded.DevinBlueprintPath]; !strings.Contains(bp, "  - make tidy\n  - name: tripcord\n    run: bash .tripcord/bootstrap.sh install\n") || !strings.HasPrefix(bp, "initialize: make deps\n") {
		t.Errorf("blueprint = %q", bp)
	}
	if steps := files[embedded.CopilotSetupStepsPath]; !strings.Contains(steps, "      - run: make deps\n      - name: Tripcord bootstrap\n        run: bash .tripcord/bootstrap.sh install\n") {
		t.Errorf("copilot-setup-steps = %q", steps)
	}
	before := snapshot(t, dir)
	code, stdout, stderr := runCLI(t, embedArgs(dir)...)
	if code != 0 || strings.Contains(stdout, "updated") || strings.Contains(stdout, "created") {
		t.Fatalf("second run: exit %d\n%s%s", code, stdout, stderr)
	}
	after := snapshot(t, dir)
	for path, content := range before {
		if after[path] != content {
			t.Errorf("%s changed on the second run", path)
		}
	}
	if code, stdout, stderr := runCLI(t, "scan", "--format", "json", dir); code != 0 || stdout != "" {
		t.Fatalf("scan: exit %d\n%s%s", code, stdout, stderr)
	}
}

func TestInitUnmergeableFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct{ path, content string }{
		"invalid JSON":        {embedded.ClaudeSettingsPath, "{\"hooks\": \n"},
		"hooks not an object": {embedded.ClaudeSettingsPath, "{\n  \"hooks\": []\n}\n"},
		"duplicate key":       {embedded.ClaudeSettingsPath, "{\n  \"hooks\": {},\n  \"hooks\": {}\n}\n"},
		"cursor version 2":    {embedded.CursorHooksPath, "{\n  \"version\": 2,\n  \"hooks\": {}\n}\n"},
		"invalid YAML":        {embedded.DevinBlueprintPath, "maintenance: [\n"},
		"no setup job":        {embedded.CopilotSetupStepsPath, "name: x\non: workflow_dispatch\njobs: {}\n"},
		"open AGENTS marker":  {embedded.AgentsPath, "# Agents\n<!-- tripcord:begin -->\n"},
		"install not string":  {embedded.CursorEnvironmentPath, "{\n  \"install\": 1\n}\n"},
		"jsonc comment":       {embedded.CursorHooksPath, "{\n  // mine\n  \"version\": 1,\n  \"hooks\": {}\n}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, force := range []bool{false, true} {
				dir := outsideGit(t)
				writeTestFile(t, dir, tc.path, tc.content)
				before := snapshot(t, dir)
				args := embedArgs()
				if force {
					args = append(args, "--force")
				}
				code, _, stderr := runCLI(t, append(args, dir)...)
				if code != int(exitcode.Config) || !strings.Contains(stderr, tc.path) || !strings.Contains(stderr, "nothing was written") {
					t.Fatalf("force=%v: exit %d, want 3 naming %s: %s", force, code, tc.path, stderr)
				}
				if after := snapshot(t, dir); !maps.Equal(before, after) {
					t.Fatalf("force=%v: files changed: %v", force, slices.Sorted(maps.Keys(after)))
				}
			}
		})
	}
}

func TestInitConflictsNeedForce(t *testing.T) {
	for name, tc := range map[string]struct{ path, content, keep string }{
		"reformat":           {embedded.ClaudeSettingsPath, "{\"model\": \"opus\"}\n", `"model": "opus"`},
		"install set":        {embedded.CursorEnvironmentPath, "{\n  \"install\": \"npm ci\"\n}\n", "bash .tripcord/bootstrap.sh install && npm ci"},
		"edited hook":        {embedded.CopilotHooksPath, "{\n  \"version\": 1,\n  \"hooks\": {\n    \"preToolUse\": [\n      {\n        \"type\": \"command\",\n        \"bash\": \"tripcord hook --harness copilot --event pre-tool || true\"\n      }\n    ]\n  }\n}\n", "--event pre-tool\""},
		"disableAllHooks":    {embedded.ClaudeSettingsPath, "{\n  \"disableAllHooks\": true\n}\n", `"disableAllHooks": true`},
		"own bootstrap":      {embedded.BootstrapPath, "#!/bin/sh\nexit 0\n", "TRIPCORD_VERSION='0.1.0'"},
		"workflow differs":   {embedded.WorkflowPath, "name: mine\n", embedded.ReusableWorkflow},
		"agents note edits":  {embedded.AgentsPath, "<!-- tripcord:begin -->\nold\n<!-- tripcord:end -->\nmine\n", "## Tripcord"},
		"maintenance string": {embedded.DevinBlueprintPath, "maintenance: make tidy\n", "  - make tidy\n  - name: tripcord\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := outsideGit(t)
			writeTestFile(t, dir, tc.path, tc.content)
			before := snapshot(t, dir)
			code, _, stderr := runCLI(t, embedArgs(dir)...)
			if code != int(exitcode.Config) || !strings.Contains(stderr, "--force") {
				t.Fatalf("exit %d, want 3 suggesting --force: %s", code, stderr)
			}
			if !maps.Equal(before, snapshot(t, dir)) {
				t.Fatal("files changed without --force")
			}
			if code, _, stderr := runCLI(t, embedArgs("--force", dir)...); code != 0 {
				t.Fatalf("--force: exit %d: %s", code, stderr)
			}
			if got := snapshot(t, dir)[tc.path]; !strings.Contains(got, tc.keep) {
				t.Fatalf("--force result lacks %q:\n%s", tc.keep, got)
			}
			forced := snapshot(t, dir)
			if code, _, stderr := runCLI(t, embedArgs("--force", dir)...); code != 0 || !maps.Equal(forced, snapshot(t, dir)) {
				t.Fatalf("second --force run changed files: exit %d: %s", code, stderr)
			}
		})
	}
}

func TestInitRefusesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	for name, setup := range map[string]func(t *testing.T, dir, outside string){
		"parent leaves the tree": func(t *testing.T, dir, outside string) {
			mustSymlink(t, outside, filepath.Join(dir, ".claude"))
		},
		"file leaves the tree": func(t *testing.T, dir, outside string) {
			writeTestFile(t, outside, "settings.json", "{}\n")
			writeTestFile(t, dir, ".claude/.keep", "")
			mustSymlink(t, filepath.Join(outside, "settings.json"), filepath.Join(dir, ".claude", "settings.json"))
		},
		"deep parent leaves the tree": func(t *testing.T, dir, outside string) {
			mustSymlink(t, outside, filepath.Join(dir, ".github"))
		},
		"parent stays in the tree": func(t *testing.T, dir, outside string) {
			writeTestFile(t, dir, "elsewhere/.keep", "")
			mustSymlink(t, "elsewhere", filepath.Join(dir, ".tripcord"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, outside := outsideGit(t), outsideGit(t)
			setup(t, dir, outside)
			before, beforeOutside := snapshot(t, dir), snapshot(t, outside)
			code, _, stderr := runCLI(t, embedArgs(dir)...)
			if code != int(exitcode.Config) || !strings.Contains(stderr, "symlink") {
				t.Fatalf("exit %d, want 3 naming the symlink: %s", code, stderr)
			}
			if !maps.Equal(before, snapshot(t, dir)) || !maps.Equal(beforeOutside, snapshot(t, outside)) {
				t.Fatal("files changed")
			}
		})
	}
}

func TestInitDryRun(t *testing.T) {
	dir := outsideGit(t)
	writeTestFile(t, dir, embedded.CursorEnvironmentPath, "{\n  \"start\": \"make dev\"\n}\n")
	code, stdout, stderr := runCLI(t, embedArgs("--dry-run", dir)...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if files := snapshot(t, dir); len(files) != 1 {
		t.Fatalf("dry run wrote %v", slices.Sorted(maps.Keys(files)))
	}
	for _, want := range []string{
		"--- /dev/null\n+++ b/.tripcord/bootstrap.sh\n@@ -0,0 +1,",
		"--- a/.cursor/environment.json\n+++ b/.cursor/environment.json\n@@ -1,3 +1,4 @@\n {\n-  \"start\": \"make dev\"\n+  \"start\": \"make dev\",\n+  \"install\": \"bash .tripcord/bootstrap.sh install\"\n }\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("diff lacks %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "nothing written") {
		t.Errorf("stderr = %q", stderr)
	}
	if code, _, _ := runCLI(t, embedArgs(dir)...); code != 0 {
		t.Fatal("init after dry run failed")
	}
	if code, stdout, _ := runCLI(t, embedArgs("--dry-run", dir)...); code != 0 || stdout != "" {
		t.Fatalf("dry run on an embedded repo: exit %d, diff:\n%s", code, stdout)
	}
}

func TestInitPathInsideRepository(t *testing.T) {
	dir := outsideGit(t)
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "init", sub); code != int(exitcode.Config) || !strings.Contains(stderr, "repository root") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if code, _, stderr := runCLI(t, "init", dir); code != 0 {
		t.Fatalf("repository root: exit %d: %s", code, stderr)
	}
}

// TestScanReportsRemovedGuard checks TC-CFG-016 end to end against what
// init writes, including that --harness on scan and the harnesses init
// selected both limit which wiring is required.
func TestScanReportsRemovedGuard(t *testing.T) {
	dir := outsideGit(t)
	if code, _, stderr := runCLI(t, embedArgs("--harness", "claude,copilot", dir)...); code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(dir, filepath.FromSlash(embedded.CopilotHooksPath))); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runCLI(t, "scan", "--format", "json", dir)
	if code != int(exitcode.Findings) {
		t.Fatalf("scan: exit %d\n%s", code, stdout)
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		var f model.Finding
		mustJSON(t, line, &f)
		if f.Rule != "TC-CFG-016" || f.Title != "Tripcord embed is missing part of its guard" || !strings.Contains(f.Fix, "tripcord init --embed --force") || strings.Contains(f.Fix, "disableAllHooks") {
			t.Fatalf("finding = %s", line)
		}
		paths = append(paths, f.Location.Path)
	}
	if !slices.Equal(paths, []string{embedded.CopilotHooksPath, embedded.CopilotHooksPath}) {
		t.Fatalf("finding paths = %v", paths)
	}
	if code, stdout, _ := runCLI(t, "scan", "--format", "json", "--harness", "claude", dir); code != 0 || stdout != "" {
		t.Fatalf("scan --harness claude: exit %d\n%s", code, stdout)
	}
}

func mustJSON(t *testing.T, raw string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		t.Fatalf("%v:\n%s", err, raw)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
