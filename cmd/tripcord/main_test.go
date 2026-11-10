package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/fpkey"
)

// noCINote is a valid fingerprint key, used only so a test about scan
// output or flag handling does not also need to anticipate the "CI
// detected" stderr note documented in docs/fingerprint.md's
// "Fail-closed vs s1 fallback" section. TestMain pins the whole package
// to CI mode with no key file, and since this round's fix to
// fpkey.Load now reports that combination instead of silently using s1
// (the researcher review's bug 3), any test that runs a scan without
// its own key source sees that note on stderr. TestScanPrintsCINoteOnce
// in fingerprint_key_test.go is the dedicated test of the note itself.
// Setting an env var mutates process state, so a caller must set it
// before calling t.Parallel(), the same rule setKeyEnv documents.
const noCINote = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

func TestVersion(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		{"version"},
		{"--version"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if got, want := stdout.String(), version+"\n"; got != want {
				t.Fatalf("stdout = %q, want %q", got, want)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		nil,
		{"help"},
		{"-h"},
		{"--help"},
	}
	for _, args := range cases {
		name := "no args"
		if len(args) > 0 {
			name = strings.Join(args, " ")
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if got := stdout.String(); got != usage {
				t.Fatalf("stdout = %q, want usage text", got)
			}
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestVersionWriteError(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := run([]string{"version"}, failWriter{}, &stderr); code != int(exitcode.Internal) {
		t.Fatalf("exit code = %d, want %d (internal or I/O error)", code, exitcode.Internal)
	}
}

func TestScanHelpWriteError(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := run([]string{"scan", "--help"}, failWriter{}, &stderr); code != int(exitcode.Internal) {
		t.Fatalf("exit code = %d, want %d (internal or I/O error)", code, exitcode.Internal)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run([]string{"unknown"}, &stdout, &stderr)
	if code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, want %d (configuration error)", code, exitcode.Config)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if got, want := stderr.String(), "tripcord: unknown command \"unknown\"\n\n"+usage; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestScanTextGolden(t *testing.T) {
	t.Setenv(fpkey.EnvVar, noCINote)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	assertGolden(t, "scan-text.golden", stdout.String())
}

func TestScanClaudeFixtureJSON(t *testing.T) {
	t.Setenv(fpkey.EnvVar, noCINote)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"tripcord hook"}]}]}}`
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--format", "json", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("json output = %q, want no findings", stdout.String())
	}
}

func TestScanReportsIncompleteDiscovery(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "evil\x1b[2J", ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"hooks":{},"Hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "md", "sarif", "text"} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run([]string{"scan", "--format", format, root}, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			msg := stderr.String()
			report := stdout.String()
			if !strings.Contains(msg, "case-variant keys") || !strings.Contains(msg, "scan is incomplete") || strings.Contains(msg, "\x1b") || strings.Contains(msg, root) {
				t.Fatalf("stderr = %q", msg)
			}
			if strings.Contains(report, "\x1b") || strings.Contains(report, root) || !strings.Contains(report, "case-variant keys") {
				t.Fatalf("report = %s", report)
			}
			switch format {
			case "json":
				if !strings.Contains(report, `"schema":"tripcord.diagnostic/v1"`) || !strings.Contains(report, `"incomplete":true`) {
					t.Fatalf("json = %s", report)
				}
			case "md":
				if !strings.Contains(report, "The scan is incomplete.") {
					t.Fatalf("markdown = %s", report)
				}
			case "sarif":
				if !strings.Contains(report, `"executionSuccessful": false`) || !strings.Contains(report, `"toolExecutionNotifications"`) {
					t.Fatalf("sarif = %s", report)
				}
			case "text":
				if !strings.Contains(report, "scan incomplete") {
					t.Fatalf("text = %s", report)
				}
			}
		})
	}
}

func TestScanSecretsAndAllDoNotScan(t *testing.T) {
	t.Parallel()
	const want = "tripcord scan: secret scanning lands in v1; v0 supports --config only\n"
	for _, flagName := range []string{"--secrets", "--all"} {
		t.Run(flagName, func(t *testing.T) {
			t.Parallel()
			outputPath := filepath.Join(t.TempDir(), "findings.txt")
			var stdout, stderr bytes.Buffer
			// A missing repository would fail discovery if scanning started.
			args := []string{"scan", flagName, "--output", outputPath, filepath.Join(t.TempDir(), "missing-repo")}
			if code := run(args, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stdout.Len() != 0 || stderr.String() != want {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
			if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Fatalf("scan wrote %s: %v", outputPath, err)
			}
		})
	}
}

func TestScanHelpListsJSONL(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--help"}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "text, json, jsonl, sarif, md, or gha") {
		t.Fatalf("help = %q", stdout.String())
	}
}

func TestScanHelpMarksSecretFlagsAsV1(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run([]string{"scan", arg}, &stdout, &stderr); code != int(exitcode.OK) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			help := stdout.String()
			for _, flagName := range []string{"-secrets", "-all"} {
				if !strings.Contains(help, flagName) || !strings.Contains(help, "(v1) not available") {
					t.Fatalf("help = %q", help)
				}
			}
			if !strings.Contains(help, "git root") || !strings.Contains(help, "https://github.com/vgmartinez/tripcord/issues/59") {
				t.Fatalf("help = %q", help)
			}
		})
	}
}

func TestScanFlagErrors(t *testing.T) {
	t.Parallel()
	dir := outsideGit(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"format", []string{"scan", "--format", "xml", dir}, "output format"},
		{"config and secrets", []string{"scan", "--config", "--secrets", dir}, "mutually exclusive"},
		{"config and all", []string{"scan", "--config", "--all", dir}, "mutually exclusive"},
		{"secrets and all", []string{"scan", "--secrets", "--all", dir}, "mutually exclusive"},
		{"scope", []string{"scan", "--scope", "workspace", dir}, "--scope"},
		{"harness", []string{"scan", "--harness", "vscode", dir}, "not a supported harness"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestScanFlagsAfterPath(t *testing.T) {
	t.Setenv(fpkey.EnvVar, noCINote)
	dir := outsideGit(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir, "--format", "text"}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), "0 finding(s)") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestScanScope(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	setHome(t, home)
	t.Setenv(fpkey.EnvVar, noCINote)
	// This test asserts a silent user-scope scan. A runner may export
	// XDG_CONFIG_HOME outside the temporary home, which is an
	// informational note on stderr (it does not fail the scan).
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--scope", "user", "--format", "text", root}, &stdout, &stderr); code != int(exitcode.OK) || stderr.Len() != 0 {
		t.Fatalf("user scope exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", root, "--scope", "repo"}, &stdout, &stderr); code != int(exitcode.Config) || !strings.Contains(stderr.String(), "incomplete") {
		t.Fatalf("repo scope exit %d stderr %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--scope", "repo", "--harness", "generic", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("generic scope exit %d stderr %q", code, stderr.String())
	}
}

// (b) --output, --policy, --org-policy, and the scan PATH argument can
// all surface an error that embeds the exact path a caller supplied;
// when that path sits under the running user's home directory, the
// home directory itself must never reach stderr, the same way every
// other diagnostic in this codebase redacts it (see pathx.TildeHome).
func TestScanErrorsRedactHomeDirectory(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	repo := outsideGit(t)

	cases := []struct {
		name string
		args func() []string
	}{
		{
			name: "output path",
			args: func() []string {
				// The parent directory does not exist, so creating the
				// output file fails with an error that embeds its path.
				return []string{"scan", "--output", filepath.Join(home, "missing-output-dir", "out.json"), repo}
			},
		},
		{
			name: "policy path",
			args: func() []string {
				return []string{"scan", "--policy", filepath.Join(home, "missing-policy.yaml"), repo}
			},
		},
		{
			name: "org-policy path",
			args: func() []string {
				return []string{"scan", "--org-policy", filepath.Join(home, "missing-org-policy.yaml"), repo}
			},
		},
		{
			name: "scan path",
			args: func() []string {
				return []string{"scan", filepath.Join(home, "missing-repo")}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args(), &stdout, &stderr)
			if code != int(exitcode.Config) && code != int(exitcode.Internal) {
				t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
			msg := stderr.String()
			if msg == "" {
				t.Fatal("want a non-empty error on stderr")
			}
			if strings.Contains(msg, home) {
				t.Fatalf("stderr leaks the home directory: %q", msg)
			}
			if !strings.Contains(msg, "~") {
				t.Fatalf("stderr = %q, want the home directory rewritten to ~", msg)
			}
		})
	}
}

// TestHomeOverrideOutsideHomeFailsScan checks that CODEX_HOME and
// COPILOT_HOME, like Claude's CLAUDE_CONFIG_DIR, make `tripcord scan`
// exit non-zero when they point outside the home directory, even though
// the redirected configuration is still read and reported.
func TestHomeOverrideOutsideHomeFailsScan(t *testing.T) {
	cases := []struct {
		harness string
		envName string
		setup   func(dir string)
	}{
		{"codex", "CODEX_HOME", func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"copilot", "COPILOT_HOME", func(dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "hooks", "a.json"), []byte(`{"version":1,"hooks":{"sessionStart":[{"bash":"x"}]}}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"gemini", "GEMINI_CLI_HOME", func(dir string) {
			if err := os.MkdirAll(filepath.Join(dir, ".gemini"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ".gemini", "settings.json"), []byte(`{"mcpServers":{"a":{"command":"x"}}}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"opencode", "OPENCODE_CONFIG_DIR", func(dir string) {
			if err := os.WriteFile(filepath.Join(dir, "opencode.json"), []byte(`{"plugin":["p"]}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.harness, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
				t.Fatal(err)
			}
			home := t.TempDir()
			outside := t.TempDir()
			tc.setup(outside)
			setHome(t, home)
			t.Setenv(tc.envName, outside)

			var stdout, stderr bytes.Buffer
			code := run([]string{"scan", "--scope", "user", "--harness", tc.harness, "--format", "text", root}, &stdout, &stderr)
			if code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "outside the home directory") || !strings.Contains(stderr.String(), "incomplete") {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

// TestXDGOutsideHomeDoesNotFailScan is the user-scope repro: with no
// OpenCode configuration installed, XDG_CONFIG_HOME or XDG_DATA_HOME
// pointing outside home must not make `tripcord scan --scope user` exit
// non-zero. The override is still reported, as an informational note.
func TestXDGOutsideHomeDoesNotFailScan(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME"} {
		t.Run(name, func(t *testing.T) {
			setHome(t, home)
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("XDG_DATA_HOME", "")
			t.Setenv(name, t.TempDir())
			var stdout, stderr bytes.Buffer
			code := run([]string{"scan", "--scope", "user", "--format", "text", root}, &stdout, &stderr)
			if code != int(exitcode.OK) {
				t.Fatalf("exit %d stderr %q", code, stderr.String())
			}
			msg := stderr.String()
			if !strings.Contains(msg, name+" is outside the home directory") || strings.Contains(msg, "incomplete") {
				t.Fatalf("stderr = %q", msg)
			}
		})
	}
}

// TestRelativeXDGUsesDefault checks the freedesktop rule: a relative
// XDG base directory is invalid and ignored, and the default under home
// is scanned, with no diagnostic.
func TestRelativeXDGUsesDefault(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("XDG_CONFIG_HOME", "rel")
	t.Setenv("XDG_DATA_HOME", "rel")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--scope", "user", "--format", "text", root}, &stdout, &stderr)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d stderr %q", code, stderr.String())
	}
	msg := stderr.String()
	if strings.Contains(msg, "not an absolute path") || strings.Contains(msg, "incomplete") || strings.Contains(msg, "XDG_") {
		t.Fatalf("stderr = %q", msg)
	}
}

func TestLegacyNoteDoesNotFailScan(t *testing.T) {
	legacy := t.TempDir()
	restore := claude.SetLegacyManagedDirForTest(legacy)
	t.Cleanup(restore)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	setHome(t, home)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--scope", "managed", "--format", "json", root}, &stdout, &stderr)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d stderr %q stdout %q", code, stderr.String(), stdout.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "not scanned") || strings.Contains(msg, "incomplete") || strings.Contains(msg, legacy) {
		t.Fatalf("stderr = %q", msg)
	}
	if !strings.Contains(stdout.String(), `"schema":"tripcord.diagnostic/v1"`) ||
		!strings.Contains(stdout.String(), `"incomplete":false`) ||
		!strings.Contains(stdout.String(), `"level":"warning"`) ||
		strings.Contains(stdout.String(), `"incomplete":true`) {
		t.Fatalf("report = %s", stdout.String())
	}
}

func TestPartitionDiagnostics(t *testing.T) {
	t.Parallel()
	blocking, notes := partitionDiagnostics([]adapters.Diagnostic{
		{Message: "note", Informational: true},
		{Message: "bad"},
	})
	if len(notes) != 1 || notes[0].Message != "note" || len(blocking) != 1 || blocking[0].Message != "bad" {
		t.Fatalf("blocking %+v notes %+v", blocking, notes)
	}
}

// TestScanDedupesEscapingSymlinkAcrossAdapters is Follow-up 6
// end-to-end: Claude's plugin-root discovery and Codex's own .codex
// matcher both flag an escaping symlink at .codex/skills (Claude cannot
// know a plugin root's name without following the symlink, which it
// does not do), but the scan must report it once, naming the adapter
// that actually owns the location, not twice.
func TestScanDedupesEscapingSymlinkAcrossAdapters(t *testing.T) {
	root := outsideGit(t)
	if err := os.MkdirAll(filepath.Join(root, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".codex", "skills")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--scope", "repo", root}, &stdout, &stderr)
	if code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	msg := stderr.String()
	if n := strings.Count(msg, "symlink resolves outside"); n != 1 {
		t.Fatalf("stderr contains %d escaping-symlink reports, want 1: %q", n, msg)
	}
	if !strings.Contains(msg, "codex: .codex/skills") {
		t.Fatalf("stderr = %q, want the kept report to name codex, the actual owner of .codex/skills", msg)
	}
}

func TestScanEscapingSymlinkReportedOnceByNewOwners(t *testing.T) {
	cases := map[string]struct{ dir, owner string }{
		"opencode agents":  {".opencode/agents", "opencode: .opencode/agents"},
		"windsurf rules":   {".windsurf/rules", "windsurf: .windsurf/rules"},
		"gemini dir":       {".gemini", "gemini: .gemini"},
		"devcontainer dir": {".devcontainer", "devcontainer: .devcontainer"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := outsideGit(t)
			link := filepath.Join(root, filepath.FromSlash(tc.dir))
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{"scan", "--scope", "repo", root}, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			msg := stderr.String()
			if n := strings.Count(msg, "symlink resolves outside"); n != 1 || !strings.Contains(msg, tc.owner) {
				t.Fatalf("stderr = %q, want one report by %q", msg, tc.owner)
			}
		})
	}
}

func TestScanGeminiOpenCodeWindsurfDevcontainer(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		".gemini/settings.json":           `{"mcpServers":{"a":{"command":"x"}}}`,
		"opencode.jsonc":                  `{"plugin":["p",],}`,
		".windsurf/hooks.json":            `{"hooks":{"pre_run_command":[{"command":"x"}]}}`,
		".devcontainer/devcontainer.json": `{"postCreateCommand":"x"}`,
		"AGENTS.md":                       "x\n",
	}
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		harness string
		implied []string
	}{
		{"gemini", []string{"generic: also scanned"}},
		{"opencode", []string{"claude: also scanned", "generic: also scanned"}},
		{"windsurf", []string{"generic: also scanned"}},
		{"devcontainer", nil},
	}
	for _, tc := range cases {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", "--harness", tc.harness, root}, &stdout, &stderr); code != int(exitcode.OK) {
			t.Fatalf("%s exit %d stderr %q", tc.harness, code, stderr.String())
		}
		for _, want := range tc.implied {
			if !strings.Contains(stderr.String(), want) {
				t.Fatalf("%s stderr = %q, want %q", tc.harness, stderr.String(), want)
			}
		}
		if tc.implied == nil && strings.Contains(stderr.String(), "also scanned") {
			t.Fatalf("%s stderr = %q", tc.harness, stderr.String())
		}
	}
}

// setHome points the home directory at home and clears the tool-specific
// overrides that move one harness's configuration elsewhere. Those stay
// blocking when they point outside home, so a runner that exports one
// would fail a user-scope scan. XDG_CONFIG_HOME and XDG_DATA_HOME are
// not cleared here: a value outside home is informational and does not
// change the exit code.
func setHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, name := range []string{"OPENCODE_CONFIG", "OPENCODE_CONFIG_DIR", "GEMINI_CLI_HOME", "CODEX_HOME", "COPILOT_HOME", "CLAUDE_CONFIG_DIR"} {
		t.Setenv(name, "")
	}
}

func outsideGit(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tripcord-scan-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}

func TestScanNewAdaptersAndImpliedOwners(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		".codex/config.toml":            "sandbox_mode = \"danger-full-access\"\n",
		".cursor/hooks.json":            `{"version":1,"hooks":{"stop":[{"command":"x"}]}}`,
		".github/hooks/guard.json":      `{"version":1,"hooks":{"preToolUse":[{"bash":"x"}]}}`,
		".github/copilot/settings.json": `{`,
		"AGENTS.md":                     "x\n",
	}
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--harness", "cursor", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("cursor exit %d stderr %q", code, stderr.String())
	}
	for _, want := range []string{"claude: also scanned", "generic: also scanned"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--harness", "copilot", root}, &stdout, &stderr); code != int(exitcode.Config) || !strings.Contains(stderr.String(), "copilot: .github/copilot/settings.json: invalid JSON") {
		t.Fatalf("copilot exit %d stderr %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", root}, &stdout, &stderr); code != int(exitcode.Config) || strings.Contains(stderr.String(), "also scanned") {
		t.Fatalf("autodetect exit %d stderr %q", code, stderr.String())
	}
}
