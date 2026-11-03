package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
)

// embeddedBase is a git repository whose HEAD commit is a fresh
// init --embed, so each test's edit is the pull request under review.
func embeddedBase(t *testing.T, extra ...string) string {
	t.Helper()
	repo := gitRepo(t)
	if code, _, stderr := runCLI(t, embedArgs(append(extra, repo)...)...); code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	runGit(t, repo, "add", "-A")
	runGit(t, repo, "commit", "-m", "embed tripcord")
	return repo
}

func commitAll(t *testing.T, repo string) {
	t.Helper()
	runGit(t, repo, "add", "-A")
	runGit(t, repo, "commit", "-m", "change")
}

type guardFinding struct {
	path, title string
}

func guardFindings(t *testing.T, args ...string) (int, []guardFinding) {
	t.Helper()
	code, stdout, stderr := runCLI(t, append([]string{"scan", "--format", "json"}, args...)...)
	if code != int(exitcode.OK) && code != int(exitcode.Findings) {
		t.Fatalf("scan %v: exit %d: %s", args, code, stderr)
	}
	var out []guardFinding
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		var f model.Finding
		mustJSON(t, line, &f)
		if f.Rule != "TC-CFG-016" {
			continue
		}
		if f.Severity != model.SeverityHigh {
			t.Errorf("%s at %s is %s, want high", f.Title, f.Location.Path, f.Severity)
		}
		out = append(out, guardFinding{f.Location.Path, f.Title})
	}
	slices.SortFunc(out, func(a, b guardFinding) int { return strings.Compare(a.path+a.title, b.path+b.title) })
	return code, slices.Compact(out)
}

const (
	titleRemoved  = "This change removes Tripcord's guard"
	titleMissing  = "Tripcord embed is missing part of its guard"
	titleChanged  = "Tripcord guard was edited"
	titleStale    = "Tripcord guard was written by an older Tripcord"
	titleDropped  = "This change drops a harness from the Tripcord embed"
	titleRepinned = "This change re-pins Tripcord"
)

// removeEmbedGuard is the reviewer's repro: bootstrap.sh, embed.json, and
// the Copilot hook file deleted, and Tripcord's hooks stripped from the
// Claude and Cursor files.
func removeEmbedGuard(t *testing.T, repo string) {
	t.Helper()
	for _, p := range []string{embedded.BootstrapPath, embedded.ManifestPath, embedded.CopilotHooksPath} {
		if err := os.Remove(filepath.Join(repo, filepath.FromSlash(p))); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, repo, embedded.ClaudeSettingsPath, emptyClaudeHooks)
	writeTestFile(t, repo, embedded.CursorHooksPath, emptyCursorHooks)
}

func TestScanSinceReportsRemovedGuard(t *testing.T) {
	repo := embeddedBase(t)
	removeEmbedGuard(t, repo)
	commitAll(t, repo)
	for _, args := range [][]string{{repo, "--since", "HEAD~1"}, {repo, "--base", "HEAD~1"}} {
		code, got := guardFindings(t, args...)
		want := []guardFinding{
			{embedded.ClaudeSettingsPath, titleRemoved},
			{embedded.CursorHooksPath, titleRemoved},
			{embedded.CopilotHooksPath, titleRemoved},
			{embedded.BootstrapPath, titleRemoved},
			{embedded.ManifestPath, titleRemoved},
		}
		slices.SortFunc(want, func(a, b guardFinding) int { return strings.Compare(a.path+a.title, b.path+b.title) })
		if code != int(exitcode.Findings) || !slices.Equal(got, want) {
			t.Fatalf("scan %v: exit %d\ngot  %v\nwant %v", args[1:], code, got, want)
		}
	}
}

func TestScanSinceReportsRemovedEmbed(t *testing.T) {
	repo := embeddedBase(t)
	removeEmbedGuard(t, repo)
	for _, p := range []string{embedded.WorkflowPath, embedded.CopilotSetupStepsPath} {
		if err := os.Remove(filepath.Join(repo, filepath.FromSlash(p))); err != nil {
			t.Fatal(err)
		}
	}
	commitAll(t, repo)
	if code, got := guardFindings(t, repo); code != int(exitcode.OK) || len(got) != 0 {
		t.Fatalf("scan without a base: exit %d, %v", code, got)
	}
	code, got := guardFindings(t, repo, "--since", "HEAD~1")
	if code != int(exitcode.Findings) || !slices.Contains(got, guardFinding{embedded.BootstrapPath, titleRemoved}) ||
		!slices.Contains(got, guardFinding{embedded.WorkflowPath, titleRemoved}) || !slices.Contains(got, guardFinding{embedded.ClaudeSettingsPath, titleRemoved}) {
		t.Fatalf("exit %d: %v", code, got)
	}
}

func TestScanWithoutBaseReportsLeftoverWorkflow(t *testing.T) {
	repo := embeddedBase(t)
	removeEmbedGuard(t, repo)
	code, got := guardFindings(t, repo)
	want := []guardFinding{{embedded.BootstrapPath, titleMissing}, {embedded.ManifestPath, titleMissing}}
	if code != int(exitcode.Findings) || !slices.Equal(got, want) {
		t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
	}
}

func TestScanSinceReportsDroppedHarness(t *testing.T) {
	repo := embeddedBase(t)
	replaceInFile(embedded.ManifestPath, "\"cursor\",\n", "")(t, repo)
	writeTestFile(t, repo, embedded.CursorHooksPath, emptyCursorHooks)
	commitAll(t, repo)
	code, got := guardFindings(t, repo, "--since", "HEAD~1")
	want := []guardFinding{{embedded.CursorHooksPath, titleRemoved}, {embedded.ManifestPath, titleDropped}}
	if code != int(exitcode.Findings) || !slices.Equal(got, want) {
		t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
	}
}

func TestScanSinceReportsRepin(t *testing.T) {
	repo := embeddedBase(t)
	if code, _, stderr := runCLI(t, "init", "--embed", "--force", "--version", "0.1.1", "--sha256", "linux-x64="+strings.Repeat("e", 64), repo); code != 0 {
		t.Fatalf("re-pin: exit %d: %s", code, stderr)
	}
	commitAll(t, repo)
	if code, got := guardFindings(t, repo); code != int(exitcode.OK) || len(got) != 0 {
		t.Fatalf("a consistent re-pin passes a scan without a base: exit %d, %v", code, got)
	}
	code, got := guardFindings(t, repo, "--since", "HEAD~1")
	if want := []guardFinding{{embedded.ManifestPath, titleRepinned}}; code != int(exitcode.Findings) || !slices.Equal(got, want) {
		t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
	}
}

func TestScanSinceReportsBootstrapTamper(t *testing.T) {
	t.Run("edited", func(t *testing.T) {
		repo := embeddedBase(t)
		replaceInFile(embedded.BootstrapPath, `[ "$got" != "$want" ]`, "false")(t, repo)
		commitAll(t, repo)
		code, got := guardFindings(t, repo, "--since", "HEAD~1")
		if want := []guardFinding{{embedded.BootstrapPath, titleChanged}}; code != int(exitcode.Findings) || !slices.Equal(got, want) {
			t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
		}
	})
	t.Run("edited with a forged manifest digest", func(t *testing.T) {
		repo := embeddedBase(t)
		forgeDigest(t, repo)
		commitAll(t, repo)
		code, got := guardFindings(t, repo, "--since", "HEAD~1")
		if want := []guardFinding{{embedded.BootstrapPath, titleStale}}; code != int(exitcode.Findings) || !slices.Equal(got, want) {
			t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
		}
	})
}

func TestScanSinceUnchangedEmbedHasNoFindings(t *testing.T) {
	repo := embeddedBase(t)
	writeTestFile(t, repo, "README.md", "docs\n")
	commitAll(t, repo)
	if code, got := guardFindings(t, repo, "--since", "HEAD~1"); code != int(exitcode.OK) || len(got) != 0 {
		t.Fatalf("exit %d: %v", code, got)
	}
}

func TestScanBaseFlagValidation(t *testing.T) {
	repo := embeddedBase(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"scan", repo, "--base", "-x"}, "--base"},
		{[]string{"scan", repo, "--base", "HEAD", "--since", "HEAD~1"}, "--base"},
		{[]string{"scan", repo, "--base", "no-such-ref"}, "not a commit"},
		{[]string{"scan", "--staged", "--base", "HEAD"}, "--base"},
	} {
		code, _, stderr := runCLI(t, tc.args...)
		if code != int(exitcode.Config) || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d: %s", tc.args[1:], code, stderr)
		}
	}
	if code, _, stderr := runCLI(t, "scan", repo, "--base", "HEAD", "--since", "HEAD"); code != int(exitcode.OK) {
		t.Errorf("--base equal to --since: exit %d: %s", code, stderr)
	}
}
