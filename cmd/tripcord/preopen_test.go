package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/preopen/preopentest"
)

// preopenTemp points os.TempDir at a fresh directory, so a test can
// check that preopen leaves nothing behind.
func preopenTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	return dir
}

func assertNoEntries(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("%s left behind %s", dir, e.Name())
	}
}

func TestPreopenScansCloneAndRunsNothing(t *testing.T) {
	git := preopentest.RequireTools(t)
	a := preopentest.NewArmed(t, git)
	tmp := preopenTemp(t)
	a.Arm(t)
	for _, target := range []string{a.Src, "file://" + filepath.ToSlash(a.Src)} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"preopen", "--format", "json", target}, &stdout, &stderr)
		if code != int(exitcode.Findings) {
			t.Fatalf("preopen %s = %d, want %d\nstdout: %s\nstderr: %s", target, code, exitcode.Findings, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"TC-CFG-001"`) || !strings.Contains(stdout.String(), ".claude/settings.json") {
			t.Errorf("preopen %s did not report the cloned settings:\n%s", target, stdout.String())
		}
		if got := a.Tripped(); len(got) != 0 {
			t.Fatalf("preopen %s ran %v", target, got)
		}
		assertNoEntries(t, tmp)
	}
}

func preopenRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	git := preopentest.RequireTools(t)
	repo := filepath.Join(t.TempDir(), "repo")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "repo")
	for path, content := range files {
		preopentest.WriteFile(t, filepath.Join(repo, filepath.FromSlash(path)), content, 0o644)
	}
	preopentest.Git(t, git, repo, "add", "-A")
	preopentest.Git(t, git, repo, "commit", "-q", "--allow-empty", "-m", "fixture")
	return repo
}

func TestPreopenCleanRepositoryExitsZero(t *testing.T) {
	repo := preopenRepo(t, map[string]string{"README": "hello\n"})
	tmp := preopenTemp(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"preopen", repo}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("preopen = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	assertNoEntries(t, tmp)
}

// A cloned repository must not relax its own result: its .tripcord
// policy is ignored, though the same file governs an in-place scan.
func TestPreopenIgnoresClonedPolicy(t *testing.T) {
	repo := preopenRepo(t, map[string]string{
		".claude/settings.json":       preopentest.ClaudeSettings,
		".tripcord/policy.yaml":       "version: 1\nmode: audit\n",
		".tripcord/policy.local.yaml": "version: 1\nmode: audit\n",
	})
	preopenTemp(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("control: scan under the repository's audit policy = %d, want 0\nstderr: %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"preopen", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("preopen = %d, want %d\nstdout: %s\nstderr: %s", code, exitcode.Findings, stdout.String(), stderr.String())
	}
}

func TestPreopenFailOn(t *testing.T) {
	repo := preopenRepo(t, map[string]string{".claude/settings.json": preopentest.ClaudeSettings})
	preopenTemp(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"preopen", "--fail-on", "critical", "--format", "json", repo}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("preopen --fail-on critical = %d, want 0 for a high finding\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"TC-CFG-001"`) {
		t.Fatalf("preopen --fail-on critical did not report the finding:\n%s", stdout.String())
	}
	if code := run([]string{"preopen", "--fail-on", "medium", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("preopen --fail-on medium = %d, want %d", code, exitcode.Findings)
	}
	if code := run([]string{"preopen", "--fail-on", "bogus", repo}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("preopen --fail-on bogus = %d, want %d", code, exitcode.Config)
	}
}

func TestPreopenRejectsUsage(t *testing.T) {
	preopentest.RequireTools(t)
	tmp := preopenTemp(t)
	sentinel := filepath.Join(t.TempDir(), "ext")
	repo := preopenRepo(t, nil)
	for name, args := range map[string][]string{
		"no target":     {"preopen"},
		"two targets":   {"preopen", repo, repo},
		"ext transport": {"preopen", "ext::sh -c touch% " + filepath.ToSlash(sentinel)},
		"git transport": {"preopen", "git://127.0.0.1:9/repo"},
		"missing path":  {"preopen", filepath.Join(t.TempDir(), "missing")},
		"option target": {"preopen", "--", "-uhelp"},
		"since":         {"preopen", "--since", "HEAD~1", repo},
		"user scope":    {"preopen", "--scope", "user", repo},
		"secrets":       {"preopen", "--secrets", repo},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != int(exitcode.Config) {
			t.Errorf("%s: preopen = %d, want %d\nstderr: %s", name, code, exitcode.Config, stderr.String())
		}
		if !strings.HasPrefix(stderr.String(), "tripcord preopen: ") {
			t.Errorf("%s: stderr = %q", name, stderr.String())
		}
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("ext:: command ran")
	}
	assertNoEntries(t, tmp)
}

func TestPreopenHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"preopen", "--help"}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("preopen --help = %d", code)
	}
	if !strings.HasPrefix(stdout.String(), "tripcord preopen <git-url|path>\n") {
		t.Fatalf("help = %q", stdout.String())
	}
}
