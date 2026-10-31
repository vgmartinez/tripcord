package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

func TestSinceDoesNotExecuteRepoGitConfig(t *testing.T) {
	repo := gitRepo(t)
	canary := filepath.Join(t.TempDir(), "canary")
	script := filepath.Join(t.TempDir(), "evil.sh")
	body := "#!/bin/sh\necho ran >> " + shellQuote(canary) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "config", "core.fsmonitor", "touch "+shellQuote(canary)+"; false")
	runGit(t, repo, "config", "diff.evil.command", script)
	runGit(t, repo, "config", "diff.evil.textconv", script)
	if err := os.WriteFile(filepath.Join(repo, ".gitattributes"), []byte("* diff=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", ".gitattributes", "a.txt")
	runGit(t, repo, "commit", "-m", "change")
	if err := os.RemoveAll(canary); err != nil {
		t.Fatal(err)
	}

	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "git.args")
	bin := t.TempDir()
	shim := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + shellQuote(logPath) + "\nexec " + shellQuote(realGit) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "not-a-repository"))

	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", repo, "--since", "HEAD~1"}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatal("repository git config executed a command")
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"core.fsmonitor=false", "core.hooksPath=/dev/null",
		"protocol.allow=never", "protocol.ext.allow=never", "protocol.file.allow=never",
		"--no-textconv", "--no-ext-diff", "--no-renames", "-z", "--end-of-options", "HEAD~1",
	} {
		if !strings.Contains(string(logged), want) {
			t.Fatalf("git invocation missing %s: %q", want, logged)
		}
	}
}

// TestSinceDoesNotLazyFetchFromPromisorRemote checks that --since does not
// contact a partial clone's promisor remote. Without --no-renames, "git
// diff --name-only" performs rename detection, which needs blob content
// and triggers a lazy fetch in a "--filter=blob:none" clone; a malicious
// remote.origin.url (here an "ext::" transport) could then run arbitrary
// code even though protocol.allow=never is set, because the repository's
// own protocol.ext.allow=always config takes precedence for that command.
func TestSinceDoesNotLazyFetchFromPromisorRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	src := t.TempDir()
	runGit(t, src, "init")
	runGit(t, src, "config", "user.email", "tripcord@example.com")
	runGit(t, src, "config", "user.name", "tripcord")
	runGit(t, src, "config", "uploadpack.allowfilter", "true")
	if err := os.WriteFile(filepath.Join(src, "old-name.txt"), []byte(strings.Repeat("line\n", 50)), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, src, "add", "old-name.txt")
	runGit(t, src, "commit", "-m", "init")
	if err := os.Rename(filepath.Join(src, "old-name.txt"), filepath.Join(src, "new-name.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "new-name.txt"), []byte(strings.Repeat("line\n", 50)+"tail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, src, "add", "-A")
	runGit(t, src, "commit", "-m", "rename")

	clone := filepath.Join(t.TempDir(), "clone")
	cloneCmd := exec.Command("git", "clone", "-q", "--no-local", "--filter=blob:none", "file://"+src, clone)
	if out, err := cloneCmd.CombinedOutput(); err != nil {
		t.Skipf("partial clone is not supported: %v\n%s", err, out)
	}

	canary := filepath.Join(t.TempDir(), "canary")
	script := filepath.Join(t.TempDir(), "evil.sh")
	body := "#!/bin/sh\ntouch " + shellQuote(canary) + "\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, clone, "config", "remote.origin.url", "ext::"+script)
	runGit(t, clone, "config", "protocol.ext.allow", "always")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", clone, "--since", "HEAD~1"}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatal("partial clone contacted the promisor remote")
	}
}

func TestSinceRejectsOptionInjection(t *testing.T) {
	repo := gitRepo(t)
	probe := filepath.Join(t.TempDir(), "probe")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", repo, "--since=--output=" + probe}, &stdout, &stderr)
	if code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatalf("git created %s: %v", probe, err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "start with '-'") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

// TestArgsAfterDashDashAreNotReparsedAsFlags checks that a positional
// argument after "--" is never treated as a flag. normalizeScanArgs must
// keep the "--" terminator in the argument list it hands to flag.Parse,
// or everything after a literal "--" is re-parsed as flags.
func TestArgsAfterDashDashAreNotReparsedAsFlags(t *testing.T) {
	t.Parallel()
	probe := filepath.Join(t.TempDir(), "probe")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--", "--output=" + probe}, &stdout, &stderr)
	if code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatalf("argument after -- was parsed as --output: %v", err)
	}
}

// TestDashPrefixedPathRequiresDashDash checks that a path starting with
// "-" is rejected as an unknown flag unless it follows "--", matching
// ordinary flag-parsing conventions. It changes the process's working
// directory, so unlike its neighbors it does not run in parallel: other
// tests in this package read relative paths (e.g. testdata/ for golden
// files) and run only once every non-parallel test, including this one
// and its deferred os.Chdir cleanup, has finished.
func TestDashPrefixedPathRequiresDashDash(t *testing.T) {
	parent := t.TempDir()
	weird := filepath.Join(parent, "-weird")
	if err := os.Mkdir(weird, 0o700); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(parent); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "-weird"}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("without --: exit code = %d, stderr = %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--", "-weird"}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("with --: exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestSinceKeepsNonASCIIAndSkipsUntracked(t *testing.T) {
	repo := gitRepo(t)
	name := "caf\u00e9.txt"
	if err := os.WriteFile(filepath.Join(repo, name), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", name)
	runGit(t, repo, "commit", "-m", "unicode")
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := changedFiles(repo, "HEAD~1")
	if err != nil {
		t.Fatal(err)
	}
	if !changed[name] {
		t.Fatalf("changed = %#v", changed)
	}
	if changed["untracked.txt"] || changed["a.txt"] {
		t.Fatalf("untracked or uncommitted path included: %#v", changed)
	}
}

func TestSinceMissingGit(t *testing.T) {
	repo := gitRepo(t)
	t.Setenv("PATH", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--since", "HEAD", repo}, &stdout, &stderr); code != int(exitcode.Internal) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "git") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestScanOutsideGit(t *testing.T) {
	dir := outsideGit(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if code := run([]string{"scan", dir, "--since", "HEAD"}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("--since exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestFailOnCannotLoosenLock(t *testing.T) {
	dir := outsideGit(t)
	org := filepath.Join(t.TempDir(), "org.yaml")
	policy := "version: 1\nmode: enforce\nfail-on: medium\nlocked:\n  mode: true\n"
	if err := os.WriteFile(org, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--org-policy", org, "--fail-on", "critical", dir}, &stdout, &stderr)
	if code != int(exitcode.Config) || !strings.Contains(stderr.String(), "ceiling") {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--org-policy", org, "--fail-on", "low", dir}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("tightening exit code = %d, stderr = %q", code, stderr.String())
	}
}

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "tripcord@example.com")
	runGit(t, repo, "config", "user.name", "tripcord")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "a.txt")
	runGit(t, repo, "commit", "-m", "init")
	return repo
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

func TestParseFlagsAfterPath(t *testing.T) {
	t.Parallel()
	opts, err := parseScanFlags([]string{".", "--since", "HEAD~1", "--format", "gha"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.path != "." || opts.since != "HEAD~1" || opts.format != "gha" {
		t.Fatalf("opts = %+v", opts)
	}
}
