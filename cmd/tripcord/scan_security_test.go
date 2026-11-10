package main

import (
	"bytes"
	"fmt"
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

// TestSinceErrorKeepsGitStderr checks that a --since failure keeps git's
// own diagnostic (e.g. "bad revision") in the error message, instead of
// only the generic wrapper text, so the user can tell why the ref did
// not resolve.
func TestSinceErrorKeepsGitStderr(t *testing.T) {
	t.Parallel()
	repo := gitRepo(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", repo, "--since", "nonexistent-ref-xyz"}, &stdout, &stderr)
	if code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "bad revision") {
		t.Fatalf("stderr = %q, want git's own diagnostic", stderr.String())
	}
}

// TestSanitizeGitStderrReplacesHome checks that sanitizeGitStderr hides
// the local home directory while keeping the rest of git's message. The
// rewrite rule itself (empty/root home, path-segment boundaries on both
// sides) is pathx.TildeHome's and is covered by internal/pathx's own
// tests; this only checks that sanitizeGitStderr actually applies it.
func TestSanitizeGitStderrReplacesHome(t *testing.T) {
	t.Parallel()
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory to redact")
	}
	raw := "fatal: not a git repository: " + home + "/repo/.git\nsome more detail\n"
	got := sanitizeGitStderr([]byte(raw))
	if strings.Contains(got, home) {
		t.Fatalf("sanitizeGitStderr(%q) = %q, still contains home directory", raw, got)
	}
	if !strings.Contains(got, "fatal: not a git repository: ~/repo/.git") || !strings.Contains(got, "some more detail") {
		t.Fatalf("sanitizeGitStderr(%q) = %q", raw, got)
	}
}

// TestSanitizeGitStderrTruncates checks that an overly long git
// diagnostic (git's own remediation text for dubious ownership can run
// well past a typical single-line error, and an attacker-controlled ref
// or path name can pad it further) is capped rather than embedded in
// full.
func TestSanitizeGitStderrTruncates(t *testing.T) {
	t.Parallel()
	raw := "fatal: " + strings.Repeat("x", maxGitStderrBytes*2)
	got := sanitizeGitStderr([]byte(raw))
	if len(got) >= len(raw) {
		t.Fatalf("sanitizeGitStderr did not truncate: got %d bytes, raw %d bytes", len(got), len(raw))
	}
	if !strings.Contains(got, "truncated") {
		t.Fatalf("sanitizeGitStderr(%q) = %q, want a truncation marker", raw, got)
	}
	if !strings.HasPrefix(got, "fatal: "+strings.Repeat("x", 20)) {
		t.Fatalf("sanitizeGitStderr dropped the start of the message: %q", got)
	}
}

// TestSanitizeGitStderrTruncatesDubiousOwnership checks the truncation
// against git's own real "dubious ownership" remediation text, which
// lists every ancestor directory up to the repository root and can run
// well past 1 KB on a deeply nested path.
func TestSanitizeGitStderrTruncatesDubiousOwnership(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("fatal: detected dubious ownership in repository at '/work/repo'\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "To add an exception for this directory, call:\n\n\tgit config --global --add safe.directory /work/repo/segment-%02d\n\n", i)
	}
	raw := b.String()
	got := sanitizeGitStderr([]byte(raw))
	if len(got) > maxGitStderrBytes+64 {
		t.Fatalf("sanitizeGitStderr did not cap the dubious-ownership dump: got %d bytes", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Fatalf("sanitizeGitStderr(%q) = %q, want a truncation marker", raw, got)
	}
	if !strings.HasPrefix(got, "fatal: detected dubious ownership") {
		t.Fatalf("sanitizeGitStderr dropped the start of the message: %q", got)
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

func TestScanFileOutsideGitDoesNotScanParent(t *testing.T) {
	dir := outsideGit(t)
	writeTestFile(t, dir, ".claude/settings.json", stagedBad)
	writeTestFile(t, dir, "notes.txt", "notes\n")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", filepath.Join(dir, "notes.txt")}, &stdout, &stderr)
	if code != int(exitcode.Config) || strings.Contains(stdout.String(), "TC-CFG-001") || !strings.Contains(stderr.String(), "file outside a Git repository") {
		t.Fatalf("file: exit %d\nstdout %s\nstderr %s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", dir}, &stdout, &stderr)
	if code != int(exitcode.Findings) || !strings.Contains(stdout.String(), "TC-CFG-001") {
		t.Fatalf("directory: exit %d\nstdout %s\nstderr %s", code, stdout.String(), stderr.String())
	}
	repo := gitRepo(t)
	writeTestFile(t, repo, ".claude/settings.json", stagedBad)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", filepath.Join(repo, "a.txt")}, &stdout, &stderr)
	if code != int(exitcode.Findings) || !strings.Contains(stdout.String(), "TC-CFG-001") {
		t.Fatalf("repo file: exit %d\nstdout %s\nstderr %s", code, stdout.String(), stderr.String())
	}
}

func TestScanOutsideGit(t *testing.T) {
	dir := outsideGit(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", dir, "--since", "HEAD"}, &stdout, &stderr); code != int(exitcode.Config) || !strings.Contains(stderr.String(), "--since requires a Git repository") || strings.Contains(stderr.String(), "not a git repository") {
		t.Fatalf("--since exit code = %d, stderr = %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--base", "HEAD", dir}, &stdout, &stderr); code != int(exitcode.Config) || !strings.Contains(stderr.String(), "--base requires a Git repository") {
		t.Fatalf("--base exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestScanSymlinkLoop(t *testing.T) {
	dir := outsideGit(t)
	self := filepath.Join(dir, "self")
	if err := os.Symlink(self, self); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{self, a} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"scan", path}, &stdout, &stderr)
		if code != int(exitcode.Config) || !strings.Contains(stderr.String(), "symbolic link loop") {
			t.Fatalf("%s: exit %d, stderr = %q", path, code, stderr.String())
		}
	}
}

// TestOutputPathErrorsAreConfigErrors checks that an invalid --output
// destination is a configuration error (exit 3), diagnosed before any
// finding is written, rather than an internal error (exit 4).
func TestOutputPathErrorsAreConfigErrors(t *testing.T) {
	t.Parallel()
	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		dir := outsideGit(t)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"scan", "--output", link, dir}, &stdout, &stderr)
		if code != int(exitcode.Config) {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
	})
	t.Run("missing directory", func(t *testing.T) {
		t.Parallel()
		dir := outsideGit(t)
		missingDir := filepath.Join(t.TempDir(), "no-such-dir", "out.txt")
		var stdout, stderr bytes.Buffer
		code := run([]string{"scan", "--output", missingDir, dir}, &stdout, &stderr)
		if code != int(exitcode.Config) {
			t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
		}
	})
}

// TestMissingPolicyFileIsConfigError checks that an explicit --policy
// path that does not exist is a configuration error, not silently
// ignored. Unlike the default .tripcord/policy.yaml, an explicit path is
// mandatory.
func TestMissingPolicyFileIsConfigError(t *testing.T) {
	t.Parallel()
	dir := outsideGit(t)
	missing := filepath.Join(t.TempDir(), "missing-policy.yaml")
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--policy", missing, dir}, &stdout, &stderr)
	if code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not exist") {
		t.Fatalf("stderr = %q", stderr.String())
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
	// A git command whose discovery walks out of repo into this
	// checkout would add, commit, or refresh the checkout's index while
	// other packages' tests read it. Ceiling stops that walk, and a
	// command that still resolves here fails instead of taking the lock.
	if len(args) == 0 || args[0] != "init" {
		if dir, err := absoluteGitDir(repo); err == nil && dir == sourceGitDir(t) {
			t.Fatalf("git %s in %s uses this checkout's index (%s)", strings.Join(args, " "), repo, dir)
		}
	}
	command := exec.Command("git", append([]string{"-C", repo, "--no-optional-locks"}, args...)...)
	command.Env = gitTestEnv(repo)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// gitTestEnv is the environment for a test git command in repo. It
// drops variables that would retarget the command onto another
// repository's index, and stops discovery from walking above repo.
func gitTestEnv(repo string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_NAMESPACE", "GIT_PREFIX":
			continue
		}
		env = append(env, entry)
	}
	ceiling := repo
	if abs, err := filepath.Abs(repo); err == nil {
		ceiling = abs
	}
	return append(env, "GIT_CEILING_DIRECTORIES="+ceiling)
}

func absoluteGitDir(repo string) (string, error) {
	cmd := exec.Command("git", "-C", repo, "--no-optional-locks", "rev-parse", "--absolute-git-dir")
	cmd.Env = gitTestEnv(repo)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return filepath.Clean(strings.TrimSpace(string(out))), nil
}

func sourceGitDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		gitPath := filepath.Join(dir, ".git")
		info, err := os.Lstat(gitPath)
		if err == nil {
			if info.IsDir() {
				return gitPath
			}
			raw, err := os.ReadFile(gitPath)
			if err != nil {
				t.Fatal(err)
			}
			line := strings.TrimSpace(string(raw))
			gitdir, ok := strings.CutPrefix(line, "gitdir: ")
			if !ok {
				t.Fatalf("%s is not a gitdir file", gitPath)
			}
			if !filepath.IsAbs(gitdir) {
				gitdir = filepath.Join(dir, gitdir)
			}
			abs, err := filepath.Abs(gitdir)
			if err != nil {
				t.Fatal(err)
			}
			return filepath.Clean(abs)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
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
