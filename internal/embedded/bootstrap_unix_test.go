//go:build !windows

package embedded

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const fakeBinary = "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$TRIPCORD_TEST_ARGS\"\n"

func hostPlatform(t *testing.T) string {
	t.Helper()
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if (runtime.GOOS != "linux" && runtime.GOOS != "darwin") || arch == "" {
		t.Skipf("bootstrap.sh does not support %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return runtime.GOOS + "-" + arch
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type bootstrapEnv struct {
	repo, cache, stubs, args string
	fetched                  string
	platform                 string
	extraEnv                 []string
}

// newBootstrapEnv writes bootstrap.sh pinned to fakeBinary for this
// platform, and npm, pip, python3, curl, and wget stubs that record
// that they ran: bootstrap.sh must never call any of them.
func newBootstrapEnv(t *testing.T, pinned map[string]string) *bootstrapEnv {
	t.Helper()
	e := &bootstrapEnv{repo: t.TempDir(), cache: t.TempDir(), stubs: t.TempDir(), platform: hostPlatform(t)}
	e.args = filepath.Join(t.TempDir(), "args")
	if pinned == nil {
		pinned = map[string]string{e.platform: sum(fakeBinary)}
	}
	write(t, e.repo, BootstrapPath, string(Bootstrap(Pin{Version: "0.1.0", SHA256: pinned})))
	e.fetched = filepath.Join(t.TempDir(), "fetched")
	for _, name := range []string{"npm", "pip", "pip3", "python3", "curl", "wget"} {
		e.stub(t, name, "#!/bin/sh\necho "+name+" >>'"+e.fetched+"'\nexit 1\n")
	}
	return e
}

// assertNoFetch fails the test if bootstrap.sh ran a package manager or
// a downloader.
func (e *bootstrapEnv) assertNoFetch(t *testing.T) {
	t.Helper()
	if raw, err := os.ReadFile(e.fetched); err == nil {
		t.Fatalf("bootstrap.sh ran %q", raw)
	}
}

func (e *bootstrapEnv) stub(t *testing.T, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.stubs, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (e *bootstrapEnv) cached() string {
	return filepath.Join(e.cache, "tripcord", "0.1.0", e.platform, "tripcord")
}

func (e *bootstrapEnv) putCache(t *testing.T, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.cached()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.cached(), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (e *bootstrapEnv) run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	code, stdout, stderr := e.runSplit(t, args...)
	return code, stdout + stderr
}

// runSplit runs bootstrap.sh and returns its stdout and stderr apart,
// since harnesses parse stdout.
func (e *bootstrapEnv) runSplit(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return e.runShell(t, "sh", args...)
}

// runShell is runSplit with an explicit interpreter. The hook line init
// writes is bash, which takes the builtin uid and platform path.
func (e *bootstrapEnv) runShell(t *testing.T, shell string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(shell, append([]string{filepath.Join(e.repo, BootstrapPath)}, args...)...)
	cmd.Env = append([]string{
		"PATH=" + e.stubs + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"XDG_CACHE_HOME=" + e.cache,
		"TMPDIR=" + t.TempDir(),
		"TRIPCORD_TEST_ARGS=" + e.args,
	}, e.extraEnv...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, stdout.String(), stderr.String()
	case errors.As(err, &exit):
		return exit.ExitCode(), stdout.String(), stderr.String()
	default:
		t.Fatal(err)
		return 0, "", ""
	}
}

func (e *bootstrapEnv) ran(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(e.args)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestBootstrapScriptHasNoUnpinnedFetch(t *testing.T) {
	script := string(Bootstrap(testPin))
	var code strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code.WriteString(line + "\n")
		}
	}
	for _, banned := range []string{"eval", "curl", "wget", "latest", "| sh", "|sh", "npm", "pip", "python", "TRIPCORD_INSTALL_SOURCES"} {
		if strings.Contains(code.String(), banned) {
			t.Errorf("bootstrap.sh contains %q", banned)
		}
	}
	for _, want := range []string{"set -eu", "TRIPCORD_VERSION='0.1.0'", `"$cp_tool" "$cached" "$copy"`, `got="$(sha256_of "$copy")"`, `run_bin "$copy" hook "$@"`, "no longer matches the binary that was verified"} {
		if !strings.Contains(script, want) {
			t.Errorf("bootstrap.sh lacks %q", want)
		}
	}
	for _, banned := range []string{"GITHUB_PATH", "CLAUDE_ENV_FILE", "export PATH"} {
		if strings.Contains(code.String(), banned) {
			t.Errorf("bootstrap.sh edits PATH via %q; hooks must run the cached binary by absolute path", banned)
		}
	}
}

// fakeScanBinary records its arguments and writes to stdout, which
// bootstrap.sh must keep off the harness's stdout.
const fakeScanBinary = "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$TRIPCORD_TEST_ARGS\"\necho 'scan report'\n"

func TestBootstrapSessionStartUsesVerifiedCache(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		stdout string
	}{
		{[]string{"session-start"}, ""},
		{[]string{"session-start", "--harness", "claude"}, ""},
		{[]string{"session-start", "--harness", "copilot"}, ""},
		{[]string{"session-start", "--harness", "cursor"}, "{}\n"},
		{[]string{"install"}, ""},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			e := newBootstrapEnv(t, map[string]string{hostPlatform(t): sum(fakeScanBinary)})
			e.putCache(t, fakeScanBinary)
			code, stdout, stderr := e.runSplit(t, tc.args...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			root, err := filepath.EvalSymlinks(e.repo)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.ran(t); got != "scan\n--config\n"+root+"\n" {
				t.Fatalf("binary ran with %q", got)
			}
			if stdout != tc.stdout {
				t.Errorf("stdout = %q, want %q", stdout, tc.stdout)
			}
			if !strings.Contains(stderr, "scan report") {
				t.Errorf("scan output missing from stderr: %q", stderr)
			}
		})
	}
}

func TestBootstrapCursorSessionStartFailureKeepsJSON(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	code, stdout, stderr := e.runSplit(t, "session-start", "--harness", "cursor")
	if code != 2 || stdout != "{}\n" || !strings.Contains(stderr, "is not in the cache") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestBootstrapHookExecsCachedBinary(t *testing.T) {
	const echoBinary = "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$TRIPCORD_TEST_ARGS\"\nprintf '{\"permission\":\"allow\"}\\n'\n"
	e := newBootstrapEnv(t, map[string]string{hostPlatform(t): sum(echoBinary)})
	e.putCache(t, echoBinary)
	code, stdout, stderr := e.runSplit(t, "hook", "--harness", "cursor", "--event", HookEvent)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if got := e.ran(t); got != "hook\n--harness\ncursor\n--event\n"+HookEvent+"\n" {
		t.Fatalf("binary ran with %q", got)
	}
	if stdout != `{"permission":"allow"}`+"\n" || stderr != "" {
		t.Fatalf("stdout %q, stderr %q", stdout, stderr)
	}
}

func TestBootstrapRejectsRelativeCacheRoot(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	e.extraEnv = []string{"XDG_CACHE_HOME=relative/cache"}
	if code, out := e.run(t, "install"); code != 2 || !strings.Contains(out, "absolute path") || e.ran(t) != "" {
		t.Fatalf("exit %d: %s", code, out)
	}
}

// TestBootstrapFailsClosed: every mode exits 2 with the reason on
// stderr, runs no binary, and fetches nothing, when the cache holds no
// binary, a tampered, symlinked, or non-executable one, a cache
// directory is a symlink or writable by others, or the platform is not
// pinned.
func TestBootstrapFailsClosed(t *testing.T) {
	other := "linux-arm64"
	if hostPlatform(t) == other {
		other = "linux-x64"
	}
	for _, tc := range []struct {
		name   string
		pinned map[string]string
		setup  func(*testing.T, *bootstrapEnv)
		reason string
	}{
		{"no binary", nil, func(*testing.T, *bootstrapEnv) {}, "is not in the cache at"},
		{"tampered binary", nil, func(t *testing.T, e *bootstrapEnv) { e.putCache(t, fakeBinary+"# tampered\n") }, "not the pinned " + sum(fakeBinary) + "; it was not run"},
		{"symlinked binary", nil, func(t *testing.T, e *bootstrapEnv) {
			real := filepath.Join(t.TempDir(), "tripcord")
			if err := os.WriteFile(real, []byte(fakeBinary), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(e.cached()), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, e.cached()); err != nil {
				t.Fatal(err)
			}
		}, "is not a regular file"},
		{"platform not pinned", map[string]string{other: sum(fakeBinary)}, func(t *testing.T, e *bootstrapEnv) { e.putCache(t, fakeBinary) }, "no SHA-256 is pinned"},
		{"binary not executable", nil, func(t *testing.T, e *bootstrapEnv) {
			e.putCache(t, fakeBinary)
			mustChmod(t, e.cached(), 0o644)
		}, "is not executable; run chmod 0755 on it"},
		{"group-writable platform dir", nil, func(t *testing.T, e *bootstrapEnv) {
			e.putCache(t, fakeBinary)
			mustChmod(t, filepath.Dir(e.cached()), 0o770)
		}, "group- or world-writable"},
		{"world-writable version dir", nil, func(t *testing.T, e *bootstrapEnv) {
			e.putCache(t, fakeBinary)
			mustChmod(t, filepath.Dir(filepath.Dir(e.cached())), 0o707)
		}, "group- or world-writable"},
		{"world-writable tripcord root", nil, func(t *testing.T, e *bootstrapEnv) {
			e.putCache(t, fakeBinary)
			mustChmod(t, filepath.Join(e.cache, "tripcord"), 0o777)
		}, "group- or world-writable"},
		{"symlinked version dir", nil, func(t *testing.T, e *bootstrapEnv) {
			e.putCache(t, fakeBinary)
			version := filepath.Dir(filepath.Dir(e.cached()))
			moved := filepath.Join(t.TempDir(), "0.1.0")
			if err := os.Rename(version, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, version); err != nil {
				t.Fatal(err)
			}
		}, "are not directories or are symlinks"},
		{"group-writable run dir", nil, func(t *testing.T, e *bootstrapEnv) {
			e.putCache(t, fakeBinary)
			runs := filepath.Join(e.cache, "tripcord", ".run")
			if err := os.Mkdir(runs, 0o700); err != nil {
				t.Fatal(err)
			}
			mustChmod(t, runs, 0o770)
		}, "group- or world-writable"},
	} {
		for _, args := range [][]string{{"install"}, {"session-start", "--harness", "claude"}, {"hook", "--harness", "claude", "--event", HookEvent, "--on-failure", "block"}} {
			t.Run(tc.name+" "+args[0], func(t *testing.T) {
				e := newBootstrapEnv(t, tc.pinned)
				tc.setup(t, e)
				code, stdout, stderr := e.runSplit(t, args...)
				if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "tripcord bootstrap: ") || !strings.Contains(stderr, tc.reason) || e.ran(t) != "" {
					t.Fatalf("exit %d, stdout %q, stderr %q, want exit 2 and %q", code, stdout, stderr, tc.reason)
				}
				e.assertNoFetch(t)
			})
		}
	}
	t.Run("usage", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		if code, out := e.run(t); code != 2 || !strings.Contains(out, "usage:") {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
}

func TestBootstrapRefusesSymlinks(t *testing.T) {
	for name, link := range map[string]func(*testing.T, *bootstrapEnv){
		"symlinked .tripcord": func(t *testing.T, e *bootstrapEnv) {
			other := t.TempDir()
			dir := filepath.Join(e.repo, ".tripcord")
			if err := os.Rename(dir, filepath.Join(other, ".tripcord")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(other, ".tripcord"), dir); err != nil {
				t.Fatal(err)
			}
		},
		"symlinked bootstrap.sh": func(t *testing.T, e *bootstrapEnv) {
			script := filepath.Join(e.repo, filepath.FromSlash(BootstrapPath))
			if err := os.Rename(script, script+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("bootstrap.sh.real", script); err != nil {
				t.Fatal(err)
			}
		},
	} {
		for _, args := range [][]string{{"session-start", "--harness", "claude"}, {"hook", "--harness", "claude", "--event", HookEvent}} {
			t.Run(name+" "+args[0], func(t *testing.T) {
				e := newBootstrapEnv(t, map[string]string{hostPlatform(t): sum(fakeScanBinary)})
				e.putCache(t, fakeScanBinary)
				link(t, e)
				code, _, stderr := e.runSplit(t, args...)
				if code == 0 || !strings.Contains(stderr, "must not be symlinks") {
					t.Fatalf("exit %d, stderr %q", code, stderr)
				}
				if got := e.ran(t); got != "" {
					t.Fatalf("binary ran with %q", got)
				}
			})
		}
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// selfPathBinary records the path it runs from, $0.
const selfPathBinary = "#!/bin/sh\nprintf '%s\\n' \"$0\" >\"$TRIPCORD_TEST_ARGS\"\n"

// TestBootstrapRunsPrivateCopy: the binary that runs is a copy in a
// directory only this user can enter, never the cached file itself, and
// both modes remove the copy afterward.
func TestBootstrapRunsPrivateCopy(t *testing.T) {
	for _, args := range [][]string{{"hook", "--harness", "claude", "--event", HookEvent}, {"install"}} {
		t.Run(args[0], func(t *testing.T) {
			e := newBootstrapEnv(t, map[string]string{hostPlatform(t): sum(selfPathBinary)})
			e.putCache(t, selfPathBinary)
			if code, out := e.run(t, args...); code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			ran := strings.TrimSpace(e.ran(t))
			runs := filepath.Join(e.cache, "tripcord", ".run")
			if ran == e.cached() || filepath.Dir(filepath.Dir(ran)) != runs || !strings.HasPrefix(filepath.Base(filepath.Dir(ran)), "run.") {
				t.Fatalf("ran %q, want a copy under %s", ran, runs)
			}
			info, err := os.Stat(runs)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("%s: %v, %v; want mode 0700", runs, info, err)
			}
			_, err = os.Stat(filepath.Dir(ran))
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s left its copy behind: %v", args[0], err)
			}
		})
	}
}

// TestBootstrapRemovesStaleCopies: exec leaves a hook run's copy behind,
// so each run removes this user's copies more than a minute old and
// keeps newer ones, which a concurrent run may be about to exec.
func TestBootstrapRemovesStaleCopies(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	runs := filepath.Join(e.cache, "tripcord", ".run")
	stale, fresh := filepath.Join(runs, "run.stale1"), filepath.Join(runs, "run.fresh1")
	for _, dir := range []string{stale, fresh} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		write(t, dir, "tripcord", fakeBinary)
	}
	old := time.Now().Add(-5 * time.Minute)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	mustChmod(t, runs, 0o700)
	if code, out := e.run(t, "hook", "--harness", "claude", "--event", HookEvent); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale copy kept: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh copy removed: %v", err)
	}
}

// TestBootstrapIgnoresPATHHashTools: sha256sum and shasum earlier in
// the caller's PATH that print the pinned digest for any file are not
// used, so a tampered binary is still refused.
func TestBootstrapIgnoresPATHHashTools(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary+"# tampered\n")
	lied := filepath.Join(t.TempDir(), "lied")
	for _, name := range []string{"sha256sum", "shasum", "find", "id", "cp", "mktemp", "uname"} {
		e.stub(t, name, "#!/bin/sh\necho "+name+" >>'"+lied+"'\nprintf '%s  %s\\n' '"+sum(fakeBinary)+"' \"$1\"\n")
	}
	for _, args := range [][]string{{"install"}, {"hook", "--harness", "claude", "--event", HookEvent}} {
		code, _, stderr := e.runSplit(t, args...)
		if code != 2 || !strings.Contains(stderr, "not the pinned") || e.ran(t) != "" {
			t.Fatalf("%s: exit %d, stderr %q, want the mismatch", args[0], code, stderr)
		}
	}
	if raw, err := os.ReadFile(lied); err == nil {
		t.Fatalf("bootstrap.sh ran PATH stubs: %q", raw)
	}
}

// TestBootstrapSwapBetweenHashAndExec swaps the cached binary between
// the pinned one and another, as fast as it can, while hook mode runs.
// The other binary must never run: what runs is the copy that was
// hashed.
func TestBootstrapSwapBetweenHashAndExec(t *testing.T) {
	const evilBinary = "#!/bin/sh\n: >\"$TRIPCORD_TEST_EVIL\"\n"
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	evilRan := filepath.Join(t.TempDir(), "evil-ran")
	e.extraEnv = []string{"TRIPCORD_TEST_EVIL=" + evilRan}
	dir := filepath.Dir(e.cached())
	good, evil := filepath.Join(dir, "good"), filepath.Join(dir, "evil")
	write(t, dir, "good", fakeBinary)
	write(t, dir, "evil", evilBinary)
	mustChmod(t, good, 0o755)
	mustChmod(t, evil, 0o755)
	stop := make(chan struct{})
	swapped := make(chan error, 1)
	go func() {
		next := filepath.Join(dir, "next")
		for i := 0; ; i++ {
			select {
			case <-stop:
				swapped <- nil
				return
			default:
			}
			src := good
			if i%2 == 1 {
				src = evil
			}
			if err := os.Link(src, next); err != nil {
				swapped <- err
				return
			}
			if err := os.Rename(next, e.cached()); err != nil {
				swapped <- err
				return
			}
		}
	}()
	ok, refused := 0, 0
	for range 150 {
		code, stdout, stderr := e.runSplit(t, "hook", "--harness", "claude", "--event", HookEvent)
		if _, err := os.Stat(evilRan); err == nil {
			close(stop)
			t.Fatalf("the swapped-in binary ran (after %d verified runs and %d refusals)", ok, refused)
		}
		switch {
		case code == 0 && e.ran(t) != "":
			ok++
		case code == 2 && (strings.Contains(stderr, "not the pinned") || strings.Contains(stderr, "cannot copy the cached tripcord") || strings.Contains(stderr, "changed while it was being verified") || strings.Contains(stderr, "no longer matches")):
			refused++
		default:
			close(stop)
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		if err := os.Remove(e.args); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	close(stop)
	if err := <-swapped; err != nil {
		t.Fatal(err)
	}
	t.Logf("%d runs of the pinned binary, %d refusals, none of the other", ok, refused)
}

// TestBootstrapRefusesCacheDirOfAnotherUser needs root to hand a cache
// directory to another user. The process is uid 0, so the refusal names
// that uid: bootstrap.sh still exits 2 and does not run the cached binary.
func TestBootstrapRefusesCacheDirOfAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown a cache directory to another user")
	}
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	dir := filepath.Dir(e.cached())
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.runSplit(t, "hook", "--harness", "claude", "--event", HookEvent)
	want := "tripcord bootstrap: unsafe cache directories: " + dir + "; cache directories must be owned by uid 0\n"
	if code != 2 || stderr != want || e.ran(t) != "" {
		t.Fatalf("exit %d, stderr %q, want exit 2 and %q", code, stderr, want)
	}
}

// TestBootstrapCacheFillDocsWorkUnderUmask0002 follows the documented
// cache-fill mkdir under the regular-user umask used by Fedora and by
// Debian/Ubuntu with USERGROUPS_ENAB. The documented umask and chmod
// leave a cache bootstrap.sh accepts.
func TestBootstrapCacheFillDocsWorkUnderUmask0002(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	cache := filepath.Dir(e.cached())
	fill := exec.Command("sh", "-c", `umask 0002; mkdir -p "$1"; chmod go-w "${1%/*/*}" "${1%/*}" "$1"`, "fill", cache)
	if out, err := fill.CombinedOutput(); err != nil {
		t.Fatalf("documented cache fill: %v: %s", err, out)
	}
	if err := os.WriteFile(e.cached(), []byte(fakeBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, out := e.run(t, "hook", "--harness", "claude", "--event", HookEvent); code != 0 {
		t.Fatalf("bootstrap rejected the documented cache: exit %d: %s", code, out)
	}
}

// TestBootstrapReportsAllWritableCacheDirs gives every cache parent the
// umask-0002 mode and requires one error to name all of them and one
// chmod go-w command to fix them all.
func TestBootstrapReportsAllWritableCacheDirs(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	root := filepath.Join(e.cache, "tripcord")
	version := filepath.Join(root, "0.1.0")
	platform := filepath.Dir(e.cached())
	for _, dir := range []string{root, version, platform} {
		mustChmod(t, dir, 0o775)
	}
	code, _, stderr := e.runSplit(t, "hook", "--harness", "claude", "--event", HookEvent)
	want := "run chmod go-w " + root + " " + version + " " + platform
	if code != 2 || !strings.Contains(stderr, root) || !strings.Contains(stderr, version) || !strings.Contains(stderr, platform) || !strings.Contains(stderr, want) {
		t.Fatalf("exit %d, stderr %q, want every bad directory and %q", code, stderr, want)
	}
}

// TestBootstrapNixToolLookup documents the lookup order and its safe
// Nix condition. The template uses the standard paths first, then only
// accepts the Nix profile after stat says that directory is root-owned
// and neither group nor other can write it.
func TestBootstrapNixToolLookup(t *testing.T) {
	script := string(Bootstrap(testPin))
	for _, want := range []string{
		`for dir in /usr/bin /bin; do`,
		`nix_bin=/run/current-system/sw/bin`,
		`"$nix_bin/stat" -c '%u:%a' "$nix_bin"`,
		`0:[0-7][0-5][0-5]|0:[0-7][0-5][0-5][0-5]`,
		`if nix_tools_safe && [ -x "/run/current-system/sw/bin/$1" ]; then`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("bootstrap.sh lacks %q", want)
		}
	}
	standard := strings.Index(script, `for dir in /usr/bin /bin; do`)
	nix := strings.Index(script, `if nix_tools_safe &&`)
	if standard < 0 || nix < standard {
		t.Fatalf("tool lookup is not standard paths before safe Nix: standard=%d nix=%d", standard, nix)
	}
}

// TestBootstrapHookRefusesChangedBinary verifies the cached binary, then
// replaces it. hook must exit 2 and run nothing: a new inode with the
// same bytes, an in-place edit, and a different program. It must not
// hash the replacement and run it.
func TestBootstrapHookRefusesChangedBinary(t *testing.T) {
	const evilBinary = "#!/bin/sh\n: >\"$TRIPCORD_TEST_EVIL\"\n"
	hookArgs := []string{"hook", "--harness", "claude", "--event", HookEvent}
	refuse := func(t *testing.T, e *bootstrapEnv) {
		t.Helper()
		code, stdout, stderr := e.runSplit(t, hookArgs...)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "no longer matches the binary that was verified") || e.ran(t) != "" {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	}
	t.Run("same bytes new inode", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		e.putCache(t, fakeBinary)
		if code, out := e.run(t, "install"); code != 0 {
			t.Fatalf("install: exit %d: %s", code, out)
		}
		if err := os.Remove(e.args); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(e.cached())
		write(t, dir, "twin", fakeBinary)
		mustChmod(t, filepath.Join(dir, "twin"), 0o755)
		if err := os.Rename(filepath.Join(dir, "twin"), e.cached()); err != nil {
			t.Fatal(err)
		}
		refuse(t, e)
	})
	t.Run("modified in place", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		e.putCache(t, fakeBinary)
		if code, out := e.run(t, "install"); code != 0 {
			t.Fatalf("install: exit %d: %s", code, out)
		}
		if err := os.Remove(e.args); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(e.cached(), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("# changed\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		refuse(t, e)
	})
	t.Run("swapped program", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		e.putCache(t, fakeBinary)
		evilRan := filepath.Join(t.TempDir(), "evil-ran")
		e.extraEnv = []string{"TRIPCORD_TEST_EVIL=" + evilRan}
		if code, out := e.run(t, "install"); code != 0 {
			t.Fatalf("install: exit %d: %s", code, out)
		}
		if err := os.Remove(e.args); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		dir := filepath.Dir(e.cached())
		write(t, dir, "evil", evilBinary)
		mustChmod(t, filepath.Join(dir, "evil"), 0o755)
		if err := os.Rename(filepath.Join(dir, "evil"), e.cached()); err != nil {
			t.Fatal(err)
		}
		refuse(t, e)
		if _, err := os.Stat(evilRan); err == nil {
			t.Fatal("the swapped-in binary ran")
		}
	})
}

// TestBootstrapBashHookRefusesSwappedBinary covers the interpreter the
// harness actually runs. bash takes the builtin uid and platform path,
// then the same stat check: a same-bytes replacement is a new inode, so
// hook exits 2 and does not run it.
func TestBootstrapBashHookRefusesSwappedBinary(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	if code, stdout, stderr := e.runShell(t, "bash", "install"); code != 0 {
		t.Fatalf("install: exit %d: %s%s", code, stdout, stderr)
	}
	if err := os.Remove(e.args); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(e.cached())
	write(t, dir, "twin", fakeBinary)
	mustChmod(t, filepath.Join(dir, "twin"), 0o755)
	if err := os.Rename(filepath.Join(dir, "twin"), e.cached()); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := e.runShell(t, "bash", "hook", "--harness", "claude", "--event", HookEvent)
	if code != 2 || stdout != "" || !strings.Contains(stderr, "no longer matches the binary that was verified") || e.ran(t) != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// TestBootstrapHookHotPathRunsVerifiedFile: after verification, hook
// runs the cached file itself. The first unverified hook still runs a
// private copy.
func TestBootstrapHookHotPathRunsVerifiedFile(t *testing.T) {
	e := newBootstrapEnv(t, map[string]string{hostPlatform(t): sum(selfPathBinary)})
	e.putCache(t, selfPathBinary)
	hookArgs := []string{"hook", "--harness", "claude", "--event", HookEvent}
	if code, out := e.run(t, hookArgs...); code != 0 {
		t.Fatalf("first hook: exit %d: %s", code, out)
	}
	first := strings.TrimSpace(e.ran(t))
	runs := filepath.Join(e.cache, "tripcord", ".run")
	if first == e.cached() || filepath.Dir(filepath.Dir(first)) != runs {
		t.Fatalf("unverified hook ran %q, want a private copy under %s", first, runs)
	}
	if err := os.Remove(e.args); err != nil {
		t.Fatal(err)
	}
	if code, out := e.run(t, hookArgs...); code != 0 {
		t.Fatalf("verified hook: exit %d: %s", code, out)
	}
	if got := strings.TrimSpace(e.ran(t)); got != e.cached() {
		t.Fatalf("verified hook ran %q, want %s", got, e.cached())
	}
}

// TestBootstrapExecFailureNamesNoexec uses an executable whose
// interpreter does not exist, the same exec failure shell returns for
// a noexec filesystem. The bootstrap must explain noexec instead of
// leaking 126 or 127.
func TestBootstrapExecFailureNamesNoexec(t *testing.T) {
	const missingInterpreter = "#!/not/a/real/interpreter\n"
	e := newBootstrapEnv(t, map[string]string{hostPlatform(t): sum(missingInterpreter)})
	e.putCache(t, missingInterpreter)
	for _, args := range [][]string{{"hook", "--harness", "claude", "--event", HookEvent}, {"install"}} {
		code, _, stderr := e.runSplit(t, args...)
		if code != 2 || !strings.Contains(stderr, "noexec mount is a likely cause") {
			t.Fatalf("%s: exit %d stderr %q", args[0], code, stderr)
		}
	}
}
