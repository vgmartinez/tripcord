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
	cmd := exec.Command("sh", append([]string{filepath.Join(e.repo, BootstrapPath)}, args...)...)
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
	for _, banned := range []string{"eval", "curl", "wget", "latest", "| sh", "|sh", "npm", "pip", "python", "TRIPCORD_INSTALL_SOURCES", "mktemp"} {
		if strings.Contains(code.String(), banned) {
			t.Errorf("bootstrap.sh contains %q", banned)
		}
	}
	for _, want := range []string{"set -eu", "TRIPCORD_VERSION='0.1.0'", `exec "$cached" hook "$@"`} {
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
// binary, a tampered one, or a symlink, or the platform is not pinned.
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
