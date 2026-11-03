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
	platform                 string
	extraEnv                 []string
}

// newBootstrapEnv writes bootstrap.sh pinned to fakeBinary for this
// platform, and npm and python3 stubs that fail like a host with no
// network.
func newBootstrapEnv(t *testing.T, pinned map[string]string) *bootstrapEnv {
	t.Helper()
	e := &bootstrapEnv{repo: t.TempDir(), cache: t.TempDir(), stubs: t.TempDir(), platform: hostPlatform(t)}
	e.args = filepath.Join(t.TempDir(), "args")
	if pinned == nil {
		pinned = map[string]string{e.platform: sum(fakeBinary)}
	}
	write(t, e.repo, BootstrapPath, string(Bootstrap(Pin{Version: "0.1.0", SHA256: pinned})))
	e.stub(t, "npm", "#!/bin/sh\nexit 1\n")
	e.stub(t, "python3", "#!/bin/sh\nexit 1\n")
	return e
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
	for _, banned := range []string{"eval", "curl", "wget", "latest", "| sh", "|sh"} {
		if strings.Contains(code.String(), banned) {
			t.Errorf("bootstrap.sh contains %q", banned)
		}
	}
	for _, want := range []string{"set -eu", `TRIPCORD_INSTALL_SOURCES="${TRIPCORD_INSTALL_SOURCES:-npm pypi cache}"`, "mktemp -d", "chmod 0700 \"$tmp\"", "TRIPCORD_VERSION='0.1.0'", `exec "$cached" hook "$@"`} {
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
	if code == 0 || stdout != "{}\n" || !strings.Contains(stderr, "matching SHA-256") {
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

func TestBootstrapHookNeverInstalls(t *testing.T) {
	for name, setup := range map[string]func(*testing.T, *bootstrapEnv){
		"no cache":       func(*testing.T, *bootstrapEnv) {},
		"tampered cache": func(t *testing.T, e *bootstrapEnv) { e.putCache(t, fakeBinary+"# tampered\n") },
	} {
		t.Run(name, func(t *testing.T) {
			e := newBootstrapEnv(t, nil)
			npmRan := filepath.Join(t.TempDir(), "npm-ran")
			e.stub(t, "npm", "#!/bin/sh\ntouch '"+npmRan+"'\nexit 1\n")
			setup(t, e)
			code, stdout, stderr := e.runSplit(t, "hook", "--harness", "claude", "--event", HookEvent)
			if code == 0 || stdout != "" || !strings.Contains(stderr, "bootstrap.sh install") || e.ran(t) != "" {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if _, err := os.Stat(npmRan); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("hook mode tried to install")
			}
		})
	}
}

func TestBootstrapInstallSourcesOverride(t *testing.T) {
	t.Run("cache only skips npm", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		e.putCache(t, fakeBinary)
		npmRan := filepath.Join(t.TempDir(), "npm-ran")
		e.stub(t, "npm", "#!/bin/sh\ntouch '"+npmRan+"'\nexit 1\n")
		e.extraEnv = []string{"TRIPCORD_INSTALL_SOURCES=cache"}
		if code, out := e.run(t, "install"); code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if _, err := os.Stat(npmRan); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("npm ran although TRIPCORD_INSTALL_SOURCES=cache")
		}
	})
	t.Run("npm only ignores the cache", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		e.putCache(t, fakeBinary)
		e.extraEnv = []string{"TRIPCORD_INSTALL_SOURCES=npm"}
		if code, out := e.run(t, "install"); code == 0 || !strings.Contains(out, "tried: npm") || e.ran(t) != "" {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
	t.Run("unknown source", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		e.putCache(t, fakeBinary)
		e.extraEnv = []string{"TRIPCORD_INSTALL_SOURCES=cache https://example.invalid"}
		if code, out := e.run(t, "install"); code != 3 || !strings.Contains(out, "unknown install source") || e.ran(t) != "" {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
}

func TestBootstrapRejectsRelativeCacheRoot(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	e.extraEnv = []string{"XDG_CACHE_HOME=relative/cache"}
	if code, out := e.run(t, "install"); code != 3 || !strings.Contains(out, "absolute path") || e.ran(t) != "" {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestBootstrapFailsClosed(t *testing.T) {
	t.Run("no network and no cache", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		if code, out := e.run(t, "install"); code == 0 || !strings.Contains(out, "matching SHA-256") || e.ran(t) != "" {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
	t.Run("cache with a different binary", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		e.putCache(t, fakeBinary+"# tampered\n")
		if code, out := e.run(t, "install"); code == 0 || e.ran(t) != "" {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
	t.Run("platform not pinned", func(t *testing.T) {
		other := "linux-arm64"
		if hostPlatform(t) == other {
			other = "linux-x64"
		}
		e := newBootstrapEnv(t, map[string]string{other: sum(fakeBinary)})
		e.putCache(t, fakeBinary)
		if code, out := e.run(t, "install"); code != 3 || !strings.Contains(out, "no SHA-256 is pinned") || e.ran(t) != "" {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
	t.Run("usage", func(t *testing.T) {
		e := newBootstrapEnv(t, nil)
		if code, out := e.run(t); code != 2 {
			t.Fatalf("exit %d: %s", code, out)
		}
	})
}

// npmStub packs content as the platform package's bin/tripcord.
func npmStub(content string) string {
	return "#!/bin/sh\nset -eu\nmkdir -p package/bin\ncat >package/bin/tripcord <<'EOF'\n" + content + "EOF\ntar -czf pkg.tgz package\nrm -rf package\n"
}

func TestBootstrapInstallsFromNPM(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.stub(t, "npm", npmStub(fakeBinary))
	if code, out := e.run(t, "install"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if e.ran(t) == "" {
		t.Fatal("installed binary did not run")
	}
	raw, err := os.ReadFile(e.cached())
	if err != nil || string(raw) != fakeBinary {
		t.Fatalf("cache = %q, %v", raw, err)
	}
}

func TestBootstrapRejectsTamperedNPMPackage(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.stub(t, "npm", npmStub(fakeBinary+"# tampered\n"))
	if code, out := e.run(t, "install"); code == 0 || e.ran(t) != "" {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(e.cached()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered binary was cached: %v", err)
	}
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
