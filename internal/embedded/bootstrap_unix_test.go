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
	cmd := exec.Command("sh", append([]string{filepath.Join(e.repo, BootstrapPath)}, args...)...)
	cmd.Env = append([]string{
		"PATH=" + e.stubs + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"XDG_CACHE_HOME=" + e.cache,
		"TMPDIR=" + t.TempDir(),
		"TRIPCORD_TEST_ARGS=" + e.args,
	}, e.extraEnv...)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exit):
		return exit.ExitCode(), string(out)
	default:
		t.Fatal(err)
		return 0, ""
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
	for _, want := range []string{"set -eu", "TRIPCORD_INSTALL_SOURCES='npm pypi cache'", "mktemp -d", "chmod 0700 \"$tmp\"", "TRIPCORD_VERSION='0.1.0'"} {
		if !strings.Contains(script, want) {
			t.Errorf("bootstrap.sh lacks %q", want)
		}
	}
}

func TestBootstrapUsesVerifiedCache(t *testing.T) {
	e := newBootstrapEnv(t, nil)
	e.putCache(t, fakeBinary)
	githubPath := filepath.Join(t.TempDir(), "path")
	claudeEnv := filepath.Join(t.TempDir(), "env")
	e.extraEnv = []string{"GITHUB_PATH=" + githubPath, "CLAUDE_ENV_FILE=" + claudeEnv}
	code, out := e.run(t, "session-start")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	root, err := filepath.EvalSymlinks(e.repo)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.ran(t); got != "scan\n--config\n"+root+"\n" {
		t.Fatalf("binary ran with %q", got)
	}
	if raw, _ := os.ReadFile(githubPath); string(raw) != filepath.Dir(e.cached())+"\n" {
		t.Errorf("GITHUB_PATH = %q", raw)
	}
	if raw, _ := os.ReadFile(claudeEnv); !strings.HasPrefix(string(raw), "export PATH='"+filepath.Dir(e.cached())+"':") {
		t.Errorf("CLAUDE_ENV_FILE = %q", raw)
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
