//go:build !windows

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/model"
)

var (
	e2eBinaryOnce sync.Once
	e2eBinaryPath string
	e2eBinaryErr  error
)

// e2eBinary builds tripcord once per test run, as `go build -trimpath`
// of this tree, the way docs/init.md says to fill the bootstrap cache.
func e2eBinary(t *testing.T) string {
	t.Helper()
	e2eBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tripcord-e2e-bin-")
		if err != nil {
			e2eBinaryErr = err
			return
		}
		e2eBinaryPath = filepath.Join(dir, "tripcord")
		build := exec.Command("go", "build", "-trimpath", "-o", e2eBinaryPath, ".")
		build.Dir = filepath.Join(adaptersDir, "..", "..", "cmd", "tripcord")
		if out, err := build.CombinedOutput(); err != nil {
			e2eBinaryErr = errors.New("go build: " + err.Error() + "\n" + string(out))
		}
	})
	if e2eBinaryErr != nil {
		t.Fatal(e2eBinaryErr)
	}
	return e2eBinaryPath
}

func e2ePlatform(t *testing.T) string {
	t.Helper()
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if (runtime.GOOS != "linux" && runtime.GOOS != "darwin") || arch == "" {
		t.Skipf("bootstrap.sh does not support %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return runtime.GOOS + "-" + arch
}

// embedE2E is a repository with init --embed output pinned to a fresh
// tripcord build, the policy of the hook tests, and a bootstrap cache
// to fill.
type embedE2E struct {
	repo, cache, home, bin string
	platform               string
}

func newEmbedE2E(t *testing.T) *embedE2E {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	e := &embedE2E{repo: embedRoot(t), cache: t.TempDir(), home: t.TempDir(), bin: e2eBinary(t), platform: e2ePlatform(t)}
	raw, err := os.ReadFile(e.bin)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "init", "--embed", "--version", "0.1.0", "--sha256", e.platform+"="+sha256Hex(raw), e.repo); code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	writeTestFile(t, e.repo, embedded.PolicyPath, hookTestPolicy)
	return e
}

func (e *embedE2E) cached() string {
	return filepath.Join(e.cache, "tripcord", "0.1.0", e.platform, "tripcord")
}

// fillCache copies content into the bootstrap cache as the binary.
func (e *embedE2E) fillCache(t *testing.T, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.cached()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.cached(), content, 0o755); err != nil {
		t.Fatal(err)
	}
}

// hookCommand is the pre-tool command init wrote into h's wiring file.
func (e *embedE2E) hookCommand(t *testing.T, h model.Harness) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.repo, filepath.FromSlash(embedded.HookPath(h))))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
			Command string `json:"command"`
			Bash    string `json:"bash"`
		} `json:"hooks"`
	}
	mustJSON(t, string(raw), &doc)
	switch h {
	case model.HarnessClaude:
		if pre := doc.Hooks["PreToolUse"]; len(pre) == 1 && len(pre[0].Hooks) == 1 {
			return pre[0].Hooks[0].Command
		}
	case model.HarnessCursor:
		if pre := doc.Hooks["preToolUse"]; len(pre) == 1 {
			return pre[0].Command
		}
	case model.HarnessCopilot:
		if pre := doc.Hooks["preToolUse"]; len(pre) == 1 {
			return pre[0].Bash
		}
	default:
		t.Fatalf("%s has no hook wiring", h)
	}
	t.Fatalf("no pre-tool hook in %s", embedded.HookPath(h))
	return ""
}

// runHookCommand runs command with bash -c, as the harness does, in dir
// with env added to a minimal environment, and input on stdin.
func (e *embedE2E) runHookCommand(t *testing.T, command, dir string, env []string, input []byte) (int, string, string) {
	t.Helper()
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	cmd.Env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + e.home,
		"XDG_CACHE_HOME=" + e.cache,
		"TMPDIR=" + t.TempDir(),
	}, env...)
	cmd.Stdin = bytes.NewReader(input)
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

// TestEmbedClaudeHookWithoutProjectDir: the Copilot CLI also runs the
// hooks in .claude/settings.json, from the repository root and without
// CLAUDE_PROJECT_DIR. The Claude Code hook then finds bootstrap.sh in
// the working directory and decides as under Claude Code.
func TestEmbedClaudeHookWithoutProjectDir(t *testing.T) {
	e := newEmbedE2E(t)
	raw, err := os.ReadFile(e.bin)
	if err != nil {
		t.Fatal(err)
	}
	e.fillCache(t, raw)
	command := e.hookCommand(t, model.HarnessClaude)
	for _, tc := range []struct {
		fixture string
		exit    int
		stdout  string
	}{
		{"pre-tool-use-bash-deny.json", 2, claudeDeny(pipeReason)},
		{"pre-tool-use-bash-allow.json", 0, "{}\n"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			code, stdout, stderr := e.runHookCommand(t, command, e.repo, nil, adapterFixture(t, model.HarnessClaude, tc.fixture))
			if code != tc.exit || stdout != tc.stdout {
				t.Errorf("got exit %d stdout %q stderr %q, want exit %d and %q", code, stdout, stderr, tc.exit, tc.stdout)
			}
		})
	}
}
