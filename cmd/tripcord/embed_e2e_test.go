//go:build !windows

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/model"
)

// e2eBinary is the binary the end-to-end tests pin and cache: this test
// binary, which TestMain runs as tripcord under testAsCLIEnv.
func e2eBinary(t *testing.T) string {
	t.Helper()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func e2ePlatform(t *testing.T) string {
	t.Helper()
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if (runtime.GOOS != "linux" && runtime.GOOS != "darwin") || arch == "" {
		t.Skipf("bootstrap.sh does not support %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return runtime.GOOS + "-" + arch
}

// embedE2E is a repository with init --embed output pinned to
// e2eBinary, the policy of the hook tests, and a bootstrap cache to
// fill.
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
		testAsCLIEnv + "=1",
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

// TestEmbedHookThroughBootstrap runs each harness's generated pre-tool
// command, as that harness would, through bootstrap.sh to tripcord
// hook (e2eBinary): a verified binary decides, and a tampered or missing one blocks
// with exit 2 and the reason on stderr.
func TestEmbedHookThroughBootstrap(t *testing.T) {
	e := newEmbedE2E(t)
	real, err := os.ReadFile(e.bin)
	if err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(e.repo, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		harness           model.Harness
		dir               string
		env               []string
		deny, allow       string
		denyOut, allowOut string
	}{
		{model.HarnessClaude, sub, []string{"CLAUDE_PROJECT_DIR=" + e.repo}, "pre-tool-use-bash-deny.json", "pre-tool-use-bash-allow.json", claudeDeny(pipeReason), "{}\n"},
		{model.HarnessCursor, sub, []string{"CURSOR_PROJECT_DIR=" + e.repo}, "pre-tool-use-shell-deny.json", "pre-tool-use-shell-allow.json", cursorDeny(pipeReason), `{"permission":"allow"}` + "\n"},
		{model.HarnessCopilot, e.repo, nil, "pre-tool-use-bash-deny.json", "pre-tool-use-bash-allow.json", "", ""},
	} {
		command := e.hookCommand(t, tc.harness)
		run := func(t *testing.T, fixture string) (int, string, string) {
			t.Helper()
			return e.runHookCommand(t, command, tc.dir, tc.env, adapterFixture(t, tc.harness, fixture))
		}
		t.Run(string(tc.harness)+"/verified", func(t *testing.T) {
			e.fillCache(t, real)
			if code, stdout, stderr := run(t, tc.deny); code != 2 || stdout != tc.denyOut || stderr != pipeReason+"\n" {
				t.Errorf("deny: got exit %d stdout %q stderr %q", code, stdout, stderr)
			}
			if code, stdout, stderr := run(t, tc.allow); code != 0 || stdout != tc.allowOut || stderr != "" {
				t.Errorf("allow: got exit %d stdout %q stderr %q", code, stdout, stderr)
			}
			writeTestFile(t, e.repo, embedded.PolicyPath, "version: 2\n")
			defer writeTestFile(t, e.repo, embedded.PolicyPath, hookTestPolicy)
			if code, _, stderr := run(t, tc.allow); code != 2 || !strings.HasPrefix(stderr, "tripcord hook failed closed: ") {
				t.Errorf("invalid policy: got exit %d stderr %q, want the wiring's --on-failure block", code, stderr)
			}
		})
		for _, bad := range []struct {
			name   string
			fill   func(t *testing.T)
			reason string
		}{
			{"tampered", func(t *testing.T) { e.fillCache(t, append(slices.Clone(real), "\n# tampered\n"...)) }, "not the pinned"},
			{"missing", func(t *testing.T) {
				if err := os.Remove(e.cached()); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}, "is not in the cache at"},
		} {
			t.Run(string(tc.harness)+"/"+bad.name, func(t *testing.T) {
				bad.fill(t)
				for _, fixture := range []string{tc.deny, tc.allow} {
					code, stdout, stderr := run(t, fixture)
					if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "tripcord bootstrap: ") || !strings.Contains(stderr, bad.reason) {
						t.Errorf("%s: got exit %d stdout %q stderr %q, want exit 2 and %q", fixture, code, stdout, stderr, bad.reason)
					}
				}
			})
		}
	}
}

// TestEmbedBootstrapErrorFoldsHome: a bootstrap.sh error names the
// cache under the home directory as ~/..., the way the binary prints a
// home path, and never the home directory itself.
func TestEmbedBootstrapErrorFoldsHome(t *testing.T) {
	e := newEmbedE2E(t)
	command := e.hookCommand(t, model.HarnessClaude)
	code, stdout, stderr := e.runHookCommand(t, command, e.repo, []string{"XDG_CACHE_HOME=", "CLAUDE_PROJECT_DIR=" + e.repo}, adapterFixture(t, model.HarnessClaude, "pre-tool-use-bash-allow.json"))
	want := "is not in the cache at ~/.cache/tripcord/0.1.0/" + e.platform + "/tripcord;"
	if code != 2 || stdout != "" || !strings.Contains(stderr, want) || strings.Contains(stderr, e.home) {
		t.Errorf("got exit %d stdout %q stderr %q, want exit 2 and %q without %s", code, stdout, stderr, want, e.home)
	}
}
