//go:build !windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/model"
)

// TestBootstrapHookLatencyBudget times the installed hook path: bash
// bootstrap.sh hook, with the pinned binary already in a local cache.
// The measured command's PATH is download stubs plus /usr/bin and /bin,
// and those stubs must not run. The policy is the locked enforce policy.
// p95 is still the 25 ms hook budget. Issue #41 records about 70 ms for
// the private copy and does not set a separate ceiling.
func TestBootstrapHookLatencyBudget(t *testing.T) {
	skipHookBudget(t)
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	platform := e2ePlatform(t)

	cache := t.TempDir()
	cached := filepath.Join(cache, "tripcord", "0.1.0", platform, "tripcord")
	if err := os.MkdirAll(filepath.Dir(cached), 0o700); err != nil {
		t.Fatal(err)
	}
	buildTrimpathTripcord(t, cached)
	raw, err := os.ReadFile(cached)
	if err != nil {
		t.Fatal(err)
	}

	root := hookProject(t, hookLockedEnforcePolicy)
	script := embedded.Bootstrap(embedded.Pin{Version: "0.1.0", SHA256: map[string]string{platform: sha256Hex(raw)}})
	scriptPath := filepath.Join(root, filepath.FromSlash(embedded.BootstrapPath))
	if err := os.WriteFile(scriptPath, script, 0o755); err != nil {
		t.Fatal(err)
	}

	stubs := t.TempDir()
	fetched := filepath.Join(t.TempDir(), "fetched")
	for _, name := range []string{"npm", "pip", "pip3", "python3", "curl", "wget"} {
		body := "#!/bin/sh\necho " + name + " >>'" + fetched + "'\nexit 1\n"
		if err := os.WriteFile(filepath.Join(stubs, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	toolPath := strings.Join([]string{stubs, "/usr/bin", "/bin"}, string(os.PathListSeparator))
	home := t.TempDir()
	tmp := t.TempDir()

	for _, tc := range hookColdCases() {
		input := adapterFixture(t, tc.harness, tc.fixture)
		wantOut, wantErr := hookColdOutput(t, tc)
		samples := make([]time.Duration, 0, hookColdStartRuns+5)
		for range hookColdStartRuns + 5 {
			cmd := exec.Command("bash", scriptPath, "hook", "--harness", string(tc.harness), "--event", tc.event, "--on-failure", "block")
			cmd.Dir = root
			cmd.Env = []string{
				"PATH=" + toolPath,
				"HOME=" + home,
				"XDG_CACHE_HOME=" + cache,
				"TMPDIR=" + tmp,
				"CLAUDE_PROJECT_DIR=" + root,
				"CURSOR_PROJECT_DIR=" + root,
				"CI=true",
			}
			cmd.Stdin = bytes.NewReader(input)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			start := time.Now()
			err := cmd.Run()
			elapsed := time.Since(start)
			if cmd.ProcessState == nil {
				t.Fatal(err)
			}
			if code := cmd.ProcessState.ExitCode(); code != tc.exit || stdout.String() != wantOut || stderr.String() != wantErr {
				t.Fatalf("bootstrap %s %s: exit %d (%v) stdout %q stderr %q", tc.harness, tc.fixture, code, err, stdout.String(), stderr.String())
			}
			samples = append(samples, elapsed)
		}
		summarizeHookBudget(t, "bootstrap locked "+string(tc.harness)+" "+tc.event, samples, true)
	}
	if got, err := os.ReadFile(fetched); err == nil {
		t.Fatalf("bootstrap.sh ran %q", got)
	}
	t.Logf("bootstrap.sh hook cached binary %d bytes", len(raw))
}

func hookColdOutput(t *testing.T, tc hookColdCase) (string, string) {
	t.Helper()
	switch tc.harness {
	case model.HarnessClaude:
		return claudeDeny(pipeReason), pipeReason + "\n"
	case model.HarnessCursor:
		return `{"permission":"allow"}` + "\n", ""
	case model.HarnessCopilot:
		return "", pipeReason + "\n"
	default:
		t.Fatalf("no hook cold-start output for %s", tc.harness)
		return "", ""
	}
}
