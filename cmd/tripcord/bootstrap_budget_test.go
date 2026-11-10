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

// TestBootstrapHookLatencyBudget times bash bootstrap.sh hook against
// the direct hook in the same run, with the same locked policy and
// harness. The pinned binary is already in a local cache, and
// bootstrap.sh install records it before the measured loop. The measured
// command's PATH is download stubs plus /usr/bin and /bin, and those
// stubs must not run. End-to-end p95 is 35 ms. The overhead, bootstrap
// minus the direct sample beside it, has p95 of 10 ms.
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
	env := []string{
		"PATH=" + toolPath,
		"HOME=" + home,
		"XDG_CACHE_HOME=" + cache,
		"TMPDIR=" + tmp,
		"CLAUDE_PROJECT_DIR=" + root,
		"CURSOR_PROJECT_DIR=" + root,
		"CI=true",
	}
	// install records the cached binary before the measured loop, so
	// every timed hook takes the fast path instead of the first run
	// paying for the copy and the hash. The project is not a full
	// embed, so the scan that install runs afterwards reports
	// TC-CFG-016 and exits 1. The record is what the loop needs.
	marker := filepath.Join(filepath.Dir(cached), "verified")
	if _, code, stdout, stderr, err := timeHook(t, env, root, bytes.NewReader(nil), "bash", scriptPath, "install"); code == 2 {
		t.Fatalf("bootstrap install: exit %d (%v) stdout %q stderr %q", code, err, stdout, stderr)
	}
	if info, err := os.Stat(marker); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("bootstrap install did not record %s: %v", marker, err)
	}

	for _, tc := range hookColdCases() {
		input := adapterFixture(t, tc.harness, tc.fixture)
		wantOut, wantErr := hookColdOutput(t, tc)
		direct := make([]time.Duration, 0, hookColdStartRuns+5)
		bootstrap := make([]time.Duration, 0, hookColdStartRuns+5)
		for range hookColdStartRuns + 5 {
			elapsed, code, stdout, stderr, err := timeHook(t, env, root, bytes.NewReader(input), cached, "hook", "--harness", string(tc.harness), "--event", tc.event, "--on-failure", "block")
			if code != tc.exit || stdout != wantOut || stderr != wantErr {
				t.Fatalf("direct %s %s: exit %d (%v) stdout %q stderr %q", tc.harness, tc.fixture, code, err, stdout, stderr)
			}
			direct = append(direct, elapsed)
			elapsed, code, stdout, stderr, err = timeHook(t, env, root, bytes.NewReader(input), "bash", scriptPath, "hook", "--harness", string(tc.harness), "--event", tc.event, "--on-failure", "block")
			if code != tc.exit || stdout != wantOut || stderr != wantErr {
				t.Fatalf("bootstrap %s %s: exit %d (%v) stdout %q stderr %q", tc.harness, tc.fixture, code, err, stdout, stderr)
			}
			bootstrap = append(bootstrap, elapsed)
		}
		overhead := make([]time.Duration, len(bootstrap))
		for i := range bootstrap {
			overhead[i] = bootstrap[i] - direct[i]
		}
		label := string(tc.harness) + " " + tc.event
		summarizeHookBudget(t, "direct locked "+label, direct, hookColdStartBudget)
		summarizeHookBudget(t, "bootstrap locked "+label, bootstrap, bootstrapHookBudget)
		summarizeHookBudget(t, "bootstrap overhead "+label, overhead, bootstrapOverheadBudget)
	}
	if got, err := os.ReadFile(fetched); err == nil {
		t.Fatalf("bootstrap.sh ran %q", got)
	}
	t.Logf("bootstrap.sh hook cached binary %d bytes", len(raw))
}

func timeHook(t *testing.T, env []string, dir string, stdin *bytes.Reader, argv ...string) (time.Duration, int, string, string, error) {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)
	if cmd.ProcessState == nil {
		t.Fatal(err)
	}
	return elapsed, cmd.ProcessState.ExitCode(), stdout.String(), stderr.String(), err
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
