package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/model"
)

// TestVersionSkewCIScanner runs the scanner CI really runs on a fresh
// embed: the generated tripcord.yml calls tripcord-pr.yml@WorkflowPin,
// which pins the composite action at some commit A, which builds
// cmd/tripcord from A's source. This test builds that same binary and
// scans what this tree's init writes, with GITHUB_ACTIONS=true. Any high
// TC-CFG-016 finding fails it.
//
// It runs only under the release gate (TRIPCORD_RELEASE_GATE=1, make
// release-gate), and there it fails until the action repin and the
// WorkflowPin repin land: today A predates this tree's templates, and
// reports seven highs: six "written by an older Tripcord" (Claude
// SessionStart and PreToolUse, Cursor and Copilot preToolUse,
// tripcord.yml, bootstrap.sh) and a missing copilot-setup-steps.yml,
// which init writes only with --cloud-setup. That failure is the
// point: no tag ships an embed its own CI flags. By the end of PR 3
// this test must report 0 high, including copilot-setup-steps.yml on
// an embed written without --cloud-setup. Moving it from the release
// gate into per-pull-request CI, passing, is
// https://github.com/vgmartinez/tripcord/issues/119.
func TestVersionSkewCIScanner(t *testing.T) {
	if os.Getenv("TRIPCORD_RELEASE_GATE") != "1" {
		t.Log("release gate not requested; set TRIPCORD_RELEASE_GATE=1 (make release-gate) to build and run the CI scanner the generated tripcord.yml pins")
		return
	}
	root := filepath.Join("..", "..")
	if reason, _ := pinHistoryProblem(root); reason != "" {
		t.Fatalf("release gate: %s", reason)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("release gate: go is not installed: %v", err)
	}
	repo := gitRepo(t)
	if code, _, stderr := runCLI(t, embedArgs(repo)...); code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	workflow, err := gitShowAt(t, embedded.WorkflowPin, ".github/workflows/tripcord-pr.yml")
	if err != nil {
		t.Fatalf("release gate: tripcord-pr.yml@%s: %v", embedded.WorkflowPin[:7], err)
	}
	actions := slices.Compact(slices.Sorted(slices.Values(actionPins(t, "tripcord-pr.yml@"+embedded.WorkflowPin[:7], workflow))))
	for _, action := range actions {
		t.Run(action[:12], func(t *testing.T) {
			bin := buildAt(t, root, action)
			args := []string{"scan", repo, "--format", "json"}
			help, _ := exec.Command(bin, "scan", "--help").CombinedOutput()
			if bytes.Contains(help, []byte("-executing-workflow")) {
				args = append(args, "--executing-workflow", "vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@"+embedded.WorkflowPin)
			}
			cmd := exec.Command(bin, args...)
			cmd.Env = append(os.Environ(), "GITHUB_ACTIONS=true")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if err != nil && (!errors.As(err, &exit) || exit.ExitCode() > 1) {
				t.Fatalf("scan with the action at %s: %v: %s", action[:7], err, stderr.String())
			}
			var highs []string
			for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
				if line == "" {
					continue
				}
				var f model.Finding
				if err := json.Unmarshal([]byte(line), &f); err != nil {
					t.Fatalf("scan output %q: %v", line, err)
				}
				if f.Rule == "TC-CFG-016" && (f.Severity == model.SeverityHigh || f.Severity == model.SeverityCritical) {
					highs = append(highs, f.Location.Path+": "+f.Title)
				}
			}
			if len(highs) > 0 {
				t.Errorf("the CI scanner (action %s, through tripcord-pr.yml@%s) reports %d high TC-CFG-016 findings on a fresh embed; repin the action, then WorkflowPin:\n  %s",
					action[:7], embedded.WorkflowPin[:7], len(highs), strings.Join(highs, "\n  "))
			}
		})
	}
}

// buildAt builds cmd/tripcord from rev's tree the way the composite
// action does: an archive with no .git, CGO_ENABLED=0, -trimpath.
func buildAt(t *testing.T, root, rev string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := exec.Command("git", "--no-optional-locks", "archive", "--format=tar", rev)
	archive.Dir = root
	tarball, err := archive.Output()
	if err != nil {
		t.Fatalf("git archive %s: %v", rev, err)
	}
	untar := exec.Command("tar", "-x", "-C", src)
	untar.Stdin = bytes.NewReader(tarball)
	if out, err := untar.CombinedOutput(); err != nil {
		t.Fatalf("tar: %v: %s", err, out)
	}
	bin := filepath.Join(dir, "tripcord")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/tripcord")
	build.Dir = src
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build at %s: %v: %s", rev, err, out)
	}
	return bin
}
