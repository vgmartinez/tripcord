package main

import (
	"bytes"
	"os/exec"
	"slices"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/policy"
)

const titleLocalPolicy = "A committed policy.local.yaml overrides everyone's policy"

// commitLocalPolicy writes .tripcord/policy.local.yaml and commits it
// along with anything else already changed in repo. init --embed adds
// the file to .gitignore, so it needs a forced add; commitAll's
// `git add -A` alone would silently skip it.
func commitLocalPolicy(t *testing.T, repo, content string) {
	t.Helper()
	writeTestFile(t, repo, policy.LocalFile, content)
	runGit(t, repo, "add", "-A")
	runGit(t, repo, "add", "-f", "--", policy.LocalFile)
	runGit(t, repo, "commit", "-m", "change")
}

// TestScanDetectsTrackedPolicyLocal is the reviewer's B1 repro: a
// tracked .tripcord/policy.local.yaml set to a mode that would not fail
// on a high finding (here, audit) must not silence the scan of the
// removal committed alongside it, in plain scan, --since, or --base
// mode. The staged repro gets its own test below, because it needs the
// file committed earlier and the removal only staged.
func TestScanDetectsTrackedPolicyLocal(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		repo := embeddedBase(t)
		commitLocalPolicy(t, repo, "version: 1\nmode: audit\n")
		code, got := guardFindings(t, repo)
		if code != int(exitcode.Findings) || !slices.Contains(got, guardFinding{policy.LocalFile, titleLocalPolicy}) {
			t.Fatalf("exit %d: %v", code, got)
		}
	})
	t.Run("since and base", func(t *testing.T) {
		repo := embeddedBase(t)
		removeEmbedGuard(t, repo)
		commitLocalPolicy(t, repo, "version: 1\nmode: audit\n")
		for _, args := range [][]string{{repo, "--since", "HEAD~1"}, {repo, "--base", "HEAD~1"}} {
			code, got := guardFindings(t, args...)
			if code != int(exitcode.Findings) ||
				!slices.Contains(got, guardFinding{embedded.BootstrapPath, titleRemoved}) ||
				!slices.Contains(got, guardFinding{policy.LocalFile, titleLocalPolicy}) {
				t.Fatalf("scan %v: exit %d: %v", args[1:], code, got)
			}
		}
	})
}

// TestStagedScanDetectsTrackedPolicyLocal is the reviewer's literal
// staged repro: a policy.local.yaml already committed to the branch (as
// a bad merge, before this fix, would leave it) sets mode: audit. A
// developer then stages `git rm bootstrap.sh` and runs `scan --staged`,
// expecting the pre-commit hook to block it; the already-committed
// policy.local.yaml must not silence that scan of its own effect.
func TestStagedScanDetectsTrackedPolicyLocal(t *testing.T) {
	bin := buildStagedBinary(t)
	repo := embeddedBase(t)
	commitLocalPolicy(t, repo, "version: 1\nmode: audit\n")
	runGit(t, repo, "rm", embedded.BootstrapPath)
	cmd := exec.Command(bin, "scan", "--format", "json", "--staged")
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("staged scan: want a non-zero exit, got 0:\n%s", stdout.String())
	}
	var sawBootstrap, sawPolicyLocal bool
	for _, f := range parseFindings(t, stdout.Bytes()) {
		if f.Rule != "TC-CFG-016" {
			continue
		}
		switch f.Path {
		case embedded.BootstrapPath:
			sawBootstrap = true
		case policy.LocalFile:
			sawPolicyLocal = true
		}
	}
	if !sawBootstrap || !sawPolicyLocal {
		t.Fatalf("staged scan: bootstrap=%v policyLocal=%v\n%s%s", sawBootstrap, sawPolicyLocal, stdout.String(), stderr.String())
	}
}

// TestScanStagedPolicyLocalDoesNotSilenceOtherFindings checks that a
// policy.local.yaml staged, but not committed, is caught the same way:
// the gate for TC-CFG-016's own policyLocal check is "tracked or
// staged", not "committed".
func TestScanStagedPolicyLocalDoesNotSilenceOtherFindings(t *testing.T) {
	bin := buildStagedBinary(t)
	repo := embeddedBase(t)
	writeTestFile(t, repo, policy.LocalFile, "version: 1\nmode: audit\n")
	runGit(t, repo, "add", "-f", "--", policy.LocalFile)
	runGit(t, repo, "rm", embedded.BootstrapPath)
	cmd := exec.Command(bin, "scan", "--format", "json", "--staged")
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("staged scan: want a non-zero exit, got 0:\n%s", stdout.String())
	}
	var sawBootstrap, sawPolicyLocal bool
	for _, f := range parseFindings(t, stdout.Bytes()) {
		if f.Rule != "TC-CFG-016" {
			continue
		}
		switch f.Path {
		case embedded.BootstrapPath:
			sawBootstrap = true
		case policy.LocalFile:
			sawPolicyLocal = true
		}
	}
	if !sawBootstrap || !sawPolicyLocal {
		t.Fatalf("staged scan: bootstrap=%v policyLocal=%v\n%s%s", sawBootstrap, sawPolicyLocal, stdout.String(), stderr.String())
	}
}
