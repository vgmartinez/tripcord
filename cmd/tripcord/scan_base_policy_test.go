package main

import (
	"slices"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/policy"
)

const titleWeakened = "This change weakens the Tripcord policy"

// TestScanSinceUsesBasePolicy is the reviewer's repro: the guard removed
// in the same change that sets the policy to audit, or adds a
// policy.local.yaml that does. Either way the head policy would let the
// scan exit 0 with the removal reported.
func TestScanSinceUsesBasePolicy(t *testing.T) {
	for _, tc := range []struct {
		name, path, content string
		weakened            bool
	}{
		{"repo policy set to audit", policy.RepoFile, "version: 1\nmode: audit\nfail-on: high\n", true},
		{"repo policy fail-on raised", policy.RepoFile, "version: 1\nmode: enforce\nfail-on: critical\n", true},
		{"repo policy exempts TC-CFG-016", policy.RepoFile, "version: 1\nmode: enforce\nfail-on: high\nrules:\n  include: [\"TC-CFG-00*\"]\n", true},
		{"new policy.local.yaml", policy.LocalFile, "version: 1\nmode: audit\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := embeddedBase(t)
			removeEmbedGuard(t, repo)
			writeTestFile(t, repo, tc.path, tc.content)
			commitAll(t, repo)
			for _, args := range [][]string{{repo, "--since", "HEAD~1"}, {repo, "--base", "HEAD~1"}} {
				code, got := guardFindings(t, args...)
				if code != int(exitcode.Findings) || !slices.Contains(got, guardFinding{embedded.BootstrapPath, titleRemoved}) {
					t.Fatalf("scan %v: exit %d: %v", args[1:], code, got)
				}
				if has := slices.Contains(got, guardFinding{policy.RepoFile, titleWeakened}); has != tc.weakened {
					t.Fatalf("scan %v: weakened reported %v, want %v: %v", args[1:], has, tc.weakened, got)
				}
			}
		})
	}
}

func TestScanSinceReportsWeakenedPolicyWithoutEmbed(t *testing.T) {
	repo := gitRepo(t)
	writeTestFile(t, repo, policy.RepoFile, "version: 1\nmode: enforce\nfail-on: high\n")
	commitAll(t, repo)
	writeTestFile(t, repo, policy.RepoFile, "version: 1\nmode: warn\nfail-on: high\n")
	commitAll(t, repo)
	want := []guardFinding{{policy.RepoFile, titleWeakened}}
	if code, got := guardFindings(t, repo, "--since", "HEAD~1"); code != int(exitcode.Findings) || !slices.Equal(got, want) {
		t.Fatalf("exit %d\ngot  %v\nwant %v", code, got, want)
	}
	if code, got := guardFindings(t, repo); code != int(exitcode.OK) || len(got) != 0 {
		t.Fatalf("without a base: exit %d, %v", code, got)
	}
}

func TestScanSinceStricterPolicyIsNotWeakened(t *testing.T) {
	repo := embeddedBase(t)
	writeTestFile(t, repo, policy.RepoFile, "version: 1\nmode: enforce\nfail-on: medium\nlocked:\n  mode: true\n")
	commitAll(t, repo)
	if code, got := guardFindings(t, repo, "--since", "HEAD~1"); code != int(exitcode.OK) || len(got) != 0 {
		t.Fatalf("exit %d: %v", code, got)
	}
}

// TestScanSinceIgnoresHeadPolicyForTheDecision checks that the base's
// policy decides: a head policy in audit mode still fails on the
// removal and on its own weakening.
func TestScanSinceIgnoresHeadPolicyForTheDecision(t *testing.T) {
	repo := embeddedBase(t)
	writeTestFile(t, repo, policy.RepoFile, "version: 1\nmode: audit\n")
	commitAll(t, repo)
	code, stdout, stderr := runCLI(t, "scan", "--format", "json", repo, "--since", "HEAD~1")
	if code != int(exitcode.Findings) {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
	code, got := guardFindings(t, repo)
	if code != int(exitcode.OK) || len(got) != 0 {
		t.Fatalf("without a base the head policy applies: exit %d, %v", code, got)
	}
}
