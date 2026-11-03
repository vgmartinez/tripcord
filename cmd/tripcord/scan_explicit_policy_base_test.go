package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// ciPolicyRel is an explicit --policy path inside the repository,
// distinct from the implicit .tripcord/policy.yaml, so these tests
// exercise the --policy flag rather than the default file.
const ciPolicyRel = ".tripcord/ci-policy.yaml"

// TestScanSinceExplicitPolicyInsideRepoReadsFromBase is item (c): an
// explicit --policy file inside the repository must be read from the
// base revision when comparing with one, the same as the implicit
// .tripcord/policy.yaml, so the change under review cannot pick its
// own weaker copy of the file it names on the command line either.
func TestScanSinceExplicitPolicyInsideRepoReadsFromBase(t *testing.T) {
	repo := embeddedBase(t)
	writeTestFile(t, repo, ciPolicyRel, "version: 1\nmode: enforce\nfail-on: high\n")
	commitAll(t, repo)
	removeEmbedGuard(t, repo)
	writeTestFile(t, repo, ciPolicyRel, "version: 1\nmode: audit\n")
	commitAll(t, repo)
	abs := filepath.Join(repo, filepath.FromSlash(ciPolicyRel))
	for _, args := range [][]string{
		{"scan", "--format", "json", "--policy", abs, "--since", "HEAD~1", repo},
		{"scan", "--format", "json", "--policy", abs, "--base", "HEAD~1", repo},
	} {
		code, stdout, stderr := runCLI(t, args...)
		if code != int(exitcode.Findings) {
			t.Fatalf("%v: the change's own audit policy must not silence the scan: exit %d\n%s%s", args[1:], code, stdout, stderr)
		}
	}
}

// TestScanSinceExplicitPolicyOutsideRepoIsUsedAsGiven is the other
// half of item (c)'s boundary: an explicit --policy path outside the
// repository is a shared, machine-local, or managed file the
// repository does not control, so it is read as given from the
// filesystem, unaffected by any base revision, the same as without a
// base at all.
func TestScanSinceExplicitPolicyOutsideRepoIsUsedAsGiven(t *testing.T) {
	repo := embeddedBase(t)
	removeEmbedGuard(t, repo)
	commitAll(t, repo)
	outside := filepath.Join(t.TempDir(), "machine-policy.yaml")
	writeTestFile(t, filepath.Dir(outside), filepath.Base(outside), "version: 1\nmode: audit\n")
	code, stdout, stderr := runCLI(t, "scan", "--format", "json", "--policy", outside, "--since", "HEAD~1", repo)
	if code != int(exitcode.OK) {
		t.Fatalf("an outside-repo policy is used as given, not read from the base: exit %d\n%s%s", code, stdout, stderr)
	}
}

// TestScanSinceExplicitPolicyMissingFromBaseIsConfigError checks that
// an explicit --policy path inside the repository that does not exist
// in the base revision is a configuration error (exit 3), not silently
// read from the head's working tree instead.
func TestScanSinceExplicitPolicyMissingFromBaseIsConfigError(t *testing.T) {
	repo := embeddedBase(t)
	writeTestFile(t, repo, ciPolicyRel, "version: 1\nmode: enforce\n")
	commitAll(t, repo)
	abs := filepath.Join(repo, filepath.FromSlash(ciPolicyRel))
	code, _, stderr := runCLI(t, "scan", "--policy", abs, "--since", "HEAD~1", repo)
	if code != int(exitcode.Config) {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if want := "does not exist in base"; !strings.Contains(stderr, want) {
		t.Fatalf("stderr %q does not contain %q", stderr, want)
	}
}
