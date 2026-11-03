package main

import (
	"strings"
	"testing"
)

// TestScanStagedDeletionReportsChecksumFile reproduces one of the hunt's
// 50 deletion misses: deleting a committed sums file a setup command
// checks with sha256sum -c changes TC-CFG-009's verdict from clean to a
// new HIGH finding, but pre-commit never passed the deleted path as a
// filename, and scriptcheck.Annotate's ChecksumFiles only names a sums
// file that still exists. Both are fixed: the hook computes its own
// change set including deletions, and SourcePaths now names the sums
// file whether or not it resolved (see scriptcheck.ItemReferencedPaths).
func TestScanStagedDeletionReportsChecksumFile(t *testing.T) {
	bin := buildStagedBinary(t)
	repo := stagedRepo(t)
	stagedWrite(t, repo, ".github/workflows/copilot-setup-steps.yml", "on: workflow_dispatch\njobs:\n  copilot-setup-steps:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: step0\n        run: \"curl -fsSLo t.sh https://get.tools.example.invalid/t.sh && sha256sum -c t.sh.sha256 && sh t.sh\"\n")
	stagedWrite(t, repo, "t.sh.sha256", strings.Repeat("ab", 32)+"  t.sh\n")
	stagedGit(t, repo, "add", ".")
	stagedGit(t, repo, "commit", "-qm", "checksum-verified setup")

	if code, out := stagedScan(t, bin, repo); code != 0 {
		t.Fatalf("checksum file present = %d, want 0\n%s", code, out)
	}

	stagedGit(t, repo, "rm", "-q", "t.sh.sha256")
	if code, out := stagedScan(t, bin, repo); code != 1 || !strings.Contains(out, "TC-CFG-009") {
		t.Fatalf("deleted checksum file, no paths = %d, want 1 with TC-CFG-009\n%s", code, out)
	}
	if code, out := stagedScan(t, bin, repo, "t.sh.sha256"); code != 1 || !strings.Contains(out, "TC-CFG-009") {
		t.Fatalf("deleted checksum file, explicit path = %d, want 1 with TC-CFG-009\n%s", code, out)
	}
}

// TestScanStagedDeletionReportsReferencedScript covers the hunt's other
// deletion example: deleting a hook script a settings.json entry
// references by project-relative path makes TC-CFG-006 report it as
// missing, but the deleted path was never passed by pre-commit, so the
// hook's own self-computed change set must now include it.
func TestScanStagedDeletionReportsReferencedScript(t *testing.T) {
	bin := buildStagedBinary(t)
	repo := stagedRepo(t)
	stagedWrite(t, repo, ".claude/settings.json", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/guard.sh"}]}]}}`)
	stagedWrite(t, repo, ".claude/hooks/guard.sh", "#!/bin/sh\necho guard\n")
	stagedGit(t, repo, "add", ".")
	stagedGit(t, repo, "commit", "-qm", "hook with a committed script")

	if code, out := stagedScan(t, bin, repo); code != 0 {
		t.Fatalf("script present = %d, want 0\n%s", code, out)
	}

	stagedGit(t, repo, "rm", "-q", ".claude/hooks/guard.sh")
	_, out := stagedScan(t, bin, repo)
	if !strings.Contains(out, "TC-CFG-006") || !strings.Contains(out, "missing") {
		t.Fatalf("deleted referenced script, no paths: want TC-CFG-006 missing\n%s", out)
	}
	_, out = stagedScan(t, bin, repo, ".claude/hooks/guard.sh")
	if !strings.Contains(out, "TC-CFG-006") || !strings.Contains(out, "missing") {
		t.Fatalf("deleted referenced script, explicit path: want TC-CFG-006 missing\n%s", out)
	}
}
