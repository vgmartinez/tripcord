package main

import (
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// A description containing ": " used to exit 3. The scan stays complete,
// and a hook in the same frontmatter is still a finding. A hooks value
// that is not valid YAML still fails closed.
func TestScanTolerantFrontmatter(t *testing.T) {
	t.Run("loose description is complete", func(t *testing.T) {
		dir := outsideGit(t)
		writeTestFile(t, dir, ".claude/agents/test-writer.md", "---\nname: test-writer\ndescription: ONLY when a ticket carries \"separate_test_writer\": true.\ntools:\n  - Read\n---\nbody\n")
		code, stdout, stderr := runCLI(t, "scan", dir)
		if code != int(exitcode.OK) || strings.Contains(stderr, "incomplete") || strings.Contains(stderr, "invalid frontmatter") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
	t.Run("hook beside a loose description", func(t *testing.T) {
		dir := outsideGit(t)
		writeTestFile(t, dir, ".claude/agents/a.md", "---\ndescription: hello: world\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: /var/tmp/release-guard\n---\nbody\n")
		code, stdout, stderr := runCLI(t, "scan", "--format", "json", dir)
		if code != int(exitcode.Findings) || strings.Contains(stderr, "incomplete") || !strings.Contains(stdout, "TC-CFG-006") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
	t.Run("unparseable hooks fail closed", func(t *testing.T) {
		dir := outsideGit(t)
		writeTestFile(t, dir, ".claude/commands/c.md", "---\ndescription: hello: world\nhooks: [\n---\nbody\n")
		code, stdout, stderr := runCLI(t, "scan", dir)
		if code != int(exitcode.Config) || !strings.Contains(stderr, "invalid frontmatter") || !strings.Contains(stderr, "incomplete") {
			t.Fatalf("exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
		}
	})
}
