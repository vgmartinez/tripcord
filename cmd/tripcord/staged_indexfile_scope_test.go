package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

// TestScanIgnoresStrayGitIndexFile proves that an ordinary (non-staged)
// scan is unaffected by a GIT_INDEX_FILE left over in the process
// environment, even one pointing at a file that does not exist.
// gitrun.Env drops GIT_INDEX_FILE globally; only the staged scan path
// opts specific git calls into seeing it (see gitrun.IndexEnv), read
// once from the environment at the point where --staged already knows
// it may be running inside a git hook.
func TestScanIgnoresStrayGitIndexFile(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".claude/settings.json": `{"permissions":{"defaultMode":"bypassPermissions"}}`,
	})

	scan := func() string {
		var stdout, stderr bytes.Buffer
		code := runScan([]string{"--format", "json", root}, &stdout, &stderr)
		return fmt.Sprintf("exit %d\n%s%s", code, stdout.String(), stderr.String())
	}

	baseline := scan()

	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "does-not-exist.lock"))
	withStray := scan()

	if baseline != withStray {
		t.Fatalf("a stray GIT_INDEX_FILE changed a normal scan's output:\nwithout:\n%s\nwith:\n%s", baseline, withStray)
	}
}
