//go:build unix

package claude

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSpecialFilesAreReportedNotRead(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"a":{"command":"a"}}}`)
	if err := syscall.Mkfifo(filepath.Join(root, ".claude", "settings.json"), 0o600); err != nil {
		if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(root, ".claude", "settings.json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	got := discover(t, New(Options{}), root)
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	if !containsDiag(got, ".claude/settings.json: not a regular file") || !containsDiag(got, "CLAUDE.md: symlink resolves outside the repository") {
		t.Fatalf("diagnostics = %q", got.Diagnostics)
	}
}
