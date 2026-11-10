//go:build unix

package scriptcheck

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDotenvSymlinkOutside(t *testing.T) {
	const command = "set -a && source .env && npx -y pkg"
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(outside, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	assertRepoScript(t, root, command, false)
}

func TestDotenvUnreadable(t *testing.T) {
	const command = "set -a && source .env && npx -y pkg"
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if os.Geteuid() == 0 {
		if err := syscall.Seteuid(65534); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = syscall.Seteuid(0) })
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Fatal("dotenv is still readable")
	}
	assertRepoScript(t, root, command, false)
}
