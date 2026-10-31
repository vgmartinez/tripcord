//go:build !windows

package adapters

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSafeReaderRejectsSpecialFilesAndLinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	fifo := filepath.Join(root, "config.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", filepath.Join(root, "zero.json")); err != nil {
		t.Fatal(err)
	}
	reader, err := NewSafeReader(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.fifo", "zero.json"} {
		t.Run(name, func(t *testing.T) {
			_, err := reader.ReadFile(name)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("ReadFile(%q) error = %v, want ErrUnsafePath", name, err)
			}
		})
	}
}
