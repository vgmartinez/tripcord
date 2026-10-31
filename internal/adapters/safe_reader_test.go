package adapters

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeReaderRejectsHostilePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	reader, err := NewSafeReader(root)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "nested.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(root, "escape-dir")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, name := range []string{"escape.json", "escape-dir/nested.json", "../outside.json", "a/../b.json", outside} {
		t.Run(name, func(t *testing.T) {
			_, err := reader.ReadFile(name)
			if !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("ReadFile(%q) error = %v, want ErrUnsafePath", name, err)
			}
		})
	}
}

func TestSafeReaderRejectsOversizedFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.json"), bytes.Repeat([]byte("x"), int(MaxConfigFileBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewSafeReader(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadFile("large.json")
	if !errors.Is(err, ErrFileTooBig) {
		t.Fatalf("ReadFile error = %v, want ErrFileTooBig", err)
	}
}
