package adapters

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newReader(t *testing.T, root string) *SafeReader {
	t.Helper()
	reader, err := NewSafeReader(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSafeReaderRejectsTraversalAndAbsolute(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, filepath.Join(root, "a", "b.json"), "{}")
	reader := newReader(t, root)
	outside := filepath.Join(t.TempDir(), "x.json")
	write(t, outside, "{}")
	for _, name := range []string{"../x.json", "a/../a/b.json", "a/./b.json", "/etc/passwd", filepath.ToSlash(outside), `a\b.json`, "C:/x.json", ""} {
		if _, err := reader.ReadFile(name, MaxConfigFileBytes); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("ReadFile(%q) error = %v, want ErrUnsafePath", name, err)
		}
	}
	if _, err := reader.ReadFile("a/b.json", MaxConfigFileBytes); err != nil {
		t.Fatalf("ReadFile(a/b.json) = %v", err)
	}
}

func TestSafeReaderSymlinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outsideDir := t.TempDir()
	write(t, filepath.Join(outsideDir, "secret.json"), "outside")
	write(t, filepath.Join(root, "inside", "real.json"), "inside")
	links := map[string]string{
		"escape.json":   filepath.Join(outsideDir, "secret.json"),
		"escape-dir":    outsideDir,
		"relative.json": "../" + filepath.Base(outsideDir) + "/secret.json",
		"inside-link":   "inside",
		"in-file.json":  "inside/real.json",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	reader := newReader(t, root)
	for _, name := range []string{"escape.json", "escape-dir/secret.json", "relative.json"} {
		data, err := reader.ReadFile(name, MaxConfigFileBytes)
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("ReadFile(%q) = %q, %v; want ErrUnsafePath", name, data, err)
		}
	}
	for _, name := range []string{"inside-link/real.json", "in-file.json"} {
		data, err := reader.ReadFile(name, MaxConfigFileBytes)
		if err != nil || string(data) != "inside" {
			t.Errorf("ReadFile(%q) = %q, %v; want in-root target", name, data, err)
		}
	}
}

func TestSafeReaderSizeCap(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, filepath.Join(root, "large.json"), string(bytes.Repeat([]byte("x"), int(MaxConfigFileBytes)+1)))
	write(t, filepath.Join(root, "exact.json"), string(bytes.Repeat([]byte("x"), int(MaxConfigFileBytes))))
	reader := newReader(t, root)
	if _, err := reader.ReadFile("large.json", MaxConfigFileBytes); !errors.Is(err, ErrFileTooBig) {
		t.Fatalf("large: %v, want ErrFileTooBig", err)
	}
	if data, err := reader.ReadFile("exact.json", MaxConfigFileBytes); err != nil || int64(len(data)) != MaxConfigFileBytes {
		t.Fatalf("exact: %d bytes, %v", len(data), err)
	}
	if _, err := ReadLocal(filepath.Join(root, "large.json"), MaxConfigFileBytes); !errors.Is(err, ErrFileTooBig) {
		t.Fatalf("ReadLocal large: %v, want ErrFileTooBig", err)
	}
}

func TestSafeReaderErrorsOmitAbsolutePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	reader := newReader(t, root)
	for _, err := range []error{
		func() error { _, err := reader.ReadFile("missing.json", 10); return err }(),
		func() error { _, err := ReadLocal(filepath.Join(root, "missing.json"), 10); return err }(),
	} {
		if err == nil || bytes.Contains([]byte(err.Error()), []byte(root)) {
			t.Fatalf("error %v leaks the absolute path", err)
		}
	}
}
