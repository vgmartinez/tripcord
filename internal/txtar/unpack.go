package txtar

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// Reasons Rel and Write reject a member name.
var (
	ErrEmpty     = errors.New("empty name")
	ErrNUL       = errors.New("NUL byte")
	ErrBackslash = errors.New("backslash")
	ErrAbsolute  = errors.New("absolute path")
	ErrDotDot    = errors.New(".. segment")
	ErrOutside   = errors.New("resolves outside the directory")
	ErrDuplicate = errors.New("duplicate name")
)

// Rel returns name as a cleaned slash-separated path that stays inside a
// destination directory. It rejects an empty name, a NUL, a backslash, an
// absolute path, a ".." segment, and a path that still climbs out after
// those checks.
func Rel(name string) (string, error) {
	switch {
	case name == "" || strings.TrimSpace(name) == "" || name == ".":
		return "", ErrEmpty
	case strings.ContainsRune(name, 0):
		return "", ErrNUL
	case strings.ContainsRune(name, '\\'):
		return "", ErrBackslash
	case strings.HasPrefix(name, "/") || filepath.IsAbs(name) || hasDrive(name):
		return "", ErrAbsolute
	}
	parts := strings.Split(name, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "":
			return "", ErrEmpty
		case ".":
			continue
		case "..":
			return "", ErrDotDot
		default:
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return "", ErrEmpty
	}
	rel := path.Join(clean...)
	if rel == ".." || strings.HasPrefix(rel, "../") || path.IsAbs(rel) {
		return "", ErrOutside
	}
	return rel, nil
}

func hasDrive(name string) bool {
	return len(name) >= 2 && name[1] == ':' && isLetter(name[0])
}

func isLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// Write creates each file of a under dir. dir must already exist. Every
// name is checked before anything is written. Members are regular files
// mode 0644. A symlink already occupying a path is not followed.
func Write(dir string, a *Archive) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	dests := make([]string, len(a.Files))
	seen := make(map[string]struct{}, len(a.Files))
	for i, f := range a.Files {
		rel, err := Rel(f.Name)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if _, ok := seen[rel]; ok {
			return fmt.Errorf("%s: %w", f.Name, ErrDuplicate)
		}
		seen[rel] = struct{}{}
		dest := filepath.Join(abs, filepath.FromSlash(rel))
		if err := inside(abs, dest); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		dests[i] = dest
	}
	for i, f := range a.Files {
		if err := writeFile(abs, dests[i], f.Data); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	return nil
}

// Unpack writes a under a fresh t.TempDir and returns that directory.
func Unpack(t *testing.T, a *Archive) string {
	t.Helper()
	dir := t.TempDir()
	if err := Write(dir, a); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFile(root, dest string, data []byte) error {
	if err := mkdirUnder(root, filepath.Dir(dest)); err != nil {
		return err
	}
	info, err := os.Lstat(dest)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return ErrOutside
	case err == nil:
		return fmt.Errorf("already exists")
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

// mkdirUnder creates dir and every missing parent, all inside root.
// An existing symlink is not followed.
func mkdirUnder(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	if !stays(rel) {
		return ErrOutside
	}
	cur := root
	if rel == "." {
		return nil
	}
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, seg)
		info, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrOutside
		}
	}
	return nil
}

func inside(root, dest string) error {
	rel, err := filepath.Rel(root, dest)
	if err != nil {
		return err
	}
	if !stays(rel) {
		return ErrOutside
	}
	return nil
}

func stays(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
