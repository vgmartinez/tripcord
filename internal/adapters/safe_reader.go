package adapters

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxConfigFileBytes is the largest configuration file an adapter may read.
const MaxConfigFileBytes int64 = 1 << 20

var (
	ErrUnsafePath = errors.New("adapter reader: unsafe path")
	ErrFileTooBig = errors.New("adapter reader: file exceeds size limit")
)

// SafeReader reads regular files rooted below Root. Paths supplied to ReadFile
// are repository-relative, must not contain a ".." segment, and must not be
// absolute. Symlinks are rejected (including parent-directory symlinks), so a
// hostile repository cannot redirect an adapter to files outside its root.
// FIFOs, devices, sockets, and directories are rejected without opening them.
type SafeReader struct {
	root string
}

// NewSafeReader creates a reader rooted at root.
func NewSafeReader(root string) (*SafeReader, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("adapter reader: inspect root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: root must be a non-symlink directory", ErrUnsafePath)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("adapter reader: resolve root: %w", err)
	}
	return &SafeReader{root: absolute}, nil
}

// ReadFile reads one regular file, enforcing MaxConfigFileBytes.
func (r *SafeReader) ReadFile(name string) ([]byte, error) {
	path, err := r.resolve(name)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, name)
	}
	if info.Size() > MaxConfigFileBytes {
		return nil, fmt.Errorf("%w: %s", ErrFileTooBig, name)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%w: %s changed while opening", ErrUnsafePath, name)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxConfigFileBytes {
		return nil, fmt.Errorf("%w: %s", ErrFileTooBig, name)
	}
	return data, nil
}

// Exists reports whether a safe regular file exists at name.
func (r *SafeReader) Exists(name string) bool {
	path, err := r.resolve(name)
	if err != nil {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func (r *SafeReader) resolve(name string) (string, error) {
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("%w: absolute path %q", ErrUnsafePath, name)
	}
	for _, segment := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return "", fmt.Errorf("%w: traversal path %q", ErrUnsafePath, name)
		}
	}
	name = filepath.Clean(filepath.FromSlash(name))
	if name == "." || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: traversal path %q", ErrUnsafePath, name)
	}
	path := filepath.Join(r.root, name)
	current := r.root
	segments := strings.Split(name, string(filepath.Separator))
	for _, segment := range segments[:len(segments)-1] {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("%w: parent %q", ErrUnsafePath, current)
		}
	}
	return path, nil
}
