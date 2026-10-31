package adapters

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// MaxConfigFileBytes is the default per-file cap for configuration reads.
const MaxConfigFileBytes int64 = 1 << 20

var (
	// ErrUnsafePath reports a path that is absolute, contains a ".."
	// segment, or resolves outside the reader's root.
	ErrUnsafePath = errors.New("unsafe path")
	// ErrNotRegular reports a FIFO, device, socket, or directory where a
	// regular file was expected.
	ErrNotRegular = errors.New("not a regular file")
	// ErrFileTooBig reports a file larger than the caller's cap.
	ErrFileTooBig = errors.New("file exceeds size limit")
)

// SafeReader reads files below one root directory. Every repository file is
// treated as attacker-controlled:
//
//   - names must be slash-separated, relative, and free of ".." segments;
//   - resolution goes through os.Root, so a symlink (in any path component,
//     including one swapped in concurrently) can only resolve to a location
//     inside the root; anything else fails;
//   - files are opened with O_NONBLOCK and their type is checked with fstat
//     on the opened descriptor, so a FIFO or device swapped in after a check
//     is rejected instead of blocking or streaming forever;
//   - reads stop at the caller's byte cap.
//
// Hardlinks cannot be distinguished from ordinary files: a hardlink inside
// the root to a file elsewhere on the same filesystem is read like any other
// file. Creating one requires write access to the target's filesystem, which
// a cloned repository does not grant.
type SafeReader struct {
	root *os.Root
}

// NewSafeReader opens dir as the confinement root.
func NewSafeReader(dir string) (*SafeReader, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open root: %w", plainError(err))
	}
	return &SafeReader{root: root}, nil
}

// Close releases the root.
func (r *SafeReader) Close() error { return r.root.Close() }

// ReadFile reads the regular file name, at most limit bytes.
func (r *SafeReader) ReadFile(name string, limit int64) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	info, err := r.root.Lstat(name)
	if err != nil {
		return nil, rootError(err)
	}
	if info.Mode()&fs.ModeSymlink == 0 && !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	file, err := r.root.OpenFile(name, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, rootError(err)
	}
	defer func() { _ = file.Close() }()
	return readRegular(file, limit)
}

// Stat follows symlinks inside the root and returns the target's info.
func (r *SafeReader) Stat(name string) (fs.FileInfo, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	info, err := r.root.Stat(name)
	if err != nil {
		return nil, rootError(err)
	}
	return info, nil
}

// ReadDir lists at most limit entries of directory name. "." is the root.
// It reports truncated when the directory holds more entries.
func (r *SafeReader) ReadDir(name string, limit int) (entries []fs.DirEntry, truncated bool, err error) {
	if name != "." {
		if err := checkName(name); err != nil {
			return nil, false, err
		}
	}
	dir, err := r.root.OpenFile(name, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, false, rootError(err)
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Stat()
	if err != nil {
		return nil, false, plainError(err)
	}
	if !info.IsDir() {
		return nil, false, ErrNotRegular
	}
	entries, err = dir.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, plainError(err)
	}
	if len(entries) > limit {
		return entries[:limit], true, nil
	}
	return entries, false, nil
}

// OpenLocal opens a file outside any repository (user or managed scope).
// Symlinks are followed: confinement applies to repositories, not to the
// user's home or system directories. The file is opened non-blocking and
// must be a regular file according to fstat on the opened descriptor.
func OpenLocal(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, plainError(err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, plainError(err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrNotRegular
	}
	return file, nil
}

// ReadLocal reads a regular file outside any repository, at most limit bytes.
func ReadLocal(name string, limit int64) ([]byte, error) {
	file, err := OpenLocal(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readRegular(file, limit)
}

func readRegular(file *os.File, limit int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, plainError(err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if info.Size() > limit {
		return nil, ErrFileTooBig
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, plainError(err)
	}
	if int64(len(data)) > limit {
		return nil, ErrFileTooBig
	}
	return data, nil
}

func checkName(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) || hasDrive(name) {
		return ErrUnsafePath
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return ErrUnsafePath
		}
	}
	if path.Clean(name) != name {
		return ErrUnsafePath
	}
	return nil
}

func hasDrive(name string) bool {
	return len(name) >= 2 && name[1] == ':' && (name[0]|0x20) >= 'a' && (name[0]|0x20) <= 'z'
}

// rootError maps an os.Root escape to ErrUnsafePath and strips the path
// from other errors, so callers can prefix their own logical path.
func rootError(err error) error {
	err = plainError(err)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		return err
	}
	if strings.Contains(err.Error(), "escapes from parent") || strings.Contains(err.Error(), "too many levels of symbolic links") {
		return ErrUnsafePath
	}
	return err
}

// plainError drops the absolute path an *fs.PathError carries.
func plainError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}
