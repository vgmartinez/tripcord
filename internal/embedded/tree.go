package embedded

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// maxReadBytes caps an existing file init merges into.
const maxReadBytes = 1 << 20

// ErrUnsafePath reports a target init refuses to read or write: a path
// with a symlink in any component, or a component that is not a
// directory or regular file.
var ErrUnsafePath = errors.New("unsafe path")

// tree is the repository root. Every access goes through os.Root, so
// nothing resolves outside it, and init refuses a symlink in any
// component of a target so a link cannot redirect a write either.
type tree struct {
	root *os.Root
}

func openTree(dir string) (*tree, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &tree{root: root}, nil
}

func (t *tree) close() error { return t.root.Close() }

// check walks every component of rel. A symlink is refused, whether it
// resolves inside the repository or outside it; a missing component
// ends the walk, since everything below it will be created.
func (t *tree) check(rel string) (exists bool, mode fs.FileMode, err error) {
	parts := strings.Split(rel, "/")
	for i := range parts {
		prefix := strings.Join(parts[:i+1], "/")
		info, err := t.root.Lstat(prefix)
		if errors.Is(err, fs.ErrNotExist) {
			return false, 0, nil
		}
		if err != nil {
			return false, 0, fmt.Errorf("%s: %w", rel, err)
		}
		last := i == len(parts)-1
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return false, 0, fmt.Errorf("%s: %w: %s is a symlink", rel, ErrUnsafePath, prefix)
		case !last && !info.IsDir():
			return false, 0, fmt.Errorf("%s: %w: %s is not a directory", rel, ErrUnsafePath, prefix)
		case last && !info.Mode().IsRegular():
			return false, 0, fmt.Errorf("%s: %w: not a regular file", rel, ErrUnsafePath)
		case last:
			return true, info.Mode().Perm(), nil
		}
	}
	return false, 0, nil
}

// read returns rel's content, or exists false when it is absent.
func (t *tree) read(rel string) (data []byte, exists bool, mode fs.FileMode, err error) {
	exists, mode, err = t.check(rel)
	if err != nil || !exists {
		return nil, exists, 0, err
	}
	f, err := t.root.Open(rel)
	if err != nil {
		return nil, false, 0, err
	}
	defer func() { _ = f.Close() }()
	data, err = io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil {
		return nil, false, 0, err
	}
	if len(data) > maxReadBytes {
		return nil, false, 0, fmt.Errorf("%s: larger than %d bytes", rel, maxReadBytes)
	}
	return data, true, mode, nil
}

// write replaces rel atomically: a temporary file in the same directory
// is written, synced, and renamed over rel.
func (t *tree) write(rel string, data []byte, mode fs.FileMode) error {
	if _, _, err := t.check(rel); err != nil {
		return err
	}
	dir := path.Dir(rel)
	if dir != "." {
		if err := t.root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if _, _, err := t.check(rel); err != nil {
			return err
		}
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := path.Join(dir, "."+path.Base(rel)+".tripcord-"+hex.EncodeToString(suffix[:]))
	f, err := t.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = t.root.Chmod(tmp, mode)
	}
	if werr == nil {
		werr = t.root.Rename(tmp, rel)
	}
	if werr != nil {
		_ = t.root.Remove(tmp)
		return werr
	}
	return nil
}
