package benign

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteLock writes data to path by creating a temporary file in the
// same directory and renaming it into place. A list that parses to
// fewer repositories than the file already there is refused, and the
// existing file is left as it was.
func WriteLock(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && len(bytesTrim(old)) > 0 {
		oldRepos, err := LoadLock(old)
		if err != nil {
			return err
		}
		newRepos, err := LoadLock(data)
		if err != nil {
			return err
		}
		if len(newRepos) < len(oldRepos) {
			return fmt.Errorf("refusing to replace %d repositories with %d", len(oldRepos), len(newRepos))
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return writeAtomic(path, data)
}

// WriteAtomic writes data to path by rename. The previous file is
// replaced only after the temporary file is written.
func WriteAtomic(path string, data []byte) error {
	return writeAtomic(path, data)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
