package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// checkManagedPolicyFile rejects a managed policy file an org
// administrator does not exclusively control: one that is
// world-writable or, on Unix, not owned by root or the current user. A
// managed policy the repository's own user can rewrite is not an org
// boundary the repository cannot bypass; see CONTRIBUTING.md. A missing
// file is not an error here: Load treats a missing managed policy as no
// managed layer, and readFile reports any other stat or read failure.
func checkManagedPolicyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil
	}
	if err := checkManagedPolicyOwner(path, info); err != nil {
		return &Error{Source: path, Err: err}
	}
	if err := checkManagedPolicyParentPath(path); err != nil {
		return &Error{Source: path, Err: err, IO: isStatError(err)}
	}
	return nil
}

func checkManagedPolicyParentPath(path string) error {
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("managed policy parent for %s: %w", path, err)
	}
	return checkManagedPolicyParent(path, parent)
}

func isStatError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr)
}

var errWorldWritable = errors.New("world-writable; an org policy a repository's own user can edit is not an org boundary")
