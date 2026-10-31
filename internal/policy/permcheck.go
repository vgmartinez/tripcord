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

// checkManagedPolicyParentPath rejects a parent or ancestor directory that
// would let another user substitute the managed policy file itself, or
// swap out the directory tree that contains it. The immediate parent is
// held to the strict rule in checkManagedPolicyParent: it must not be
// world- or group-writable even with the sticky bit, because an attacker
// could still create a new entry there with the policy's exact name.
// Ancestors above it use the relaxed rule in checkManagedPolicyAncestor,
// because the sticky bit on a shared directory such as /tmp already stops
// any other user from renaming or deleting the already-validated child
// entry beneath it.
func checkManagedPolicyParentPath(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("managed policy parent for %s: %w", path, err)
	}
	if err := checkManagedPolicyParent(path, info); err != nil {
		return err
	}
	for {
		next := filepath.Dir(dir)
		if next == dir {
			return nil
		}
		dir = next
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("managed policy ancestor for %s: %w", path, err)
		}
		if err := checkManagedPolicyAncestor(path, info); err != nil {
			return err
		}
	}
}

func isStatError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr)
}

var errWorldWritable = errors.New("world-writable; an org policy a repository's own user can edit is not an org boundary")
