package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vgmartinez/tripcord/internal/pathx"
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
		return &Error{Source: redactPath(path), Err: err}
	}
	if err := checkManagedPolicyParentPath(path); err != nil {
		return &Error{Source: redactPath(path), Err: err, IO: isStatError(err)}
	}
	return nil
}

// redactPath hides the running user's home directory in path before it
// reaches an error message, the same way every other diagnostic in this
// codebase avoids printing it (see pathx.TildeHome). The managed policy
// path is normally a fixed system location (/etc/tripcord/policy.yaml
// and similar), but Options.ManagedPolicy lets a caller point it, and
// therefore these error messages, anywhere, including under a home
// directory. The home directory is looked up lazily, once per error,
// and path is returned unchanged if it cannot be determined.
func redactPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	return pathx.TildeHome(home, path)
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
//
// path itself is resolved with filepath.EvalSymlinks first: if the
// policy file is itself a symlink, its real target's parent is what
// must be held to the rules above, not the symlink's own, unrelated
// parent directory (which can be, and often is, perfectly safe while
// the target it points at is not). path is not required to exist for
// this step to matter: checkManagedPolicyFile's own os.Stat before
// calling this already confirmed existence and, by following a
// symlinked leaf to its real target, already used the right file for
// the ownership check; EvalSymlinks failing here (a dangling symlink,
// or path simply not existing in a caller that invokes this directly,
// as some tests do) falls back to the literal path unchanged.
//
// The immediate parent directory of that (possibly resolved) leaf is
// then itself resolved with filepath.EvalSymlinks, so the walk follows
// the real filesystem hierarchy from there. Without that, if any
// directory on the way up were a symlink, filepath.Dir would keep
// walking up the symlink's literal location rather than its target's,
// checking the permissions of directories the policy file is not
// actually under.
func checkManagedPolicyParentPath(path string) error {
	leaf := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		leaf = resolved
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(leaf))
	if err != nil {
		return fmt.Errorf("managed policy parent for %s: %w", redactPath(path), err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("managed policy parent for %s: %w", redactPath(path), err)
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
			return fmt.Errorf("managed policy ancestor for %s: %w", redactPath(path), err)
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
