//go:build !windows

package fpkey

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// checkDirSecurity rejects a key directory that is not owned by the
// current user or that a group or other user can write to. A writable
// directory would let another user replace the key file (or symlink it
// elsewhere) without touching the file's own permissions.
func checkDirSecurity(info fs.FileInfo, _ string) error {
	if err := checkOwner(info, LogicalDir); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%w: %s must not be group- or world-writable (mode %04o)", ErrKeyUnusable, LogicalDir, perm)
	}
	return nil
}

// checkFileSecurity rejects a key file that is not owned by the current
// user or that a group or other user can read or write. Unlike the
// directory, the file must have no group or other bits at all: it holds
// the key itself, not just a pointer to it.
func checkFileSecurity(info fs.FileInfo, _ string) error {
	if err := checkOwner(info, LogicalPath); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s must not be readable or writable by group or other (mode %04o)", ErrKeyUnusable, LogicalPath, perm)
	}
	return nil
}

// checkOwner rejects logical (LogicalDir or LogicalPath) when info's
// owner is not the current user. uid 0 gets its own message: `sudo`
// with HOME preserved (macOS's default, and some Linux configurations)
// runs `tripcord scan` as root but still resolves ~/.tripcord under the
// invoking user's home, so a one-off sudo invocation leaves the
// directory and key file root-owned, and every later, unprivileged run
// hits this check and exits 3 until someone notices and fixes the
// ownership by hand.
func checkOwner(info fs.FileInfo, logical string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid := int(stat.Uid)
	if uid == os.Getuid() {
		return nil
	}
	if uid == 0 {
		return fmt.Errorf(
			"%w: %s is owned by uid 0 (probably created by an earlier `sudo tripcord scan` with HOME preserved); "+
				"run `sudo chown -R $USER %s` to fix it",
			ErrKeyUnusable, logical, LogicalDir,
		)
	}
	return fmt.Errorf("%w: %s is owned by uid %d, not the current user", ErrKeyUnusable, logical, uid)
}
