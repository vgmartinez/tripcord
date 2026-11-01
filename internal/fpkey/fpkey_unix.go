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

func checkOwner(info fs.FileInfo, logical string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%w: %s is not owned by the current user", ErrKeyUnusable, logical)
	}
	return nil
}
