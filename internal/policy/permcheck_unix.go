//go:build !windows

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// checkManagedPolicyOwner enforces the Unix half of
// checkManagedPolicyFile's contract: the file's world-write bit is
// clear, and it is owned by root (uid 0) or by the user running this
// process. A file info whose Sys value is not a *syscall.Stat_t (not
// expected on a real filesystem) skips the ownership check and only
// enforces world-writable.
func checkManagedPolicyOwner(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("managed policy %s: %w", path, errWorldWritable)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid := os.Getuid()
	if int(stat.Uid) != 0 && int(stat.Uid) != uid {
		return fmt.Errorf("managed policy %s: owned by uid %d, want root or the current user (uid %d)", path, stat.Uid, uid)
	}
	return nil
}

// checkManagedPolicyParent rejects a directory that lets another user
// replace the managed policy. The owner must be root or the current user.
// World-writable is always rejected. Group-writable is rejected unless
// both the owner and the group are the current user's, because a sticky
// bit still lets the owner rewrite the directory entry.
func checkManagedPolicyParent(path string, info os.FileInfo) error {
	if !info.IsDir() {
		return fmt.Errorf("managed policy parent for %s: not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("managed policy parent for %s: owner is unknown", path)
	}
	uid := os.Getuid()
	owner := int(stat.Uid)
	if owner != 0 && owner != uid {
		return fmt.Errorf("managed policy parent for %s: owned by uid %d, want root or the current user (uid %d)", path, owner, uid)
	}
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return fmt.Errorf("managed policy parent for %s: %w", path, errWorldWritable)
	}
	if perm&0o020 != 0 && (owner != uid || int(stat.Gid) != os.Getgid()) {
		return fmt.Errorf("managed policy parent for %s: group-writable and not owned by the current user", path)
	}
	return nil
}
