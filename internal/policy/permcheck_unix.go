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
