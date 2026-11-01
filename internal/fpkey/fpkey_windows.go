//go:build windows

package fpkey

import "io/fs"

// checkDirSecurity and checkFileSecurity are no-ops on Windows.
// os.FileInfo.Mode() synthesizes a POSIX-style mode on Windows (typically
// 0666 for files and 0777 for directories) that does not reflect the
// file's actual ACL, and there is no POSIX uid to compare against the
// current user. Protecting ~/.tripcord on Windows relies on the
// filesystem's ACLs (the user's profile directory is private by
// default) rather than on the permission and ownership checks this
// package runs on Unix; see docs/fingerprint.md.
func checkDirSecurity(fs.FileInfo, string) error  { return nil }
func checkFileSecurity(fs.FileInfo, string) error { return nil }
