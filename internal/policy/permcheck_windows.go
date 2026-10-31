//go:build windows

package policy

import "os"

// checkManagedPolicyOwner is best-effort on Windows: ownership and
// write access there are governed by an ACL, which does not map onto a
// Unix permission bit or a single owning uid, so this is a no-op. An
// administrator who wants the managed policy file to be an org
// boundary the repository cannot edit should set its ACL to deny write
// access to the account the repository runs as.
func checkManagedPolicyOwner(path string, info os.FileInfo) error {
	return nil
}

func checkManagedPolicyParent(path string, info os.FileInfo) error {
	return nil
}

func checkManagedPolicyAncestor(path string, info os.FileInfo) error {
	return nil
}
