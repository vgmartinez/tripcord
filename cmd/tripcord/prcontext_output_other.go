//go:build !unix

package main

import (
	"errors"
	"os"

	"github.com/vgmartinez/tripcord/internal/prcontext"
)

// outputOpenFlags is empty where O_NOFOLLOW is not available (Windows);
// refuseGitHubOutputSymlink's Lstat check is this platform's symlink
// guard instead.
const outputOpenFlags = 0

// refuseGitHubOutputSymlink rejects path when it is already a symlink.
// This platform has no O_NOFOLLOW open flag, so the check runs before
// Open rather than atomically with it.
func refuseGitHubOutputSymlink(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	case info.Mode()&os.ModeSymlink != 0:
		return &prcontext.InputError{Msg: "GITHUB_OUTPUT must not be a symlink"}
	}
	return nil
}

// classifyOutputOpenError is the identity here: this platform has no
// equivalent to the unix ELOOP/ENXIO open(2) failures.
func classifyOutputOpenError(err error) error { return err }
