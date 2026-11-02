//go:build unix

package main

import (
	"errors"
	"syscall"

	"github.com/vgmartinez/tripcord/internal/prcontext"
)

// outputOpenFlags make the GITHUB_OUTPUT open refuse a symlink target
// atomically (O_NOFOLLOW) and refuse to block forever opening a FIFO
// with no reader (O_NONBLOCK); writeGitHubOutput's fstat check also
// rejects a FIFO that already has a reader.
const outputOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// refuseGitHubOutputSymlink is a no-op here: outputOpenFlags' O_NOFOLLOW
// already refuses a symlink atomically when the file is opened.
func refuseGitHubOutputSymlink(string) error { return nil }

// classifyOutputOpenError maps the open(2) failures outputOpenFlags
// causes to the InputError callers already treat as bad config (exit 3):
// ELOOP is O_NOFOLLOW resolving a symlink, and ENXIO is O_NONBLOCK
// opening a FIFO with no reader.
func classifyOutputOpenError(err error) error {
	switch {
	case errors.Is(err, syscall.ELOOP):
		return &prcontext.InputError{Msg: "GITHUB_OUTPUT must not be a symlink"}
	case errors.Is(err, syscall.ENXIO):
		return &prcontext.InputError{Msg: "GITHUB_OUTPUT must be a regular file"}
	default:
		return err
	}
}
