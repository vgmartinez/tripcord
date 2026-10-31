package policy

import (
	"fmt"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// Error is an invalid or unreadable policy. Source is the policy file
// or pack reference.
type Error struct {
	Source string
	Err    error
	// IO marks a read failure other than a missing file.
	IO bool
}

func (e *Error) Error() string {
	return fmt.Sprintf("policy: %s: %v", e.Source, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// ExitCode is exitcode.Config (3) for an invalid policy and
// exitcode.Internal (4) for a read failure.
func (e *Error) ExitCode() exitcode.Code {
	if e.IO {
		return exitcode.Internal
	}
	return exitcode.Config
}
