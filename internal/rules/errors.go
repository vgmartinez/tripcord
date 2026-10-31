package rules

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// Error is an invalid or unreadable rule, pack, or registry. Source is
// the file or pack the problem was found in.
type Error struct {
	Source string
	Err    error
	// IO marks a read failure other than a missing file.
	IO bool
}

func (e *Error) Error() string {
	if e.Source == "" {
		return "rules: " + e.Err.Error()
	}
	return fmt.Sprintf("rules: %s: %v", e.Source, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// ExitCode is exitcode.Config for invalid content or a missing file,
// and exitcode.Internal for other read failures.
func (e *Error) ExitCode() exitcode.Code {
	if e.IO {
		return exitcode.Internal
	}
	return exitcode.Config
}

func invalid(source string, format string, args ...any) error {
	return &Error{Source: source, Err: fmt.Errorf(format, args...)}
}

// wrap attaches source to err unless it already is an *Error.
// fs.PathError values other than fs.ErrNotExist are marked IO.
func wrap(source string, err error) error {
	var re *Error
	if errors.As(err, &re) {
		return err
	}
	var pe *fs.PathError
	io := errors.As(err, &pe) && !errors.Is(err, fs.ErrNotExist)
	return &Error{Source: source, Err: err, IO: io}
}
