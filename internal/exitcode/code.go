package exitcode

import "fmt"

// Code is a process exit status.
type Code int

const (
	// OK is 0: no findings above --fail-on.
	OK Code = 0
	// Findings is 1: findings above the threshold.
	Findings Code = 1
	// Block is 2: hook mode block (Claude, Copilot, and Windsurf convention).
	Block Code = 2
	// Config is 3: configuration error or invalid policy.
	Config Code = 3
	// Internal is 4: internal or I/O error.
	// Hook mode translates this to fail-closed when policy asks for that.
	Internal Code = 4
)

// All returns the five defined statuses, from 0 through 4.
func All() []Code {
	return []Code{OK, Findings, Block, Config, Internal}
}

// Parse returns the status for n.
func Parse(n int) (Code, error) {
	c := Code(n)
	switch c {
	case OK, Findings, Block, Config, Internal:
		return c, nil
	default:
		return 0, fmt.Errorf("exit code %d: unknown", n)
	}
}

// Valid reports whether c is one of the five defined statuses.
func (c Code) Valid() bool {
	_, err := Parse(int(c))
	return err == nil
}

// String returns the table meaning for c.
func (c Code) String() string {
	switch c {
	case OK:
		return "no findings above --fail-on"
	case Findings:
		return "findings above the threshold"
	case Block:
		return "hook mode: block (Claude, Copilot, and Windsurf convention)"
	case Config:
		return "configuration error or invalid policy"
	case Internal:
		return "internal or I/O error (hook mode translates this to fail-closed when policy asks)"
	default:
		return fmt.Sprintf("exit code %d", int(c))
	}
}
