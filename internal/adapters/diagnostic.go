package adapters

import (
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Diagnostic is a discovery problem that does not stop discovery: a file
// that could not be read or parsed, an unsafe symlink, a truncated walk, or
// configuration written to evade a scanner (such as case-variant keys).
// Path is the logical, scope-shaped path (repo-relative, "~/"-rooted, or a
// managed absolute path) and never a user's absolute home directory.
//
// Informational diagnostics are notes, such as a legacy directory that is
// not scanned. They are printed to stderr and do not make the scan
// incomplete, so they do not change the exit code.
type Diagnostic struct {
	Harness       model.Harness
	Scope         model.Scope
	Path          string
	Message       string
	Informational bool
}

func (d Diagnostic) String() string {
	var b strings.Builder
	b.WriteString(string(d.Harness))
	if d.Path != "" {
		b.WriteString(": ")
		b.WriteString(d.Path)
	}
	b.WriteString(": ")
	b.WriteString(d.Message)
	return b.String()
}

// DiagnosticError is returned by Discover together with the items it could
// still produce. A caller scans those items and then reports the scan as
// incomplete: the configuration Tripcord could not read may be exactly the
// configuration the harness executes.
type DiagnosticError struct {
	Diagnostics []Diagnostic
}

func (e *DiagnosticError) Error() string {
	parts := make([]string, len(e.Diagnostics))
	for i, d := range e.Diagnostics {
		parts[i] = d.String()
	}
	return strings.Join(parts, "; ")
}
