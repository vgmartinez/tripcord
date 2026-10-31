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

// escapingSymlinkMarker is the fixed phrase every adapter's "cannot
// follow this symlink safely" diagnostic shares (see kit.Walk and the
// Claude adapter's own repository walker), used to recognize the one
// diagnostic kind more than one adapter can independently report for
// the same repository-relative symlink.
const escapingSymlinkMarker = "symlink resolves outside the "

func isEscapingSymlinkDiagnostic(d Diagnostic) bool {
	return strings.Contains(d.Message, escapingSymlinkMarker)
}

// DedupeEscapingSymlinkDiagnostics collapses duplicate escaping-symlink
// diagnostics for the same (scope, path) down to one, when a caller has
// merged diagnostics from more than one adapter over the same tree.
// Several adapters' Relevant matchers overlap by design: Claude's plugin
// discovery deliberately flags directory names (skills, agents,
// commands, hooks) a Claude plugin can use at an arbitrary, not yet
// known root, broader than what Claude actually reads, so that a
// genuinely Claude-only escaping symlink is still caught. When another
// harness also reports the very same symlink, that harness names a
// location it actually reads, so Claude's report is the redundant one
// and is dropped; a symlink only Claude flags is unaffected. Diagnostics
// that are not an escaping-symlink report pass through unchanged, and
// relative order is preserved.
func DedupeEscapingSymlinkDiagnostics(in []Diagnostic) []Diagnostic {
	type key struct {
		scope model.Scope
		path  string
	}
	reportedByOthers := map[key]bool{}
	for _, d := range in {
		if d.Harness != model.HarnessClaude && isEscapingSymlinkDiagnostic(d) {
			reportedByOthers[key{d.Scope, d.Path}] = true
		}
	}
	out := make([]Diagnostic, 0, len(in))
	for _, d := range in {
		if d.Harness == model.HarnessClaude && isEscapingSymlinkDiagnostic(d) && reportedByOthers[key{d.Scope, d.Path}] {
			continue
		}
		out = append(out, d)
	}
	return out
}
