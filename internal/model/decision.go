package model

import "fmt"

// Decision is the outcome attached to a finding:
// allow, deny, warn, audit, or ask.
// Policy mode (enforce, warn, audit) is a separate vocabulary.
//
// In hook mode, ask maps to the harness's native human-confirmation
// prompt where that harness supports one (Claude Code, Cursor) and
// degrades to deny with an explanatory message elsewhere. That
// mapping is implemented later, in the hook PR. This package only
// accepts ask as a decision value.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionWarn  Decision = "warn"
	DecisionAudit Decision = "audit"
	DecisionAsk   Decision = "ask"
)

var decisions = []Decision{
	DecisionAllow,
	DecisionDeny,
	DecisionWarn,
	DecisionAudit,
	DecisionAsk,
}

// String returns the wire value.
func (d Decision) String() string { return string(d) }

// Valid reports whether d is a known decision.
func (d Decision) Valid() bool {
	for _, item := range decisions {
		if item == d {
			return true
		}
	}
	return false
}

// ParseDecision parses a wire value.
func ParseDecision(s string) (Decision, error) {
	d := Decision(s)
	if !d.Valid() {
		return "", fmt.Errorf("decision %q: unknown", s)
	}
	return d, nil
}
