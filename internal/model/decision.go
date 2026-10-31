package model

import "fmt"

// Decision is the outcome attached to a finding.
// Policy mode (enforce, warn, audit) is a separate vocabulary.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionWarn  Decision = "warn"
	DecisionAudit Decision = "audit"
)

var decisions = []Decision{
	DecisionAllow,
	DecisionDeny,
	DecisionWarn,
	DecisionAudit,
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
