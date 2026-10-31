package model

import (
	"cmp"
	"fmt"
)

// Severity is a finding severity. The order is
// low < medium < high < critical.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityOrder is the rank. Index 0 is the least severe.
var severityOrder = []Severity{
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// String returns the wire value.
func (s Severity) String() string { return string(s) }

// Valid reports whether s is one of the four severities.
func (s Severity) Valid() bool {
	_, err := s.rank()
	return err == nil
}

// ParseSeverity parses a wire value.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(s)
	if !sev.Valid() {
		return "", fmt.Errorf("severity %q: unknown", s)
	}
	return sev, nil
}

// Compare orders severities. It returns -1 when s is less severe than
// other, 0 when they are equal, and 1 when s is more severe.
func (s Severity) Compare(other Severity) (int, error) {
	left, err := s.rank()
	if err != nil {
		return 0, err
	}
	right, err := other.rank()
	if err != nil {
		return 0, err
	}
	return cmp.Compare(left, right), nil
}

func (s Severity) rank() (int, error) {
	for i, item := range severityOrder {
		if item == s {
			return i, nil
		}
	}
	return 0, fmt.Errorf("severity %q: unknown", s)
}
