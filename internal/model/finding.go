package model

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
)

// fingerprintPattern is the wire shape: tcf_ plus lowercase hex.
// The length is not fixed here. The spec sample uses 6 hex digits.
// Fingerprint emits 16.
var fingerprintPattern = regexp.MustCompile(`^tcf_[0-9a-f]+$`)

// Evidence cites one event. Excerpts stored on a finding must already
// be redacted; Fingerprint hashes the excerpt text it is given.
type Evidence struct {
	Event   string `json:"event"`
	Excerpt string `json:"excerpt"`
}

// Location is where a finding applies.
// Path and line are optional. The spec sample has harness and session only.
type Location struct {
	Harness Harness `json:"harness"`
	Session string  `json:"session,omitempty"`
	Path    string  `json:"path,omitempty"`
	Line    *int    `json:"line,omitempty"`
}

// Finding is one policy result (tripcord.finding/v1).
type Finding struct {
	Schema      string     `json:"schema"`
	Rule        string     `json:"rule"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Decision    Decision   `json:"decision"`
	Confidence  float64    `json:"confidence"`
	Evidence    []Evidence `json:"evidence"`
	Location    Location   `json:"location"`
	Refs        []string   `json:"refs"`
	Fix         string     `json:"fix"`
	Fingerprint string     `json:"fingerprint"`
}

// MarshalJSON emits empty arrays for nil slices.
func (f Finding) MarshalJSON() ([]byte, error) {
	if f.Evidence == nil {
		f.Evidence = []Evidence{}
	}
	if f.Refs == nil {
		f.Refs = []string{}
	}
	type alias Finding
	return json.Marshal(alias(f))
}

// Validate checks closed vocabularies and the fingerprint shape.
// It does not recompute the fingerprint.
func (f Finding) Validate() error {
	if f.Schema != SchemaFinding {
		return fmt.Errorf("finding: schema %q", f.Schema)
	}
	if f.Rule == "" || f.Title == "" || f.Fix == "" {
		return fmt.Errorf("finding: rule, title, and fix are required")
	}
	if !f.Severity.Valid() {
		return fmt.Errorf("finding: severity %q: unknown", f.Severity)
	}
	if !f.Decision.Valid() {
		return fmt.Errorf("finding: decision %q: unknown", f.Decision)
	}
	if math.IsNaN(f.Confidence) || f.Confidence < 0 || f.Confidence > 1 {
		return fmt.Errorf("finding: confidence out of range")
	}
	for i, ev := range f.Evidence {
		if ev.Event == "" || ev.Excerpt == "" {
			return fmt.Errorf("finding: evidence %d: event and excerpt are required", i)
		}
	}
	if !f.Location.Harness.Valid() {
		return fmt.Errorf("finding: location harness %q: unknown", f.Location.Harness)
	}
	if f.Location.Line != nil && *f.Location.Line < 1 {
		return fmt.Errorf("finding: location line %d", *f.Location.Line)
	}
	for i, ref := range f.Refs {
		if ref == "" {
			return fmt.Errorf("finding: ref %d is empty", i)
		}
	}
	if !fingerprintPattern.MatchString(f.Fingerprint) {
		return fmt.Errorf("finding: fingerprint %q", f.Fingerprint)
	}
	return nil
}
