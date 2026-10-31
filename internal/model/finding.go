package model

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// fingerprintPattern is the wire shape: "tcf_" plus exactly 16 lowercase
// hex digits, the length Fingerprint emits. Pinning the length here, and
// in tripcord.finding/v1, is part of the frozen v1 contract: narrowing
// it later would be a breaking schema change.
var fingerprintPattern = regexp.MustCompile(`^tcf_[0-9a-f]{16}$`)

// ConfigRef cites one config file and, optionally, one stable entry
// inside it. ID is a ConfigItem.ID (harness:scope:path). Key is a
// content-derived sub-identifier, never a positional index: an MCP
// server name, a task label, or matcher+command for a hook entry.
// Fingerprint hashes both, so two entries in the same file get distinct
// fingerprints, and reordering those entries does not change them.
type ConfigRef struct {
	ID  string `json:"id"`
	Key string `json:"key,omitempty"`
}

// Evidence cites one event or one config item, never both. Event is an
// Event.ID. Config is a ConfigRef. Excerpt is optional either way and,
// when set, must already be redacted. Fingerprint hashes the normalized
// excerpt and Config (id and key), but never Event (see Fingerprint).
type Evidence struct {
	Event   string     `json:"event,omitempty"`
	Config  *ConfigRef `json:"config,omitempty"`
	Excerpt string     `json:"excerpt,omitempty"`
}

// Location is where a finding applies.
// Scope, path, and line are optional. The spec sample has harness and
// session only. Scope and path together feed Fingerprint; see
// normalizeScopedPath. Line is for display: it is never hashed, so
// adding a line above a hook does not change the fingerprint.
type Location struct {
	Harness Harness `json:"harness"`
	Session string  `json:"session,omitempty"`
	Scope   Scope   `json:"scope,omitempty"`
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

// Validate checks closed vocabularies, location paths, config ids, and
// the stored fingerprint. Every fingerprint input is on the finding:
// the rule, the location (harness, session, scope, path), and each
// evidence excerpt and config id/key. Line and event id are on the
// document too, and Fingerprint ignores them, so they do not have to be
// supplied from anywhere else. Validate recomputes Fingerprint and
// requires the stored value to match.
//
// location.path must already be normalizeScopedPath's result, the same
// rule parseConfigID applies to a config id. Fingerprint still
// canonicalizes a non-canonical path internally, so a caller can hash
// "a/./b" and get the digest of "a/b"; a stored finding may not.
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
		hasEvent := ev.Event != ""
		hasConfig := ev.Config != nil
		if hasEvent == hasConfig {
			return fmt.Errorf("finding: evidence %d: exactly one of event or config is required", i)
		}
		if hasConfig {
			if strings.TrimSpace(ev.Config.ID) == "" {
				return fmt.Errorf("finding: evidence %d: config id is required", i)
			}
			if _, _, _, err := parseConfigID(ev.Config.ID); err != nil {
				return fmt.Errorf("finding: evidence %d: %w", i, err)
			}
		}
	}
	if !f.Location.Harness.Valid() {
		return fmt.Errorf("finding: location harness %q: unknown", f.Location.Harness)
	}
	if f.Location.Scope != "" && !f.Location.Scope.Valid() {
		return fmt.Errorf("finding: location scope %q: unknown", f.Location.Scope)
	}
	if f.Location.Path != "" {
		normalized, err := normalizeScopedPath(f.Location.Scope, f.Location.Path)
		if err != nil {
			return fmt.Errorf("finding: location %w", err)
		}
		if normalized != f.Location.Path {
			return fmt.Errorf("finding: location %w: %q", errPathNotNormalized, f.Location.Path)
		}
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
	got, err := Fingerprint(f.Rule, f.Location, f.Evidence)
	if err != nil {
		return fmt.Errorf("finding: fingerprint: %w", err)
	}
	if got != f.Fingerprint {
		return fmt.Errorf("finding: fingerprint %q, computed %q", f.Fingerprint, got)
	}
	return nil
}
