package policy

import (
	"slices"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Policy aspects Weakened reports.
const (
	WeakerMode       = "mode"
	WeakerFailOn     = "fail-on"
	WeakerHarnesses  = "harnesses"
	WeakerRules      = "rules"
	WeakerSeverity   = "severity"
	WeakerExceptions = "exceptions"
	WeakerCustom     = "custom"
	WeakerLocks      = "locked"
)

// Weakened lists, in a fixed order, each aspect in which head reports
// or fails on less than base:
//
//   - mode: a weaker mode (enforce, warn, audit).
//   - fail-on: a higher threshold, or none where base had one.
//   - harnesses: a harness base scans that head does not.
//   - rules: a catalog rule base selects that head does not
//     (rules.include, the allowlist).
//   - severity: a catalog rule with a lower severity override.
//   - exceptions: an exception base does not have.
//   - custom: a custom rule base defines that head does not.
//   - locked: a lock base declares that head does not.
func Weakened(base, head *Effective, catalog RuleCatalog) []string {
	var out []string
	if head.Mode.strength() < base.Mode.strength() {
		out = append(out, WeakerMode)
	}
	if failsLess(head.FailOn, base.FailOn) {
		out = append(out, WeakerFailOn)
	}
	if slices.ContainsFunc(base.Harnesses, func(h model.Harness) bool { return !slices.Contains(head.Harnesses, h) }) {
		out = append(out, WeakerHarnesses)
	}
	if catalog != nil {
		rules, severity := false, false
		for _, r := range catalog.Rules() {
			if base.Selected(r.ID) && !head.Selected(r.ID) {
				rules = true
			}
			if c, err := head.Severity(r.ID, r.Severity).Compare(base.Severity(r.ID, r.Severity)); err == nil && c < 0 {
				severity = true
			}
		}
		if rules {
			out = append(out, WeakerRules)
		}
		if severity {
			out = append(out, WeakerSeverity)
		}
	}
	if slices.ContainsFunc(head.Exceptions, func(ex Exception) bool {
		return !slices.ContainsFunc(base.Exceptions, func(b Exception) bool {
			return b.Rule == ex.Rule && b.Path == ex.Path && b.SHA256 == ex.SHA256 && b.Expires.Equal(ex.Expires)
		})
	}) {
		out = append(out, WeakerExceptions)
	}
	if slices.ContainsFunc(base.Custom, func(c *CustomRule) bool {
		return !slices.ContainsFunc(head.Custom, func(h *CustomRule) bool { return h.ID == c.ID })
	}) {
		out = append(out, WeakerCustom)
	}
	if weakerLocks(base, head) {
		out = append(out, WeakerLocks)
	}
	return out
}

// failsLess reports whether a fail-on of head fails on fewer
// severities than base. The zero value never fails.
func failsLess(head, base model.Severity) bool {
	switch {
	case base == "":
		return false
	case head == "":
		return true
	default:
		c, err := head.Compare(base)
		return err == nil && c > 0
	}
}

func weakerLocks(base, head *Effective) bool {
	if base.ModeLock != nil && (head.ModeLock == nil || head.ModeLock.Floor.strength() < base.ModeLock.Floor.strength()) {
		return true
	}
	for _, l := range base.RuleLocks {
		if !slices.ContainsFunc(head.RuleLocks, func(h RuleLock) bool { return h.Pattern == l.Pattern }) {
			return true
		}
	}
	for _, l := range base.ExemptionLocks {
		if !slices.ContainsFunc(head.ExemptionLocks, func(h ExemptionLock) bool { return h.Pattern == l.Pattern }) {
			return true
		}
	}
	return false
}
