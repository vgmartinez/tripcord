package policy

import (
	"slices"
	"strings"
	"testing"
)

const addedException = "rules:\n  exceptions:\n    - {rule: TC-CFG-004, path: .claude/settings.json, sha256: " +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, reason: reviewed, expires: 2099-01-01}\n"

func TestWeakened(t *testing.T) {
	const base = "mode: enforce\nfail-on: high\n"
	for _, tc := range []struct {
		name, base, head string
		want             []string
	}{
		{"same", base, base, nil},
		{"stricter", base, "mode: enforce\nfail-on: medium\nlocked: {mode: true}\n", nil},
		{"mode warn", base, "mode: warn\nfail-on: high\n", []string{WeakerMode}},
		{"mode audit", base, "mode: audit\n", []string{WeakerMode}},
		{"fail-on raised", base, "mode: enforce\nfail-on: critical\n", []string{WeakerFailOn}},
		{"harness dropped", base, base + "harnesses: [claude]\n", []string{WeakerHarnesses}},
		{"rule left out of the allowlist", base, base + "rules:\n  include: [\"TC-CFG-00*\"]\n", []string{WeakerRules}},
		{"severity lowered", base, base + "rules:\n  severity_overrides: {TC-CFG-004: low}\n", []string{WeakerSeverity}},
		{"severity raised", base, base + "rules:\n  severity_overrides: {TC-CFG-004: critical}\n", nil},
		{"exception added", base, base + addedException, []string{WeakerExceptions}},
		{"exception kept", base + addedException, base + addedException, nil},
		{"exception removed", base + addedException, base, nil},
		{"custom rule removed", base + "custom:\n  - {id: ORG-001, deny_if: \"true\", message: no, severity: high}\n", base, []string{WeakerCustom}},
		{"mode lock removed", base + "locked: {mode: true}\n", base, []string{WeakerLocks}},
		{"rule lock removed", base + "locked: {rules: [TC-CFG-*]}\n", base, []string{WeakerLocks}},
		{"several", base, "mode: audit\nfail-on: critical\n" + addedException, []string{WeakerMode, WeakerFailOn, WeakerExceptions}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := mustMerge(t, catalog, tc.base)
			h := mustMerge(t, catalog, tc.head)
			if got := Weakened(b, h, catalog); !slices.Equal(got, tc.want) {
				t.Fatalf("Weakened = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWeakenedNoFailOn(t *testing.T) {
	b := mustMerge(t, catalog, "mode: enforce\nfail-on: high\n")
	h := mustMerge(t, catalog, "mode: enforce\n")
	h.FailOn = ""
	if got := Weakened(b, h, catalog); !slices.Contains(got, WeakerFailOn) {
		t.Fatalf("Weakened = %v", got)
	}
	if got := strings.Join(Weakened(h, b, catalog), ","); got != "" {
		t.Fatalf("gaining a fail-on is not weaker: %s", got)
	}
}
