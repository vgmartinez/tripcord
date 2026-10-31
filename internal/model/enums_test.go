package model

import (
	"testing"
)

func TestHarnessCatalog(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id      Harness
		product bool
	}{
		{HarnessClaude, true},
		{HarnessCodex, true},
		{HarnessCursor, true},
		{HarnessCopilot, true},
		{HarnessGemini, true},
		{HarnessOpenCode, true},
		{HarnessWindsurf, true},
		{SurfaceVSCode, false},
		{SurfaceDevcontainer, false},
		{SurfaceGeneric, false},
	}
	if len(cases) != len(productHarnesses)+len(surfaces) {
		t.Fatalf("catalog len = %d, slices = %d", len(cases), len(productHarnesses)+len(surfaces))
	}
	seen := map[Harness]bool{}
	for _, tc := range cases {
		if seen[tc.id] {
			t.Fatalf("duplicate %s", tc.id)
		}
		seen[tc.id] = true
		got, err := ParseHarness(string(tc.id))
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.id || got.String() != string(tc.id) {
			t.Fatalf("ParseHarness(%s) = %s", tc.id, got)
		}
		if got.IsProduct() != tc.product || !got.Valid() {
			t.Fatalf("%s product=%v valid=%v", tc.id, got.IsProduct(), got.Valid())
		}
	}
	for _, id := range []Harness{"", "devin", "jules", "Claude"} {
		if id.Valid() {
			t.Fatalf("%q is valid", id)
		}
		if _, err := ParseHarness(string(id)); err == nil {
			t.Fatalf("ParseHarness(%q) succeeded", id)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	t.Parallel()
	if len(severityOrder) != 4 {
		t.Fatalf("len = %d", len(severityOrder))
	}
	for i, sev := range severityOrder {
		got, err := ParseSeverity(string(sev))
		if err != nil {
			t.Fatal(err)
		}
		if got != sev || !got.Valid() {
			t.Fatalf("parse %s", sev)
		}
		for j, other := range severityOrder {
			cmp, err := sev.Compare(other)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case i < j && cmp != -1:
				t.Fatalf("%s Compare %s = %d", sev, other, cmp)
			case i == j && cmp != 0:
				t.Fatalf("%s Compare %s = %d", sev, other, cmp)
			case i > j && cmp != 1:
				t.Fatalf("%s Compare %s = %d", sev, other, cmp)
			}
		}
	}
	if _, err := ParseSeverity("info"); err == nil {
		t.Fatal("parsed info")
	}
	if _, err := SeverityCritical.Compare(Severity("info")); err == nil {
		t.Fatal("compared unknown")
	}
	if Severity("HIGH").Valid() {
		t.Fatal("HIGH is valid")
	}
}

func TestDecisionVocabulary(t *testing.T) {
	t.Parallel()
	want := []Decision{DecisionAllow, DecisionDeny, DecisionWarn, DecisionAudit, DecisionAsk}
	if len(decisions) != len(want) {
		t.Fatalf("len(decisions) = %d", len(decisions))
	}
	for i, d := range want {
		if decisions[i] != d {
			t.Fatalf("decisions[%d] = %s, want %s", i, decisions[i], d)
		}
		got, err := ParseDecision(string(d))
		if err != nil || got != d || !got.Valid() {
			t.Fatalf("decision %s: %v", d, err)
		}
	}
	for _, raw := range []string{"", "enforce", "block", "Deny"} {
		if Decision(raw).Valid() {
			t.Fatalf("%q is valid", raw)
		}
		if _, err := ParseDecision(raw); err == nil {
			t.Fatalf("parsed %q", raw)
		}
	}
}

func TestScopeAndConfigKind(t *testing.T) {
	t.Parallel()
	for _, scope := range scopes {
		got, err := ParseScope(string(scope))
		if err != nil || got != scope || !got.Valid() {
			t.Fatalf("scope %s: %v", scope, err)
		}
	}
	if _, err := ParseScope("global"); err == nil {
		t.Fatal("parsed global")
	}
	for _, kind := range configKinds {
		got, err := ParseConfigKind(string(kind))
		if err != nil || got != kind || !got.Valid() {
			t.Fatalf("kind %s: %v", kind, err)
		}
	}
	if _, err := ParseConfigKind("script"); err == nil {
		t.Fatal("parsed script")
	}
}

func TestOriginVocabulary(t *testing.T) {
	t.Parallel()
	for _, origin := range origins {
		got, err := ParseOrigin(string(origin))
		if err != nil || got != origin || !got.Valid() {
			t.Fatalf("origin %s: %v", origin, err)
		}
	}
	if _, err := ParseOrigin("remote"); err == nil {
		t.Fatal("parsed remote")
	}
}

func TestEventKindConstants(t *testing.T) {
	t.Parallel()
	kinds := []EventKind{
		EventKindToolCall,
		EventKindRead,
		EventKindWrite,
		EventKindNet,
		EventKindMessage,
	}
	seen := map[EventKind]bool{}
	for _, kind := range kinds {
		if kind == "" || seen[kind] {
			t.Fatalf("kind %q", kind)
		}
		seen[kind] = true
	}
	if EventKindToolCall != "tool_call" || EventKindRead != "read" || EventKindWrite != "write" || EventKindNet != "net" || EventKindMessage != "message" {
		t.Fatalf("kind values changed: %v", kinds)
	}
}
