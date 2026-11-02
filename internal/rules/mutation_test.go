package rules

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

// sameSeverityFallthrough lists severity_when clauses whose matches fall
// through to a later clause of the same severity when they are disabled,
// so severity alone cannot tell them apart. Each names the test that
// pins the clause instead.
var sameSeverityFallthrough = map[string]string{
	// The bypass pair falls to bypassPermissions alone; one finding and
	// its title are pinned by TestScanApprovalModeSeverities in
	// cmd/tripcord.
	"TC-CFG-005[0]": "TestScanApprovalModeSeverities",
}

// TestSeverityClausesAreCovered disables each severity_when clause of
// each core rule in turn and checks that the rule's fixtures then fail:
// every clause is exercised by a fixture whose expected severity it
// decides.
func TestSeverityClausesAreCovered(t *testing.T) {
	env := testEnv(t)
	never, err := env.Compile("false")
	if err != nil {
		t.Fatal(err)
	}
	core := corePackWithSymlinks(t)
	pack, err := LoadDir(core, env)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range pack.Rules {
		for i := range r.SeverityWhen {
			name := fmt.Sprintf("%s[%d]", r.ID, i)
			t.Run(name, func(t *testing.T) {
				if _, ok := sameSeverityFallthrough[name]; ok {
					t.Skipf("pinned by %s", sameSeverityFallthrough[name])
				}
				mutant := *r
				mutant.SeverityWhen = slices.Clone(r.SeverityWhen)
				mutant.SeverityWhen[i].When = never
				if err := CheckRuleFixtures(context.Background(), env, core, &mutant, adapterDiscover); err == nil {
					t.Fatalf("fixtures still pass with severity_when[%d] (%s) disabled", i, r.SeverityWhen[i].Severity)
				}
			})
		}
	}
}
