package main

import "testing"

// TestScanTCFG012ExfilNeverLeaks keeps the instruction-file URL canary in
// its own focused five-format check, rather than adding the heuristic's
// corpus to the broad config leak subset.
func TestScanTCFG012ExfilNeverLeaks(t *testing.T) {
	t.Parallel()
	scanCorpusFixture(t, "TC-CFG-012", "positivos", "../../rules/TC-CFG-012.test/positivos/agents-exfil-url")
}
