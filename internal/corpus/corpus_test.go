package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

// allowlistCeiling is the number of entries allowlist.tsv must hold.
// Lower it when a fixture is fixed and its entry removed. Raising it
// means a new finding was accepted instead of fixed.
const allowlistCeiling = 104

// TestCorpus lints corpus/, which must be clean: no allowlist applies.
func TestCorpus(t *testing.T) {
	findings, err := Check(filepath.Join(moduleRoot(t), "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("%s: %s: %s", f.Path, f.Kind, f.Detail)
	}
}

// fixtureRoots are the trees TestFixtureTrees lints. Rule definitions
// and docs in rules/ skip the host, IOC, and entropy checks.
func fixtureRoots(root string) []Root {
	return []Root{{Dir: filepath.Join(root, "rules"), Defs: PackDefs}}
}

// TestFixtureTrees lints the rule fixture trees. Every finding needs an
// allowlist.tsv entry and every entry needs a finding.
func TestFixtureTrees(t *testing.T) {
	root := moduleRoot(t)
	allow := loadAllowlist(t)
	if n := len(allow.Entries); n != allowlistCeiling {
		t.Errorf("allowlist.tsv has %d entries, allowlistCeiling is %d: the list only shrinks; lower the ceiling with it", n, allowlistCeiling)
	}
	findings, err := CheckRoots(fixtureRoots(root)...)
	if err != nil {
		t.Fatal(err)
	}
	unlisted, stale, err := allow.Apply(root, findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range unlisted {
		rel, _ := RelPath(root, f)
		t.Errorf("%s: %s: %s: not in allowlist.tsv; fix the fixture", rel, f.Kind, f.Detail)
	}
	for _, e := range stale {
		t.Errorf("allowlist.tsv:%d: %s %s %s matches no finding; remove it", e.Line, e.Path, e.Kind, e.Detail)
	}
}

func loadAllowlist(t *testing.T) *Allowlist {
	t.Helper()
	raw, err := os.ReadFile("allowlist.tsv")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAllowlist(raw)
	if err != nil {
		t.Fatalf("allowlist.tsv: %v", err)
	}
	return a
}
