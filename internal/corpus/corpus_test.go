package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

// allowlistCeiling is the number of entries allowlist.tsv must hold.
// Lower it when a fixture is fixed and its entry removed. Raising it
// means a new finding was accepted instead of fixed.
const allowlistCeiling = 113

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

// fixtureRoots are the trees TestFixtureTrees lints: rules/, whose rule
// definitions and docs skip the host, IOC, and entropy checks, and
// every adapter testdata tree.
func fixtureRoots(t *testing.T, root string) []Root {
	t.Helper()
	roots := []Root{{Dir: filepath.Join(root, "rules"), Defs: PackDefs}}
	testdata, err := filepath.Glob(filepath.Join(root, "internal", "adapters", "*", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	if len(testdata) == 0 {
		t.Fatal("no internal/adapters/*/testdata trees")
	}
	for _, dir := range testdata {
		roots = append(roots, Root{Dir: dir})
	}
	return roots
}

// TestFixtureTrees lints the rule and adapter fixture trees. Every
// finding needs an allowlist.tsv entry and every entry needs a finding.
func TestFixtureTrees(t *testing.T) {
	root := moduleRoot(t)
	allow := loadAllowlist(t)
	if n := len(allow.Entries); n != allowlistCeiling {
		t.Errorf("allowlist.tsv has %d entries, allowlistCeiling is %d: the list only shrinks; lower the ceiling with it", n, allowlistCeiling)
	}
	findings, err := CheckRoots(fixtureRoots(t, root)...)
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
