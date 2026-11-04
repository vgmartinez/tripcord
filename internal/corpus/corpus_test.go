package corpus

import (
	"path/filepath"
	"testing"
)

// TestCorpus lints corpus/ only. rules/ and adapter testdata are separate
// roots a later migration can pass to Check.
func TestCorpus(t *testing.T) {
	findings, err := Check(filepath.Join(moduleRoot(t), "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("%s: %s: %s", f.Path, f.Kind, f.Detail)
	}
}
