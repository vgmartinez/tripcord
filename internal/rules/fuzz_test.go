package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func FuzzParseSpec(f *testing.F) {
	f.Add([]byte(validRule))
	f.Add([]byte(""))
	f.Add([]byte("id: [\n"))
	f.Add([]byte("a: &a [*a, *a]\n"))
	f.Add([]byte("refs: !!binary aGVsbG8=\n"))
	seeds, _ := filepath.Glob("testdata/packs/fixture/*.yaml")
	for _, s := range seeds {
		if data, err := os.ReadFile(s); err == nil {
			f.Add(data)
		}
	}
	env := testEnv(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		spec, err := ParseSpec(data)
		if err != nil {
			return
		}
		if !ValidID(spec.ID) || len(spec.Refs) == 0 || len(spec.Harness) == 0 || len(spec.Files) == 0 {
			t.Fatalf("accepted an invalid spec: %+v", spec)
		}
		if _, err := model.ParseSeverity(spec.Severity); err != nil {
			t.Fatalf("accepted severity %q", spec.Severity)
		}
		if err := spec.Validate(); err != nil {
			t.Fatalf("ParseSpec accepted what Validate rejects: %v", err)
		}
		// Compilation may fail on the expression, but must not panic.
		_, _ = Compile(spec, PackRef{Name: spec.Pack, Version: "2026.11"}, env)
	})
}
