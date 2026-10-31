package rules

import (
	"os"
	"strings"
	"testing"
)

func mustRegistry(t *testing.T, s string) *Registry {
	t.Helper()
	r, err := ParseRegistry([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseRegistry(t *testing.T) {
	r := mustRegistry(t, "# header\n\nTC-CFG-001 active tripcord/core@2026.11\n  TC-CFG-002   retired tripcord/core@2026.11  \n")
	if len(r.Entries()) != 2 {
		t.Fatalf("entries = %+v", r.Entries())
	}
	e, ok := r.Lookup("TC-CFG-002")
	if !ok || e.Status != StatusRetired || e.Line != 4 {
		t.Fatalf("entry = %+v", e)
	}
}

func TestParseRegistryRejects(t *testing.T) {
	for name, s := range map[string]string{
		"duplicate":   "TC-CFG-001 active tripcord/core@2026.11\nTC-CFG-001 retired tripcord/core@2026.11\n",
		"bad status":  "TC-CFG-001 deleted tripcord/core@2026.11\n",
		"bad id":      "tc-cfg-1 active tripcord/core@2026.11\n",
		"bad pack":    "TC-CFG-001 active tripcord/core\n",
		"two fields":  "TC-CFG-001 active\n",
		"four fields": "TC-CFG-001 active tripcord/core@2026.11 extra\n",
	} {
		if _, err := ParseRegistry([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckRegistryEvolution(t *testing.T) {
	base := "TC-CFG-001 active tripcord/core@2026.11\nTC-CFG-002 retired tripcord/core@2026.11\n"
	ok := map[string]string{
		"unchanged": base,
		"append":    base + "TC-CFG-003 active tripcord/core@2026.12\n",
		"retire":    strings.Replace(base, "TC-CFG-001 active", "TC-CFG-001 retired", 1),
		"reorder":   "TC-CFG-002 retired tripcord/core@2026.11\nTC-CFG-001 active tripcord/core@2026.11\n",
	}
	for name, next := range ok {
		if err := CheckRegistryEvolution(mustRegistry(t, base), mustRegistry(t, next)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]string{
		"remove active":  "TC-CFG-002 retired tripcord/core@2026.11\n",
		"remove retired": "TC-CFG-001 active tripcord/core@2026.11\n",
		"reactivate":     strings.Replace(base, "TC-CFG-002 retired", "TC-CFG-002 active", 1),
		"rewrite intro":  strings.Replace(base, "TC-CFG-001 active tripcord/core@2026.11", "TC-CFG-001 active tripcord/core@2027.01", 1),
	}
	for name, next := range bad {
		if err := CheckRegistryEvolution(mustRegistry(t, base), mustRegistry(t, next)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCoreRegistry checks the committed registry. LoadCore separately
// checks that active ids and rule files agree.
func TestCoreRegistry(t *testing.T) {
	data, err := os.ReadFile("../../rules/" + RegistryFile)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRegistry(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Entries() {
		if e.Introduced.Name != "tripcord/core" {
			t.Errorf("%s: introduced in %s", e.ID, e.Introduced)
		}
		if !strings.HasPrefix(e.ID, "TC-") {
			t.Errorf("%s: core ids start with TC-", e.ID)
		}
	}
}
