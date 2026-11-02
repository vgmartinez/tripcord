package advisory

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSemverOrder(t *testing.T) {
	t.Parallel()
	if c, ok := cmpVersion(EcoNPM, "1.0.0-rc.1", "1.0.0"); !ok || c >= 0 {
		t.Fatalf("prerelease compare = %d %v", c, ok)
	}
	if c, ok := cmpVersion(EcoNPM, "1.0.0-1", "1.0.0-alpha"); !ok || c >= 0 {
		t.Fatalf("numeric prerelease compare = %d %v", c, ok)
	}
	if _, ok := CanonicalSemver("1.2"); ok {
		t.Fatal("partial version parsed as exact")
	}
	got, ok := CanonicalSemver("v1.2.3")
	if !ok || got != "1.2.3" {
		t.Fatalf("canonical = %q %v", got, ok)
	}
}

func TestPEP440Order(t *testing.T) {
	t.Parallel()
	pairs := [][2]string{
		{"1.0.dev1", "1.0a1"},
		{"1.0a1", "1.0"},
		{"1.0", "1.0.post1"},
		{"2025.9.25", "2025.12.18"},
	}
	for _, p := range pairs {
		c, ok := cmpVersion(EcoPyPI, p[0], p[1])
		if !ok || c >= 0 {
			t.Fatalf("%s < %s: compare = %d %v", p[0], p[1], c, ok)
		}
	}
	if _, ok := parsePep("1!1.0"); ok {
		t.Fatal("epoch parsed")
	}
	if _, ok := parsePep("1.0+local"); ok {
		t.Fatal("local version parsed")
	}
	if c, ok := cmpVersion(EcoPyPI, "1.0.0", "1.0"); !ok || c != 0 {
		t.Fatalf("trailing zero = %d %v", c, ok)
	}
}

func TestRangeCoverage(t *testing.T) {
	t.Parallel()
	figma := []Range{{Fixed: "0.6.3"}}
	covered, err := rangeCovered(EcoNPM, "~0.5.0", figma)
	if err != nil || !covered {
		t.Fatalf("~0.5.0 covered = %v %v", covered, err)
	}
	covered, err = rangeCovered(EcoNPM, "^0.6.0", figma)
	if err != nil || covered {
		t.Fatalf("^0.6.0 covered = %v %v", covered, err)
	}
	covered, err = rangeCovered(EcoNPM, "^0.6.0 || ~0.5.0", figma)
	if err != nil || covered {
		t.Fatalf("|| covered = %v %v", covered, err)
	}
	in, err := versionIn(EcoNPM, "0.6.2", figma)
	if err != nil || !in {
		t.Fatalf("0.6.2 in = %v %v", in, err)
	}
	in, err = versionIn(EcoNPM, "0.6.3", figma)
	if err != nil || in {
		t.Fatalf("0.6.3 in = %v %v", in, err)
	}
	git := []Range{{Fixed: "2026.1.14"}}
	covered, err = rangeCovered(EcoPyPI, ">=2025.1,<2027", git)
	if err != nil || covered {
		t.Fatalf("wide pypi range covered = %v %v", covered, err)
	}
	if !PyRangeOK("==1.2.*") || !PyRangeOK("~=1.4.2") {
		t.Fatal("pep operators")
	}
	if _, err := affected(Range{Introduced: "1.0.0", Fixed: "1.0.0"}, parseSemver, cmpSemver); err == nil {
		t.Fatal("introduced == fixed accepted")
	}
	if _, err := affected(Range{Fixed: "1.0.0", LastAffected: "0.9.0"}, parseSemver, cmpSemver); err == nil {
		t.Fatal("fixed and last_affected accepted")
	}
}

func TestRangeLimits(t *testing.T) {
	t.Parallel()
	var py, npm strings.Builder
	py.WriteString("<2025.9.25")
	npm.WriteString("<0.6.3")
	for i := range 20000 {
		py.WriteString(",!=2025.1." + strconv.Itoa(i))
		npm.WriteString(" || 0.0." + strconv.Itoa(i))
	}
	start := time.Now()
	_, pyErr := parsePyRanges(py.String())
	_, npmErr := parseNPMRanges(npm.String())
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("oversized ranges took %v", elapsed)
	}
	if pyErr == nil || npmErr == nil {
		t.Fatalf("oversized ranges accepted: %v %v", pyErr, npmErr)
	}
	if !PyRangeOK("<2026" + strings.Repeat(",!=1", MaxSpecClauses-1)) {
		t.Fatal("pep specifier at the clause limit rejected")
	}
	if PyRangeOK("<2026" + strings.Repeat(",!=1", MaxSpecClauses)) {
		t.Fatal("pep specifier over the clause limit accepted")
	}
	if NPMRangeOK(strings.Repeat("1.0.0 || ", MaxSpecClauses) + "1.0.0") {
		t.Fatal("npm range over the clause limit accepted")
	}
}
