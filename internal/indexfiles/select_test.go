package indexfiles

import (
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
)

func TestChooseSkipsUnrelatedAndGitlinks(t *testing.T) {
	entries := []Entry{
		{Mode: "100644", OID: "1", Path: ".claude/settings.json", Size: 40, Body: []byte(`{"hooks":{}}`)},
		{Mode: "100644", OID: "2", Path: "src/main.go", Size: 8 << 20},
		{Mode: "100644", OID: "3", Path: "vendor/lib/blob.dat", Size: 4 << 20},
		{Mode: "160000", OID: "4", Path: "third_party/mod"},
		{Mode: "120000", OID: "5", Path: ".claude/hooks.json", Size: 16, Target: "../outside"},
	}
	plan, err := Choose(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Write{}
	for _, w := range plan.Writes {
		got[w.Path] = w
		if w.Path == "src/main.go" || w.Path == "vendor/lib/blob.dat" || w.Path == "third_party/mod" {
			t.Errorf("wrote unrelated path %s", w.Path)
		}
	}
	if _, ok := got[".claude/settings.json"]; !ok {
		t.Fatal("settings.json was not selected")
	}
	if _, ok := got[".claude/hooks.json"]; !ok {
		t.Fatal("relevant symlink was not selected")
	}
}

func TestCapsMatchScan(t *testing.T) {
	kitLimits := kit.DefaultLimits()
	claudeLimits := claude.DefaultLimits()
	if kitLimits.MaxDepth != maxDepth || claudeLimits.MaxDepth != maxDepth ||
		kitLimits.MaxEntries != maxEntries || claudeLimits.MaxEntries != maxEntries ||
		kitLimits.MaxFiles != maxFiles || claudeLimits.MaxFiles != maxFiles ||
		kitLimits.MaxBytes != maxBytes || claudeLimits.MaxBytes != maxBytes ||
		kitLimits.MaxFile != maxFile || claudeLimits.MaxFile != maxFile {
		t.Fatalf("staged caps drifted from scan limits: kit=%+v claude=%+v", kitLimits, claudeLimits)
	}
}

func TestHookPathCoversKnownShapes(t *testing.T) {
	for _, path := range []string{
		"GEMINI.md",
		"pkg/GEMINI.md",
		"tools/vgmartinez/skills/review/SKILL.md",
		".DevContainer/devcontainer.json",
		".DevContainer/Py/DevContainer.JSON",
		"services/api/.agents/skills/nested/SKILL.md",
		".claude/settings.json",
		"agents.override.md",
	} {
		if !HookPath(path) {
			t.Errorf("HookPath(%q) = false", path)
		}
	}
	if HookPath("src/main.go") {
		t.Fatal("source file is a hook path")
	}
}

// TestBudgetOversizeMatchesPlaceholder documents that indexfiles (used
// only by scan --staged, not preopen) treats a real >1 MiB blob and a
// cap+1 placeholder the same way: both exceed maxFile, so the file is
// kept as a sparse hole and its contents are never read or hashed.
func TestBudgetOversizeMatchesPlaceholder(t *testing.T) {
	for _, size := range []int64{2 << 20, adapters.MaxConfigFileBytes + 1} {
		nfiles := 0
		var nbytes int64
		keep, content, sparse, why := budget(size, &nfiles, &nbytes)
		if !keep || content || sparse != size || why != "" || nfiles != 1 || nbytes != 0 {
			t.Fatalf("size %d: keep=%v content=%v sparse=%d why=%q nfiles=%d nbytes=%d",
				size, keep, content, sparse, why, nfiles, nbytes)
		}
	}
}
