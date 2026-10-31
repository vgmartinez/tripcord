package generic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestSharedSkillsUseGenericHarness(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	skill := "---\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: shared\n---\nbody\n"
	writeFile(t, filepath.Join(root, ".agents", "skills", "lint", "SKILL.md"), skill)
	writeFile(t, filepath.Join(root, ".github", "skills", "docs", "SKILL.md"), skill)
	writeFile(t, filepath.Join(root, ".claude", "skills", "own", "SKILL.md"), skill)
	writeFile(t, filepath.Join(root, "services", "api", ".agents", "skills", "nested", "SKILL.md"), skill)
	a := New(Options{})
	if !a.Detect(root) {
		t.Fatal("Detect missed shared skills")
	}
	items, err := a.Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, item := range items {
		if item.Harness != model.SurfaceGeneric {
			t.Errorf("harness = %s", item.Harness)
		}
		if err := item.Validate(); err != nil {
			t.Errorf("validate: %v", err)
		}
		paths[item.Path+" "+string(item.Kind)] = true
	}
	for _, want := range []string{
		".agents/skills/lint/SKILL.md skill",
		".agents/skills/lint/SKILL.md hook",
		".github/skills/docs/SKILL.md skill",
		"services/api/.agents/skills/nested/SKILL.md skill",
	} {
		if !paths[want] {
			t.Errorf("missing %s in %v", want, paths)
		}
	}
	if paths[".claude/skills/own/SKILL.md skill"] {
		t.Fatal("generic adapter read a Claude skill")
	}
}

func TestClaudeDoesNotClaimSharedSkills(t *testing.T) {
	t.Parallel()
	// Imported behavior is covered by the Claude package. This test only
	// checks that a repository whose only skills are shared still detects.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".github", "skills", "docs", "SKILL.md"), "---\nname: docs\n---\n")
	if !New(Options{}).Detect(root) {
		t.Fatal("Detect missed .github/skills")
	}
	onlyClaude := t.TempDir()
	writeFile(t, filepath.Join(onlyClaude, ".claude", "skills", "own", "SKILL.md"), "---\nname: own\n---\n")
	if New(Options{}).Detect(onlyClaude) {
		t.Fatal("Detect reported a Claude-only skill directory")
	}
}

func TestEscapingSkillSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "SKILL.md"), "---\nname: x\n---\n")
	if err := os.MkdirAll(filepath.Join(root, ".agents", "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".agents", "skills", "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	items, err := New(Options{}).Discover(context.Background(), root)
	var diag *adapters.DiagnosticError
	if !errors.As(err, &diag) {
		t.Fatalf("err = %v", err)
	}
	if len(items) != 0 || len(diag.Diagnostics) == 0 || !strings.Contains(diag.Error(), "outside the repository") {
		t.Fatalf("items %+v err %v", items, err)
	}
}

func TestSkipRepo(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".agents", "skills", "lint", "SKILL.md"), "---\nname: lint\n---\n")
	a := New(Options{SkipRepo: true})
	if a.Detect(root) {
		t.Fatal("Detect reported skills when the repository scope is off")
	}
	items, err := a.Discover(context.Background(), root)
	if err != nil || len(items) != 0 {
		t.Fatalf("items %+v err %v", items, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
