package scriptcheck

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func hook(path, payload string) model.ConfigItem {
	return model.ConfigItem{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: path, Kind: model.ConfigKindHook, Payload: []byte(payload)}
}

func TestScripts(t *testing.T) {
	cases := []struct {
		item model.ConfigItem
		want []string
	}{
		{hook(".claude/settings.json", `{"command":"\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/guard.sh"}`), []string{".claude/hooks/guard.sh"}},
		{hook("packages/web/.claude/settings.json", `{"command":"./scripts/x.sh"}`), []string{"packages/web/scripts/x.sh"}},
		{hook(".github/hooks/a.json", `{"bash":"./a.sh","powershell":".\\a.ps1","cwd":"tools"}`), []string{"tools/a.sh"}},
		{hook(".github/hooks/a.json", `{"exec":"node","args":[".github/hooks/lint.js","--out","/tmp/x"]}`), []string{".github/hooks/lint.js"}},
		{hook(".github/hooks/a.json", `{"bash":"./a.sh","cwd":"../elsewhere"}`), nil},
		{hook(".github/hooks/a.json", `{"bash":"./a.sh","cwd":1}`), nil},
		{hook(".claude/skills/fmt/SKILL.md", `{"command":"./scripts/fmt.sh"}`), []string{"scripts/fmt.sh"}},
		{hook("tools/vgmartinez/hooks/hooks.json", `{"command":"./scripts/x.sh"}`), nil},
		{hook(".claude/settings.json", `{"type":"http","url":"https://x.invalid"}`), nil},
	}
	for _, c := range cases {
		if got := Scripts(c.item); !slices.Equal(got, c.want) {
			t.Errorf("%s %s = %q, want %q", c.item.Path, c.item.Payload, got, c.want)
		}
	}
	raw := hook(".claude/settings.json", `{"command":"[REDACTED]"}`)
	raw.Detect = []byte(`{"command":"./raw.sh"}`)
	if got := Scripts(raw); !slices.Equal(got, []string{"raw.sh"}) {
		t.Errorf("Detect view not read: %q", got)
	}
}

func TestAnnotate(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "hooks", "present.sh"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "x.sh")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".claude", "hooks", "escape.sh")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("/nonexistent/x.sh", filepath.Join(root, ".claude", "hooks", "broken.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("present.sh", filepath.Join(root, ".claude", "hooks", "inside.sh")); err != nil {
		t.Fatal(err)
	}
	items := []model.ConfigItem{
		hook(".claude/settings.json", `{"command":".claude/hooks/present.sh && .claude/hooks/gone.sh && bash .claude/hooks/also-gone.sh"}`),
		hook(".claude/settings.json", `{"command":".claude/hooks/present.sh"}`),
		hook(".claude/settings.json", `{"command":".claude/hooks/escape.sh"}`),
		hook(".claude/settings.json", `{"command":".claude/hooks/broken.sh"}`),
		hook(".claude/settings.json", `{"command":".claude/hooks/inside.sh"}`),
		{Harness: model.HarnessClaude, Scope: model.ScopeUser, Path: "~/.claude/settings.json", Kind: model.ConfigKindHook, Payload: []byte(`{"command":"./gone.sh"}`)},
		{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".claude/settings.json", Kind: model.ConfigKindPermissions, Payload: []byte(`{"command":"./gone.sh"}`)},
	}
	if _, err := os.Stat("/etc/passwd"); err == nil {
		if err := os.Symlink("/etc/passwd", filepath.Join(root, ".claude", "hooks", "system.sh")); err != nil {
			t.Fatal(err)
		}
		items = append(items, hook(".claude/settings.json", `{"command":".claude/hooks/system.sh"}`))
	}
	home, err := os.UserHomeDir()
	if err == nil {
		target := filepath.Join(home, ".tripcord-scriptcheck-home.sh")
		if err := os.WriteFile(target, nil, 0o600); err == nil {
			t.Cleanup(func() { _ = os.Remove(target) })
			if err := os.Symlink(target, filepath.Join(root, ".claude", "hooks", "home.sh")); err != nil {
				t.Fatal(err)
			}
			items = append(items, hook(".claude/settings.json", `{"command":".claude/hooks/home.sh"}`))
		}
	}
	if err := Annotate(root, items); err != nil {
		t.Fatal(err)
	}
	var gotMissing []int
	for _, item := range items[:7] {
		gotMissing = append(gotMissing, int(item.MissingScripts))
	}
	if want := []int{2, 0, 0, 1, 0, 0, 0}; !slices.Equal(gotMissing, want) {
		t.Fatalf("MissingScripts = %v, want %v", gotMissing, want)
	}
	if got, want := items[2].ScriptLocations, []string{outsideClass(outside)}; !slices.Equal(got, want) || want[0] == "" {
		t.Fatalf("outside symlink class = %v, want %v", got, want)
	}
	if len(items[4].ScriptLocations) != 0 {
		t.Fatalf("inside symlink class = %v", items[4].ScriptLocations)
	}
	for _, item := range items[7:] {
		if item.MissingScripts != 0 || len(item.ScriptLocations) != 1 {
			t.Fatalf("outside symlink = missing %d class %v", item.MissingScripts, item.ScriptLocations)
		}
		switch item.ScriptLocations[0] {
		case "absolute", "home":
		default:
			t.Fatalf("symlink class = %v", item.ScriptLocations)
		}
	}
}

func TestSymlinkedDirectories(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.Symlink("/tmp", probe); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	tmpFile := filepath.Join("/tmp", "tripcord-scriptcheck-x.sh")
	if err := os.WriteFile(tmpFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tmpFile) })
	nested := filepath.Join("/tmp", "tripcord-scriptcheck-b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "x.sh"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(nested) })

	repo := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
			t.Fatal(err)
		}
		return root
	}
	check := func(t *testing.T, root, command string, missing int, class string) {
		t.Helper()
		items := []model.ConfigItem{hook(".claude/settings.json", `{"command":`+command+`}`)}
		if err := Annotate(root, items); err != nil {
			t.Fatal(err)
		}
		if int(items[0].MissingScripts) != missing || !slices.Equal(items[0].ScriptLocations, loc(class)) {
			t.Fatalf("missing %d class %v, want missing %d class %q", items[0].MissingScripts, items[0].ScriptLocations, missing, class)
		}
	}

	t.Run("directory to tmp", func(t *testing.T) {
		root := repo(t)
		if err := os.Symlink("/tmp", filepath.Join(root, "scripts")); err != nil {
			t.Fatal(err)
		}
		check(t, root, `"./scripts/tripcord-scriptcheck-x.sh"`, 0, "temp")
	})
	t.Run("directory to etc", func(t *testing.T) {
		if _, err := os.Stat("/etc/passwd"); err != nil {
			t.Skip(err)
		}
		root := repo(t)
		if err := os.Symlink("/etc", filepath.Join(root, "scripts")); err != nil {
			t.Fatal(err)
		}
		check(t, root, `"./scripts/passwd"`, 0, "absolute")
	})
	t.Run("dotdot", func(t *testing.T) {
		root := repo(t)
		if err := os.Symlink("/tmp/..", filepath.Join(root, "a")); err != nil {
			t.Fatal(err)
		}
		check(t, root, `"./a/tmp/tripcord-scriptcheck-b/x.sh"`, 0, "temp")
	})
	t.Run("nested link", func(t *testing.T) {
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "x.sh"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		root := repo(t)
		if err := os.MkdirAll(filepath.Join(root, "a"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "a", "b")); err != nil {
			t.Fatal(err)
		}
		check(t, root, `"./a/b/x.sh"`, 0, outsideClass(filepath.Join(outside, "x.sh")))
	})
	t.Run("chain", func(t *testing.T) {
		root := repo(t)
		if err := os.Symlink("/tmp", filepath.Join(root, "c")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("c", filepath.Join(root, "b")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("b", filepath.Join(root, "a")); err != nil {
			t.Fatal(err)
		}
		check(t, root, `"./a/tripcord-scriptcheck-x.sh"`, 0, "temp")
	})
	t.Run("project dir", func(t *testing.T) {
		root := repo(t)
		if err := os.Symlink("/tmp", filepath.Join(root, "scripts")); err != nil {
			t.Fatal(err)
		}
		check(t, root, `"\"$CLAUDE_PROJECT_DIR\"/scripts/tripcord-scriptcheck-x.sh"`, 0, "temp")
	})
	t.Run("bash", func(t *testing.T) {
		root := repo(t)
		if err := os.Symlink("/tmp", filepath.Join(root, "scripts")); err != nil {
			t.Fatal(err)
		}
		check(t, root, `"bash scripts/tripcord-scriptcheck-x.sh"`, 0, "temp")
	})
	t.Run("root is a symlink", func(t *testing.T) {
		real := repo(t)
		if err := os.WriteFile(filepath.Join(real, ".claude", "present.sh"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "repo")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		check(t, link, `".claude/present.sh"`, 0, "")
	})
}

func loc(class string) []string {
	if class == "" {
		return nil
	}
	return []string{class}
}
