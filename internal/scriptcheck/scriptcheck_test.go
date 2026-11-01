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
		{hook("tools/acme/hooks/hooks.json", `{"command":"./scripts/x.sh"}`), nil},
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
	items := []model.ConfigItem{
		hook(".claude/settings.json", `{"command":".claude/hooks/present.sh && .claude/hooks/gone.sh && bash .claude/hooks/also-gone.sh"}`),
		hook(".claude/settings.json", `{"command":".claude/hooks/present.sh"}`),
		hook(".claude/settings.json", `{"command":".claude/hooks/escape.sh"}`),
		{Harness: model.HarnessClaude, Scope: model.ScopeUser, Path: "~/.claude/settings.json", Kind: model.ConfigKindHook, Payload: []byte(`{"command":"./gone.sh"}`)},
		{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".claude/settings.json", Kind: model.ConfigKindPermissions, Payload: []byte(`{"command":"./gone.sh"}`)},
	}
	if err := Annotate(root, items); err != nil {
		t.Fatal(err)
	}
	var got []int
	for _, item := range items {
		got = append(got, int(item.MissingScripts))
	}
	if want := []int{2, 0, 0, 0, 0}; !slices.Equal(got, want) {
		t.Fatalf("MissingScripts = %v, want %v", got, want)
	}
}
