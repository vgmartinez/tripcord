package autorun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

const sha = "0000000000000000000000000000000000000000000000000000000000000000"

func hookItem(t *testing.T, h model.Harness, path, event, command string) model.ConfigItem {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"event": event, "type": "command", "command": command})
	if err != nil {
		t.Fatal(err)
	}
	return model.ConfigItem{Harness: h, Scope: model.ScopeRepo, Path: path, SHA256: sha, Kind: model.ConfigKindHook, Payload: payload}
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryEventsAndFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "scripts/setup.sh", "#!/bin/sh\n")
	items := []model.ConfigItem{
		hookItem(t, model.HarnessClaude, ".claude/settings.json", "SessionStart", "./scripts/setup.sh"),
		hookItem(t, model.HarnessClaude, ".claude/settings.local.json", "Setup", "./scripts/setup.sh"),
		hookItem(t, model.HarnessClaude, "sub/.claude/settings.json", "SessionStart", "./scripts/setup.sh"),
		hookItem(t, model.HarnessCursor, ".cursor/hooks.json", "sessionStart", "./scripts/setup.sh"),
		// Not auto-run events.
		hookItem(t, model.HarnessClaude, ".claude/settings.json", "PreToolUse", "./scripts/setup.sh"),
		hookItem(t, model.HarnessClaude, ".claude/settings.json", "sessionStart", "./scripts/setup.sh"),
		hookItem(t, model.HarnessCursor, ".cursor/hooks.json", "SessionStart", "./scripts/setup.sh"),
		// Not a file read when a session starts.
		hookItem(t, model.HarnessClaude, ".claude/skills/s/SKILL.md", "SessionStart", "./scripts/setup.sh"),
		hookItem(t, model.HarnessClaude, ".claude/agents/a.md", "SessionStart", "./scripts/setup.sh"),
		hookItem(t, model.HarnessClaude, "plugins/p/hooks/hooks.json", "SessionStart", "./scripts/setup.sh"),
		hookItem(t, model.HarnessCodex, ".codex/hooks.json", "SessionStart", "./scripts/setup.sh"),
		// No repository file.
		hookItem(t, model.HarnessClaude, ".claude/settings.json", "SessionStart", "echo hi"),
		hookItem(t, model.HarnessClaude, ".claude/settings.json", "SessionStart", "./scripts/missing.sh"),
	}
	user := hookItem(t, model.HarnessClaude, "~/.claude/settings.json", "SessionStart", "./scripts/setup.sh")
	user.Scope = model.ScopeUser
	items = append(items, user)
	got, err := Inventory(root, items)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Harness: model.HarnessClaude, Path: ".claude/settings.json", Event: "SessionStart", Command: "./scripts/setup.sh", Target: "scripts/setup.sh"},
		{Harness: model.HarnessClaude, Path: ".claude/settings.local.json", Event: "Setup", Command: "./scripts/setup.sh", Target: "scripts/setup.sh"},
		{Harness: model.HarnessCursor, Path: ".cursor/hooks.json", Event: "sessionStart", Command: "./scripts/setup.sh", Target: "scripts/setup.sh"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestInventoryNestedProject lists a nested project's hook with its
// script resolved from that project's directory.
func TestInventoryNestedProject(t *testing.T) {
	root := t.TempDir()
	write(t, root, "sub/scripts/setup.sh", "#!/bin/sh\n")
	got, err := Inventory(root, []model.ConfigItem{hookItem(t, model.HarnessClaude, "sub/.claude/settings.json", "SessionStart", "./scripts/setup.sh")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Target != "sub/scripts/setup.sh" {
		t.Fatalf("got %+v", got)
	}
}

// TestInventorySymlinkOutside leaves out a script whose symlink leaves
// the repository: it is not committed code, and TC-CFG-006 reports it.
func TestInventorySymlinkOutside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "x.sh")
	if err := os.WriteFile(outside, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "scripts", "setup.sh")); err != nil {
		t.Fatal(err)
	}
	got, err := Inventory(root, []model.ConfigItem{hookItem(t, model.HarnessClaude, ".claude/settings.json", "SessionStart", "./scripts/setup.sh")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestInventoryLine(t *testing.T) {
	root := t.TempDir()
	write(t, root, "scripts/a.sh", "#!/bin/sh\n")
	write(t, root, ".claude/settings.json", `{
  "hooks": {
    "PreToolUse": [
      { "hooks": [ { "type": "command", "command": "./scripts/a.sh" } ] }
    ],
    "SessionStart": [
      { "hooks": [
        { "type": "command", "command": "./scripts/a.sh" }
      ] }
    ]
  }
}
`)
	got, err := Inventory(root, []model.ConfigItem{hookItem(t, model.HarnessClaude, ".claude/settings.json", "SessionStart", "./scripts/a.sh")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Line != 8 {
		t.Fatalf("got %+v, want line 8", got)
	}
}

func TestLocate(t *testing.T) {
	raw := []byte("{\n \"SessionStart\": [\n  {\"command\": \"a && b\"}\n ],\n \"x\": \"\\u0061\"\n}\n")
	for _, tc := range []struct {
		key, value string
		want       int
	}{
		{"SessionStart", "a && b", 3},
		{"SessionStart", "missing", 2},
		{"SessionStart", "", 2},
		// The file writes "a" as "\u0061", which is not how
		// encoding/json writes it: the key's line.
		{"x", "a", 5},
		{"Setup", "a && b", 0},
	} {
		if got := locate(raw, tc.key, tc.value); got != tc.want {
			t.Errorf("locate(%q, %q) = %d, want %d", tc.key, tc.value, got, tc.want)
		}
	}
	if locate(nil, "SessionStart", "a") != 0 {
		t.Error("an unread file has a line")
	}
}

// TestInventoryOversizedFileHasNoLine keeps the entry and drops only the
// line when the configuration file is larger than an adapter reads.
func TestInventoryOversizedFileHasNoLine(t *testing.T) {
	root := t.TempDir()
	write(t, root, "scripts/a.sh", "#!/bin/sh\n")
	big := make([]byte, maxConfigBytes+1)
	for i := range big {
		big[i] = ' '
	}
	write(t, root, ".claude/settings.json", `{"SessionStart": "./scripts/a.sh"}`+string(big))
	got, err := Inventory(root, []model.ConfigItem{hookItem(t, model.HarnessClaude, ".claude/settings.json", "SessionStart", "./scripts/a.sh")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Line != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestInventoryModule(t *testing.T) {
	root := t.TempDir()
	write(t, root, "p/hooks/hooks.json", "{\n  \"modules\": [\"./register.tsx\"]\n}\n")
	payload, _ := json.Marshal(map[string]any{"setting": "modules", "module": "./register.tsx", "module_path": "p/hooks/register.tsx", "plugin_root": "p"})
	item := model.ConfigItem{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: "p/hooks/hooks.json", SHA256: sha, Kind: model.ConfigKindPlugin, Payload: payload}
	other, _ := json.Marshal(map[string]any{"setting": "plugin", "value": map[string]any{"name": "p"}})
	manifest := model.ConfigItem{Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: "p/.claude-plugin/plugin.json", SHA256: sha, Kind: model.ConfigKindPlugin, Payload: other}
	got, err := Inventory(root, []model.ConfigItem{manifest, item})
	if err != nil {
		t.Fatal(err)
	}
	want := Entry{Harness: model.HarnessClaude, Path: "p/hooks/hooks.json", Line: 2, Event: EventModules, Command: "./register.tsx", Target: "p/hooks/register.tsx"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
