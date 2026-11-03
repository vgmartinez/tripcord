package embedded

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func embed(t *testing.T, harnesses ...model.Harness) string {
	t.Helper()
	dir := t.TempDir()
	changes, err := Plan(dir, Options{Embed: true, Harnesses: harnesses, Pin: testPin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(dir, changes); err != nil {
		t.Fatal(err)
	}
	return dir
}

type guardHit struct {
	harness model.Harness
	path    string
	event   string
	state   string
}

func check(t *testing.T, dir string, only ...model.Harness) []guardHit {
	t.Helper()
	items, err := Check(dir, only)
	if err != nil {
		t.Fatal(err)
	}
	var hits []guardHit
	for _, item := range items {
		if err := item.Validate(); err != nil {
			t.Fatal(err)
		}
		var p map[string]string
		if err := json.Unmarshal(item.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p["setting"] != GuardSetting || item.Kind != model.ConfigKindPermissions || item.Scope != model.ScopeRepo {
			t.Fatalf("item = %+v", item)
		}
		hits = append(hits, guardHit{item.Harness, item.Path, p["event"], p["state"]})
	}
	return hits
}

func TestCheckFreshEmbedIsIntact(t *testing.T) {
	if hits := check(t, embed(t)); len(hits) != 0 {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestCheckNoEmbed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, PolicyPath, string(DefaultPolicy()))
	if hits := check(t, dir); len(hits) != 0 {
		t.Fatalf("policy alone is not an embed: %+v", hits)
	}
}

func TestCheckStates(t *testing.T) {
	dir := embed(t)
	if err := os.Remove(filepath.Join(dir, ".github", "hooks", "tripcord.json")); err != nil {
		t.Fatal(err)
	}
	write(t, dir, ClaudeSettingsPath, "{\"hooks\": {\"PreToolUse\": [{\"matcher\": \"*\", \"hooks\": [{\"type\": \"command\", \"command\": \"tripcord\"}]}]}}")
	write(t, dir, CursorHooksPath, "{ not json")
	got := check(t, dir)
	want := []guardHit{
		{model.HarnessClaude, ClaudeSettingsPath, "SessionStart", StateMissing},
		{model.HarnessClaude, ClaudeSettingsPath, "PreToolUse", StateChanged},
		{model.HarnessCursor, CursorHooksPath, "sessionStart", StateUnreadable},
		{model.HarnessCursor, CursorHooksPath, "preToolUse", StateUnreadable},
		{model.HarnessCopilot, CopilotHooksPath, "sessionStart", StateMissing},
		{model.HarnessCopilot, CopilotHooksPath, "preToolUse", StateMissing},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("hits = %+v\nwant %+v", got, want)
	}
	if got := check(t, dir, model.HarnessCopilot); len(got) != 2 || got[0].harness != model.HarnessCopilot {
		t.Fatalf("only copilot: %+v", got)
	}
}

func TestCheckCursorJSONCIsRead(t *testing.T) {
	dir := embed(t, model.HarnessCursor)
	raw, err := os.ReadFile(filepath.Join(dir, ".cursor", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, CursorHooksPath, "// kept by the team\n"+strings.Replace(string(raw), "]\n  }", "],\n  }", 1))
	if hits := check(t, dir); len(hits) != 0 {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestCheckOnlySelectedHarnesses(t *testing.T) {
	dir := embed(t, model.HarnessClaude, model.HarnessDevin)
	if hits := check(t, dir); len(hits) != 0 {
		t.Fatalf("hits = %+v", hits)
	}
	if err := os.Remove(filepath.Join(dir, ".tripcord", "embed.json")); err != nil {
		t.Fatal(err)
	}
	// Without the manifest every hook harness is required.
	hits := check(t, dir)
	if len(hits) != 4 || hits[0].harness != model.HarnessCursor || hits[2].harness != model.HarnessCopilot {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestCheckRecordedDigestMismatch(t *testing.T) {
	dir := embed(t, model.HarnessClaude)
	p := filepath.Join(dir, ".tripcord", "embed.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := HookEntries(model.HarnessClaude)[1].SHA256()
	if err := os.WriteFile(p, []byte(strings.Replace(string(raw), want, strings.Repeat("f", 64), 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if hits := check(t, dir); len(hits) != 1 || hits[0].event != "PreToolUse" || hits[0].state != StateChanged {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestCheckSymlinkedWiringOutsideIsUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := embed(t, model.HarnessClaude)
	outside := t.TempDir()
	raw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, outside, "settings.json", string(raw))
	if err := os.Remove(filepath.Join(dir, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "settings.json"), filepath.Join(dir, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	hits := check(t, dir)
	if len(hits) != 2 || hits[0].state != StateUnreadable {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestHookEntryDigestsAreStable(t *testing.T) {
	// The digests are recorded in every embedded repository's
	// embed.json: changing them makes every existing embed report
	// TC-CFG-016 until it reruns init.
	want := map[string]string{}
	for _, h := range HookHarnesses {
		for _, e := range HookEntries(h) {
			if len(e.SHA256()) != 64 {
				t.Fatalf("%s %s digest = %q", h, e.Event, e.SHA256())
			}
			want[string(h)+" "+e.Event] = e.SHA256()
		}
	}
	m := newManifest("0.1.0", Harnesses)
	if len(m.Hooks) != len(want) {
		t.Fatalf("manifest hooks = %d, want %d", len(m.Hooks), len(want))
	}
	for _, hook := range m.Hooks {
		if want[hook.Harness+" "+hook.Event] != hook.SHA256 {
			t.Errorf("manifest %s %s = %s", hook.Harness, hook.Event, hook.SHA256)
		}
	}
}
