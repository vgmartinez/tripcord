package rules

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/model"
)

func fixtureEngine(t *testing.T) (*Engine, *Catalog) {
	t.Helper()
	env := testEnv(t)
	pack, err := LoadDir(fixturePackDir, env)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCatalog(pack)
	if err != nil {
		t.Fatal(err)
	}
	return NewEngine(env, c.Rules()), c
}

func item(h model.Harness, path string, kind model.ConfigKind, payload string) model.ConfigItem {
	return model.ConfigItem{
		Harness: h, Scope: model.ScopeRepo, Path: path, Kind: kind,
		SHA256: strings.Repeat("a", 64), Payload: json.RawMessage(payload),
	}
}

func TestScanConfig(t *testing.T) {
	engine, _ := fixtureEngine(t)
	items := []model.ConfigItem{
		item(model.SurfaceVSCode, ".vscode/tasks.json", model.ConfigKindTask, `{"runOptions":{"runOn":"folderOpen"}}`),
		item(model.SurfaceVSCode, ".vscode/tasks.json", model.ConfigKindTask, `{"label":"build"}`),
		item(model.HarnessClaude, ".vscode/tasks.json", model.ConfigKindTask, `{"runOptions":{"runOn":"folderOpen"}}`),
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"sh","tools":["a"]}`),
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"node","tools":["a"]}`),
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{}`),
	}
	res := engine.ScanConfig(context.Background(), items)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	var got []string
	for _, m := range res.Matches {
		got = append(got, m.Rule.ID+"@"+m.Item.Harness.String())
	}
	if strings.Join(got, ",") != "TEST-CFG-001@vscode,TEST-CFG-002@claude,TEST-CFG-004@claude" {
		t.Fatalf("matches = %v", got)
	}
}

func TestMatchFinding(t *testing.T) {
	engine, _ := fixtureEngine(t)
	it := item(model.SurfaceVSCode, ".vscode/tasks.json", model.ConfigKindTask, `{"runOptions":{"runOn":"folderOpen"}}`)
	res := engine.ScanConfig(context.Background(), []model.ConfigItem{it})
	if len(res.Matches) != 1 {
		t.Fatalf("res = %+v", res)
	}
	f, err := res.Matches[0].Finding(model.SeverityHigh, model.DecisionDeny)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Config == nil || f.Evidence[0].Config.ID != "vscode:repo:.vscode/tasks.json" || f.Evidence[0].Config.Key != "" || f.Evidence[0].Event != "" || f.Evidence[0].Excerpt != "" {
		t.Fatalf("evidence = %+v", f.Evidence)
	}
	if f.Rule != "TEST-CFG-001" || f.Location.Path != ".vscode/tasks.json" || f.Location.Scope != model.ScopeRepo || len(f.Refs) != 1 || f.Fix == "" {
		t.Fatalf("finding = %+v", f)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"evidence":[{"config":{"id":"vscode:repo:.vscode/tasks.json"}}]`) {
		t.Fatalf("json = %s", raw)
	}
	if len(f.Fingerprint) != len("tcf_")+16 {
		t.Fatalf("fingerprint %q", f.Fingerprint)
	}

	// Editing the file changes sha256 but not the finding's identity.
	edited := it
	edited.SHA256 = strings.Repeat("f", 64)
	g, err := Match{Rule: res.Matches[0].Rule, Item: edited}.Finding(model.SeverityHigh, model.DecisionDeny)
	if err != nil || g.Fingerprint != f.Fingerprint {
		t.Fatalf("fingerprint changed: %s vs %s (%v)", g.Fingerprint, f.Fingerprint, err)
	}
	if _, err := res.Matches[0].Finding("urgent", model.DecisionDeny); err == nil {
		t.Fatal("invalid severity accepted")
	}
}

func TestEvidenceKey(t *testing.T) {
	_, cat := fixtureEngine(t)
	rule, ok := cat.Rule("TEST-CFG-001")
	if !ok {
		t.Fatal("missing fixture rule")
	}
	find := func(payload string, kind model.ConfigKind) model.Finding {
		t.Helper()
		it := item(model.SurfaceVSCode, ".vscode/tasks.json", kind, payload)
		f, err := (Match{Rule: rule, Item: it}).Finding(model.SeverityHigh, model.DecisionDeny)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	setup := find(`{"label":" setup ","runOptions":{"runOn":"folderOpen"}}`, model.ConfigKindTask)
	build := find(`{"label":"build","runOptions":{"runOn":"folderOpen"}}`, model.ConfigKindTask)
	plain := find(`{"runOptions":{"runOn":"folderOpen"}}`, model.ConfigKindTask)
	if setup.Evidence[0].Config.Key != "setup" || build.Evidence[0].Config.Key != "build" || plain.Evidence[0].Config.Key != "" {
		t.Fatalf("task keys: %q %q %q", setup.Evidence[0].Config.Key, build.Evidence[0].Config.Key, plain.Evidence[0].Config.Key)
	}
	if setup.Fingerprint == build.Fingerprint || setup.Fingerprint == plain.Fingerprint {
		t.Fatal("entries in one file share a fingerprint")
	}
	numbered := find(`{"label":1,"runOptions":{"runOn":"folderOpen"}}`, model.ConfigKindTask)
	if numbered.Evidence[0].Config.Key != "" || numbered.Fingerprint != plain.Fingerprint {
		t.Fatalf("non-string label became a key: %q", numbered.Evidence[0].Config.Key)
	}

	server := find(`{"name":"filesystem","command":"npx"}`, model.ConfigKindMCPServer)
	if server.Evidence[0].Config.Key != "filesystem" {
		t.Fatalf("mcp key %q", server.Evidence[0].Config.Key)
	}
	unnamed := find(`{"command":"sh"}`, model.ConfigKindMCPServer)
	if unnamed.Evidence[0].Config.Key != "" {
		t.Fatalf("command used as mcp name: %q", unnamed.Evidence[0].Config.Key)
	}

	hook := item(model.HarnessClaude, ".claude/settings.json", model.ConfigKindHook, `{"matcher":"PreToolUse","command":"curl"}`)
	hf, err := (Match{Rule: rule, Item: hook}).Finding(model.SeverityHigh, model.DecisionDeny)
	if err != nil {
		t.Fatal(err)
	}
	if hf.Evidence[0].Config.Key != "PreToolUse|curl" {
		t.Fatalf("hook key %q", hf.Evidence[0].Config.Key)
	}
	matcherOnly := item(model.HarnessClaude, ".claude/settings.json", model.ConfigKindHook, `{"matcher":"PreToolUse"}`)
	mf, err := (Match{Rule: rule, Item: matcherOnly}).Finding(model.SeverityHigh, model.DecisionDeny)
	if err != nil || mf.Evidence[0].Config.Key != "PreToolUse|" {
		t.Fatalf("matcher-only key %q (%v)", mf.Evidence[0].Config.Key, err)
	}
	note := find(`{"label":"setup"}`, model.ConfigKindInstructions)
	if note.Evidence[0].Config.Key != "" {
		t.Fatalf("instructions key %q", note.Evidence[0].Config.Key)
	}
}

func TestConfigIDVariable(t *testing.T) {
	env := testEnv(t)
	it := item(model.HarnessClaude, "~/.claude/settings.json", model.ConfigKindHook, `{}`)
	if _, err := ConfigInput(it, env.Limits()); err == nil {
		t.Fatal("user path accepted for repo scope")
	}
	it.Scope = model.ScopeUser
	in, err := ConfigInput(it, env.Limits())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := compileT(t, env, `config.id == "claude:user:~/.claude/settings.json" && config.scope == "user"`).Eval(context.Background(), in)
	if err != nil || !ok {
		t.Fatalf("got %v, %v", ok, err)
	}
}

func TestScanConfigErrorsAreNotMatches(t *testing.T) {
	engine, _ := fixtureEngine(t)
	items := []model.ConfigItem{
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":42,"tools":["a"]}`),
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{not json`),
	}
	res := engine.ScanConfig(context.Background(), items)
	if len(res.Matches) != 0 || len(res.Errors) != 2 {
		t.Fatalf("matches %v errors %v", res.Matches, res.Errors)
	}
	if res.Errors[0].Rule != "TEST-CFG-002" || res.Errors[1].Rule != "" {
		t.Fatalf("errors = %v", res.Errors)
	}
}

func TestScanConfigInputLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxInputBytes = 32
	env, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := LoadDir(fixturePackDir, env)
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(env, pack.Rules)
	big := `{"command":"sh","pad":"` + strings.Repeat("x", 64) + `"}`
	res := engine.ScanConfig(context.Background(), []model.ConfigItem{item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, big)})
	if len(res.Matches) != 0 || len(res.Errors) != 1 || !errors.Is(res.Errors[0].Err, ErrInputLimit) {
		t.Fatalf("res = %+v", res)
	}
}

func TestScanConfigCancelled(t *testing.T) {
	engine, _ := fixtureEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := engine.ScanConfig(ctx, []model.ConfigItem{item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"sh"}`)})
	if len(res.Matches) != 0 || len(res.Errors) != 1 || !errors.Is(res.Errors[0].Err, context.Canceled) {
		t.Fatalf("res = %+v", res)
	}
}

func TestScanConfigFilter(t *testing.T) {
	_, c := fixtureEngine(t)
	engine := NewEngine(testEnv(t), c.Rules(), WithFilter(func(r *Rule, it model.ConfigItem) bool {
		return r.ID != "TEST-CFG-004" && it.Harness != model.HarnessCursor
	}))
	items := []model.ConfigItem{
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"sh"}`),
		item(model.HarnessCursor, ".cursor/mcp.json", model.ConfigKindMCPServer, `{"command":"sh"}`),
	}
	res := engine.ScanConfig(context.Background(), items)
	if len(res.Errors) != 0 || len(res.Matches) != 1 || res.Matches[0].Rule.ID != "TEST-CFG-002" || res.Matches[0].Item.Harness != model.HarnessClaude {
		t.Fatalf("matches %v errors %v", res.Matches, res.Errors)
	}
}

func TestScanConfigBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.Budget = time.Nanosecond
	benv, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := LoadDir(fixturePackDir, benv)
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(benv, pack.Rules)
	res := engine.ScanConfig(context.Background(), []model.ConfigItem{
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"sh"}`),
	})
	if len(res.Matches) != 0 || len(res.Errors) != 1 || !errors.Is(res.Errors[0].Err, ErrBudget) {
		t.Fatalf("matches %v errors %v", res.Matches, res.Errors)
	}
}
