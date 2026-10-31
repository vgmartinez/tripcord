package rules

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"sh"}`),
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"node"}`),
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
	if strings.Join(got, ",") != "TEST-CFG-001@vscode,TEST-CFG-002@claude" {
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
	if len(f.Evidence) != 1 || f.Evidence[0].Config != "vscode:repo:.vscode/tasks.json" || f.Evidence[0].Event != "" || f.Evidence[0].Excerpt != "" {
		t.Fatalf("evidence = %+v", f.Evidence)
	}
	if f.Rule != "TEST-CFG-001" || f.Location.Path != ".vscode/tasks.json" || f.Location.Scope != model.ScopeRepo || len(f.Refs) != 1 || f.Fix == "" {
		t.Fatalf("finding = %+v", f)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"evidence":[{"config":"vscode:repo:.vscode/tasks.json"}]`) {
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
		item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":42}`),
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
