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
