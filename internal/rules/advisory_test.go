package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestAdvisoryFinding(t *testing.T) {
	env := testEnv(t)
	pack, err := LoadCore(env)
	if err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for _, r := range pack.Rules {
		if r.ID == "TC-CFG-023" {
			rule = r
		}
	}
	if rule == nil {
		t.Fatal("TC-CFG-023 missing")
	}
	item := model.ConfigItem{
		Harness: model.HarnessClaude,
		Scope:   model.ScopeRepo,
		Path:    ".mcp.json",
		Kind:    model.ConfigKindMCPServer,
		Payload: []byte(`{"name":"ui","command":"uvx","args":["--with","prefab-ui==0.20.2","my-fastmcp-server"]}`),
	}
	res := NewEngine(env, []*Rule{rule}).ScanConfig(context.Background(), []model.ConfigItem{item})
	if len(res.Errors) > 0 || len(res.Matches) != 1 {
		t.Fatalf("matches %d errors %v", len(res.Matches), res.Errors)
	}
	if res.Matches[0].Severity != model.SeverityCritical {
		t.Fatalf("severity %s", res.Matches[0].Severity)
	}
	f, err := res.Matches[0].Finding(res.Matches[0].Severity, model.DecisionWarn)
	if err != nil {
		t.Fatal(err)
	}
	if f.Evidence[0].Excerpt != "pkg:pypi/prefab-ui@0.20.2 TCA-2026-0001" {
		t.Fatalf("excerpt %q", f.Evidence[0].Excerpt)
	}
	if !strings.Contains(f.Title, "prefab-ui@0.20.2") || !strings.Contains(f.Title, "fixed in 0.21.0") {
		t.Fatalf("title %q", f.Title)
	}
	if !strings.Contains(strings.Join(f.Refs, " "), "https://osv.dev/") || !strings.Contains(strings.Join(f.Refs, " "), "GHSA-3g72-rrqc-f76c") {
		t.Fatalf("refs %v", f.Refs)
	}
	if f.Fingerprint == "" {
		t.Fatal("empty fingerprint")
	}

	git := item
	git.Payload = []byte(`{"name":"git","command":"uvx","args":["mcp-server-git==2025.9.0"]}`)
	res = NewEngine(env, []*Rule{rule}).ScanConfig(context.Background(), []model.ConfigItem{git})
	if len(res.Matches) != 1 || res.Matches[0].Severity != model.SeverityHigh {
		t.Fatalf("git server %+v %v", res.Matches, res.Errors)
	}
	f, err = res.Matches[0].Finding(res.Matches[0].Severity, model.DecisionWarn)
	if err != nil {
		t.Fatal(err)
	}
	if f.Evidence[0].Excerpt != "pkg:pypi/mcp-server-git@2025.9.0 TCA-2026-0005 TCA-2026-0006 TCA-2026-0007 TCA-2026-0008" {
		t.Fatalf("excerpt %q", f.Evidence[0].Excerpt)
	}
	if !strings.Contains(f.Title, "fixed in 2026.1.14") {
		t.Fatalf("title %q", f.Title)
	}

	var prints []string
	for _, p := range []string{"/home/alice/kali-gpt/kali_gpt/tools/mcp_server.py", "/home/bob/src/kali_gpt/tools/mcp_server.py"} {
		mod := item
		mod.Payload = []byte(`{"name":"kali","command":"python3","args":["` + p + `"]}`)
		res = NewEngine(env, []*Rule{rule}).ScanConfig(context.Background(), []model.ConfigItem{mod})
		if len(res.Matches) != 1 {
			t.Fatalf("module path %+v %v", res.Matches, res.Errors)
		}
		f, err = res.Matches[0].Finding(res.Matches[0].Severity, model.DecisionWarn)
		if err != nil {
			t.Fatal(err)
		}
		if f.Evidence[0].Excerpt != "pkg:generic/kali_gpt/tools/mcp_server.py TCA-2026-0002" || strings.Contains(f.Title, "/home/") {
			t.Fatalf("module finding carries the local path: excerpt %q title %q", f.Evidence[0].Excerpt, f.Title)
		}
		prints = append(prints, f.Fingerprint)
	}
	if prints[0] != prints[1] {
		t.Fatalf("module fingerprint depends on the local path: %v", prints)
	}
}
