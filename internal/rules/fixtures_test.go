package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// TestRuleFixtures runs every rule's positivos and negativos. By default
// it covers the core pack in rules/ and the test fixture pack.
// `make test-rule ID=...` sets TRIPCORD_RULE_ID, and optionally
// TRIPCORD_RULES_DIR, to run one rule.
func TestRuleFixtures(t *testing.T) {
	dirs := []string{"../../rules", fixturePackDir}
	if d := os.Getenv("TRIPCORD_RULES_DIR"); d != "" {
		dirs = []string{d}
	}
	only := os.Getenv("TRIPCORD_RULE_ID")
	env := testEnv(t)
	found := false
	for _, dir := range dirs {
		pack, err := LoadDir(dir, env)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range pack.Rules {
			if only != "" && r.ID != only {
				continue
			}
			found = true
			t.Run(r.ID, func(t *testing.T) {
				if err := CheckRuleFixtures(context.Background(), env, dir, r, adapterDiscover); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	if only != "" && !found {
		t.Fatalf("rule %s not found in %s", only, strings.Join(dirs, ", "))
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRuleFixturesFailures(t *testing.T) {
	env := testEnv(t)
	pack, err := LoadDir(fixturePackDir, env)
	if err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for _, r := range pack.Rules {
		if r.ID == "TEST-CFG-002" {
			rule = r
		}
	}
	trigger := `{"harness":"claude","scope":"repo","path":".mcp.json","kind":"mcp-server","payload":{"command":"sh"}}`
	quiet := `{"harness":"claude","scope":"repo","path":".mcp.json","kind":"mcp-server","payload":{"command":"node"}}`
	outOfScope := `{"harness":"codex","scope":"repo","path":".mcp.json","kind":"mcp-server","payload":{"command":"sh"}}`
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"positive does not trigger": {map[string]string{"positivos/a.json": quiet, "negativos/b.json": quiet}, "did not trigger"},
		"negative triggers":         {map[string]string{"positivos/a.json": trigger, "negativos/b.json": trigger}, "negative fixture triggered"},
		"positive out of scope":     {map[string]string{"positivos/a.json": outOfScope, "negativos/b.json": quiet}, "no item matches"},
		"negative out of scope":     {map[string]string{"positivos/a.json": trigger, "negativos/b.json": outOfScope}, "no item matches"},
		"no negatives":              {map[string]string{"positivos/a.json": trigger}, "negativos"},
		"empty negatives":           {map[string]string{"positivos/a.json": trigger, "negativos/.keep": ""}, "at least one fixture"},
		"non-json file":             {map[string]string{"positivos/a.json": trigger, "negativos/tasks.yaml": "x: 1"}, "ConfigItem document or a directory"},
		"invalid item":              {map[string]string{"positivos/a.json": `{"harness":"emacs"}`, "negativos/b.json": quiet}, "harness"},
		"eval error":                {map[string]string{"positivos/a.json": trigger, "negativos/b.json": `{"harness":"claude","scope":"repo","path":".mcp.json","kind":"mcp-server","payload":{"command":1}}`}, "TEST-CFG-002"},
		"raw positive quiet":        {map[string]string{"positivos/repo/.mcp.json": `{"mcpServers":{"a":{"command":"node"}}}`, "negativos/b.json": quiet}, "did not trigger"},
		"raw negative triggers":     {map[string]string{"positivos/a.json": trigger, "negativos/repo/.mcp.json": `{"mcpServers":{"a":{"command":"sh"}}}`}, "negative fixture triggered"},
		"raw unreadable":            {map[string]string{"positivos/a.json": trigger, "negativos/repo/.mcp.json": `{`}, "not fully read"},
		"raw empty":                 {map[string]string{"positivos/a.json": trigger, "negativos/repo/README.md": "x"}, "no config items"},
		"severity mismatch":         {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "positivos:\n  a.json: high\n"}, "severities = [critical], want [high]"},
		"default severity":          {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "positivos:\n  a.json: [critical, high]\n"}, "want [critical high]"},
		"stale expectation":         {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "positivos:\n  gone.json: critical\n"}, "gone.json: no such fixture"},
		"bad severity":              {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "positivos:\n  a.json: severe\n"}, "severe"},
		"negative severity":         {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "negativos:\n  b.json: high\n"}, "can only expect error"},
		"positive error":            {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "positivos:\n  a.json: error\n"}, "error"},
		"expected error evaluates":  {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "negativos:\n  b.json: error\n"}, "expected TEST-CFG-002 to fail to evaluate"},
		"unknown key":               {map[string]string{"positivos/a.json": trigger, "negativos/b.json": quiet, ExpectFile: "positives:\n  a.json: critical\n"}, "positives"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, body := range c.files {
				writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, rel), body)
			}
			err := CheckRuleFixtures(context.Background(), env, dir, rule, adapterDiscover)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	t.Run("raw without discover", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "positivos/a.json"), trigger)
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "negativos/repo/.mcp.json"), `{"mcpServers":{"a":{"command":"node"}}}`)
		err := CheckRuleFixtures(context.Background(), env, dir, rule, nil)
		if err == nil || !strings.Contains(err.Error(), "need the harness adapters") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("passing", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "positivos/a.json"), "["+trigger+","+quiet+"]")
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "positivos/repo/.mcp.json"), `{"mcpServers":{"a":{"command":"sh"}}}`)
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "negativos/b.json"), quiet)
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "negativos/repo/.mcp.json"), `{"mcpServers":{"a":{"command":"node"}}}`)
		if err := CheckRuleFixtures(context.Background(), env, dir, rule, adapterDiscover); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("expected error and severities pass", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "positivos/a.json"), trigger)
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "negativos/b.json"), quiet)
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "negativos/c.json"), `{"harness":"claude","scope":"repo","path":".mcp.json","kind":"mcp-server","payload":{"command":1}}`)
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, ExpectFile), "positivos:\n  a.json: critical\nnegativos:\n  c.json: error\n")
		if err := CheckRuleFixtures(context.Background(), env, dir, rule, adapterDiscover); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("severity_when needs an expectation", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "positivos/a.json"), trigger)
		writeFile(t, filepath.Join(dir, rule.ID+TestDirSuffix, "negativos/b.json"), quiet)
		clauses := *rule
		clauses.SeverityWhen = []SeverityClause{{Severity: model.SeverityHigh, When: rule.When}}
		err := CheckRuleFixtures(context.Background(), env, dir, &clauses, adapterDiscover)
		if err == nil || !strings.Contains(err.Error(), "no expected severity") {
			t.Fatalf("err = %v", err)
		}
	})
}
