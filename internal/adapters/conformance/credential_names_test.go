package conformance

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// credentialNames are env-style names whose value is a credential even
// though most do not contain "token" or "password".
var credentialNames = []string{"SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "DB_PASS", "PASS"}

// plantCredential writes name=value into Gemini hooks and MCP servers,
// Windsurf and Devin hooks and Windsurf MCP servers, and devcontainer
// env, lifecycle commands, and runArgs.
func plantCredential(t *testing.T, root, home, name, value string) {
	t.Helper()
	assign := name + "=" + value
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), `{
		"hooksConfig": {"disabled": ["`+assign+` ./unnamed.sh"]},
		"hooks": {"BeforeTool": [{"matcher": "run_shell_command", "hooks": [
			{"type": "command", "name": "guard", "command": "`+assign+` ./guard.sh"},
			{"type": "command", "command": "`+assign+` ./unnamed.sh"},
			{"type": "command", "command": "./env.sh", "env": {"`+name+`": "`+value+`"}}
		]}]},
		"mcpServers": {
			"argv": {"command": "node", "args": ["srv.js", "`+assign+`"]},
			"env": {"command": "node", "args": ["srv.js"], "env": {"`+name+`": "`+value+`"}},
			"shell": {"command": "`+assign+` node srv.js"}
		}
	}`)
	kittest.WriteFile(t, filepath.Join(root, ".windsurf", "hooks.json"), `{"hooks": {"pre_run_command": [{"command": "`+assign+` ./audit.sh"}]}}`)
	kittest.WriteFile(t, filepath.Join(root, ".devin", "hooks.json"), `{"hooks": {"pre_mcp_tool_use": [{"command": "`+assign+` ./guard.sh", "powershell": "$env:`+name+`='`+value+`'; ./guard.ps1"}]}}`)
	kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{"mcpServers": {
		"argv": {"command": "node", "args": ["srv.js", "`+assign+`"]},
		"env": {"command": "node", "env": {"`+name+`": "`+value+`"}}
	}}`)
	kittest.WriteFile(t, filepath.Join(root, ".devcontainer", "devcontainer.json"), `{
		"image": "alpine",
		"containerEnv": {"`+name+`": "`+value+`"},
		"remoteEnv": {"`+name+`": "`+value+`"},
		"runArgs": ["-e", "`+assign+`", "--env=`+assign+`", "-e`+assign+`"],
		"postCreateCommand": "`+assign+` make setup",
		"postStartCommand": ["env", "`+assign+`", "./start.sh"]
	}`)
}

func TestCredentialNamedValuesNeverLeak(t *testing.T) {
	t.Parallel()
	for _, name := range credentialNames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := "cv-" + strings.ToLower(strings.ReplaceAll(name, "_", "")) + "-7Qx9"
			root, home := t.TempDir(), t.TempDir()
			plantCredential(t, root, home, name, value)
			list := []adapters.Adapter{
				gemini.New(gemini.Options{HomeDir: home, Getenv: kittest.Env()}),
				windsurf.New(windsurf.Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}),
				devcontainer.New(devcontainer.Options{}),
			}
			got := discoverAll(t, root, list)

			want := map[string]int{
				"gemini:" + string(model.ConfigKindHook):           3,
				"gemini:" + string(model.ConfigKindMCPServer):      3,
				"windsurf:" + string(model.ConfigKindHook):         2,
				"windsurf:" + string(model.ConfigKindMCPServer):    2,
				"devcontainer:" + string(model.ConfigKindEnvSetup): 6,
			}
			count := map[string]int{}
			var findings []model.Finding
			rule := &rules.Rule{ID: "TC-TEST-002", Title: "credential names", Fix: "none", Severity: model.SeverityHigh}
			for harness, items := range got.byAdapter {
				for _, item := range items {
					count[string(harness)+":"+string(item.Kind)]++
					if strings.Contains(string(item.Payload), value) {
						t.Fatalf("%s %s payload contains the value: %s", harness, item.Path, item.Payload)
					}
					var payload map[string]any
					if err := json.Unmarshal(item.Payload, &payload); err != nil {
						t.Fatal(err)
					}
					key, _ := payload["key"].(string)
					if key == "" || strings.Contains(key, value) {
						t.Fatalf("%s %s key = %q", harness, item.Path, key)
					}
					if strings.Contains(rules.ConfigEvidenceKey(item), value) {
						t.Fatalf("%s %s evidence key contains the value", harness, item.Path)
					}
					finding, err := rules.Match{Rule: rule, Item: item}.Finding(model.SeverityHigh, model.DecisionWarn)
					if err != nil {
						t.Fatalf("finding for %s: %v", item.Path, err)
					}
					findings = append(findings, finding)
				}
			}
			for k, n := range want {
				if count[k] != n {
					t.Fatalf("%s items = %d, want %d (all: %v)", k, count[k], n, count)
				}
			}

			var diags []output.Diagnostic
			disabledNote := false
			for _, d := range got.diags {
				if strings.Contains(d.Message, value) {
					t.Fatalf("diagnostic contains the value: %s", d.Message)
				}
				if strings.Contains(d.Message, "is named in hooksConfig.disabled") {
					disabledNote = true
				}
				diags = append(diags, output.Diagnostic{Harness: string(d.Harness), Scope: string(d.Scope), Path: d.Path, Message: d.Message})
			}
			if !disabledNote {
				t.Fatalf("hooksConfig.disabled note missing: %v", got.diags)
			}

			for _, format := range []string{"json", "md", "sarif", "text", "gha"} {
				var buf bytes.Buffer
				handle, err := output.SelectSink(format, "", &buf, output.Options{Redactor: output.DefaultRedactor, RepoRoot: root, ToolVersion: "test"})
				if err != nil {
					t.Fatal(err)
				}
				if err := handle.SetDiagnostics(diags); err != nil {
					t.Fatal(err)
				}
				for _, f := range findings {
					if err := handle.Write(f); err != nil {
						t.Fatal(err)
					}
				}
				if err := handle.Flush(); err != nil {
					t.Fatal(err)
				}
				report := buf.String()
				if !strings.Contains(report, "TC-TEST-002") {
					t.Fatalf("%s report has no findings", format)
				}
				if strings.Contains(report, value) {
					t.Fatalf("%s output contains the %s value", format, name)
				}
			}
		})
	}
}
