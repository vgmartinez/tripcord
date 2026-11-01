package conformance

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// mcpArgvSecrets are placed beside a docker or podman env flag. Before
// redactionToolArgs used the sanitized payload as its input, the tool
// replacement copied raw args back over these SafeValue redactions.
var mcpArgvSecrets = []string{
	"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"SLACKLEAK", "APIKEYLEAK", "DBPASSWORDLEAK", "PASSLEAK", "URLPASSLEAK",
	"HEADERLEAK", "PRIVATELEAK", "APIKEYTAIL", "PODMANLEAK", "LOGINLEAK", "BEARERLEAK",
}

func mcpRedactionServers() map[string]any {
	return map[string]any{
		"github": map[string]any{
			"command": "docker",
			"args":    []any{"run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN=" + mcpArgvSecrets[0], "-eSLACK_BOT_TOKEN=" + mcpArgvSecrets[1], "ghcr.io/github/github-mcp-server"},
		},
		"assignments": map[string]any{
			"command": "docker",
			"args":    []any{"run", "--env=API_KEY=" + mcpArgvSecrets[2], "-e", "DB_PASSWORD=" + mcpArgvSecrets[3], "img"},
		},
		"pass-url": map[string]any{
			"command": "docker",
			"args":    []any{"run", "-ePASS=" + mcpArgvSecrets[4], "img", "postgres://admin:" + mcpArgvSecrets[5] + "@db/x"},
		},
		"headers": map[string]any{
			"command": "docker",
			"args":    []any{"run", "--header", "Authorization: Bearer " + mcpArgvSecrets[6], "-ePRIVATE_KEY=" + mcpArgvSecrets[7], "img", "--api-key", mcpArgvSecrets[8]},
		},
		"podman": map[string]any{
			"command": "podman",
			"args":    []any{"run", "--env=DB_PASS=" + mcpArgvSecrets[9], "img", "xoxb-12345678901234567890"},
		},
		"login": map[string]any{
			"command": "docker",
			"args":    []any{"login", "-p", mcpArgvSecrets[10], "--", "x", "Bearer", mcpArgvSecrets[11]},
		},
	}
}

func jsonMCPConfig(t *testing.T, key string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{key: mcpRedactionServers()})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func codexMCPConfig(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, name := range kit.SortedKeys(mcpRedactionServers()) {
		server := mcpRedactionServers()[name].(map[string]any)
		args, err := json.Marshal(server["args"])
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("[mcp_servers.")
		b.WriteString(name)
		b.WriteString("]\ncommand = ")
		command, _ := json.Marshal(server["command"])
		b.Write(command)
		b.WriteString("\nargs = ")
		b.Write(args)
		b.WriteString("\n")
	}
	return b.String()
}

func openCodeMCPConfig(t *testing.T) string {
	t.Helper()
	servers := map[string]any{}
	for _, name := range kit.SortedKeys(mcpRedactionServers()) {
		server := mcpRedactionServers()[name].(map[string]any)
		command := []any{server["command"]}
		command = append(command, server["args"].([]any)...)
		servers[name] = map[string]any{"type": "local", "command": command}
	}
	raw, err := json.Marshal(map[string]any{"mcp": servers})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestMCPArgvRedactionNeverRestoresOtherSecrets exercises every MCP
// adapter. Each server has a container env flag that activates the
// shared tool redactor alongside independent SafeValue redactions, so
// copying raw args over that output would leak one or more values.
func TestMCPArgvRedactionNeverRestoresOtherSecrets(t *testing.T) {
	t.Parallel()
	root, home := t.TempDir(), t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".mcp.json"), jsonMCPConfig(t, "mcpServers"))
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), codexMCPConfig(t))
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "mcp.json"), jsonMCPConfig(t, "mcpServers"))
	kittest.WriteFile(t, filepath.Join(root, ".vscode", "mcp.json"), jsonMCPConfig(t, "servers"))
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), jsonMCPConfig(t, "mcpServers"))
	kittest.WriteFile(t, filepath.Join(root, "opencode.json"), openCodeMCPConfig(t))
	kittest.WriteFile(t, filepath.Join(home, ".copilot", "mcp-config.json"), jsonMCPConfig(t, "mcpServers"))
	kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), jsonMCPConfig(t, "mcpServers"))

	got := discoverAll(t, root, allAdapters(home, true))
	want := map[model.Harness]bool{
		model.HarnessClaude:   true,
		model.HarnessCodex:    true,
		model.HarnessCursor:   true,
		model.HarnessCopilot:  true,
		model.HarnessGemini:   true,
		model.HarnessOpenCode: true,
		model.HarnessWindsurf: true,
		model.SurfaceGeneric:  true,
	}
	for harness := range want {
		var mcpItems []model.ConfigItem
		for _, item := range got.byAdapter[harness] {
			if item.Kind == model.ConfigKindMCPServer {
				mcpItems = append(mcpItems, item)
			}
		}
		if len(mcpItems) != len(mcpRedactionServers()) {
			t.Fatalf("%s MCP items = %d, want %d", harness, len(mcpItems), len(mcpRedactionServers()))
		}
		for _, item := range mcpItems {
			for _, secret := range mcpArgvSecrets {
				if strings.Contains(string(item.Payload), secret) {
					t.Fatalf("%s payload leaks %q: %s", harness, secret, item.Payload)
				}
				if evidence := rules.ConfigEvidenceKey(item); strings.Contains(evidence, secret) {
					t.Fatalf("%s evidence key leaks %q: %s", harness, secret, evidence)
				}
			}
		}
	}
}
