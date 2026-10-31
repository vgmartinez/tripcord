package claude

import (
	"path/filepath"
	"strings"
	"testing"
)

// Env-style credential names (AWS_SECRET_ACCESS_KEY, PRIVATE_KEY,
// DB_PASS) are redacted at the source in .mcp.json env keys and in an
// MCP server's sh -c command.
func TestMCPEnvCredentialNamesAreRedacted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), string(mustJSON(t, map[string]any{
		"mcpServers": map[string]any{"db": map[string]any{
			"command": "sh",
			"args":    []any{"-c", "docker run -e AWS_SECRET_ACCESS_KEY=ARGSAK -e PRIVATE_KEY=ARGPK -e DB_PASS=ARGPASS img"},
			"env":     map[string]any{"AWS_SECRET_ACCESS_KEY": "ENVSAK", "PRIVATE_KEY": "ENVPK", "DB_PASS": "ENVPASS", "LOG_LEVEL": "debug"},
		}},
	})))
	got := discover(t, New(Options{}), root)
	if len(got.Items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	payload := string(got.Items[0].Payload)
	for _, secret := range []string{"ARGSAK", "ARGPK", "ARGPASS", "ENVSAK", "ENVPK", "ENVPASS"} {
		if strings.Contains(payload, secret) {
			t.Errorf("payload leaks %q: %s", secret, payload)
		}
	}
	if !strings.Contains(payload, "debug") {
		t.Errorf("non-secret env value was redacted: %s", payload)
	}
}
