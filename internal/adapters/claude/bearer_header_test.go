package claude

import (
	"path/filepath"
	"strings"
	"testing"
)

// An MCP server's "Bearer" scheme can end an element ("Authorization:
// Bearer" or "--header=Authorization: Bearer") with the token in the next.
func TestMCPArgsHeaderBearerElementIsRedacted(t *testing.T) {
	t.Parallel()
	for name, args := range map[string][]any{
		"separate header flag": {"mcp-remote", "https://h.example/mcp", "--header", "Authorization: Bearer", "SEPBEARERTOK"},
		"glued header flag":    {"mcp-remote", "https://h.example/mcp", "--header=Authorization: Bearer", "GLUEDBEARERTOK"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, ".mcp.json"), string(mustJSON(t, map[string]any{
				"mcpServers": map[string]any{"s": map[string]any{"command": "npx", "args": args}},
			})))
			got := discover(t, New(Options{}), root)
			raw := string(mustJSON(t, got.Items))
			if secret := args[len(args)-1].(string); strings.Contains(raw, secret) {
				t.Fatalf("bearer token leaked: %s", raw)
			}
			if !strings.Contains(raw, "Authorization: Bearer") {
				t.Fatalf("header name dropped: %s", raw)
			}
		})
	}
}
