package claude

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// A credential shape output.DefaultRedactor recognizes (a ghp_ token) is
// redacted at the source in .mcp.json args and env and in apiKeyHelper,
// not only by the output sink, and still discriminates the key.
func TestSourceAppliesDefaultRedactorShapes(t *testing.T) {
	t.Parallel()
	const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), string(mustJSON(t, map[string]any{
		"mcpServers": map[string]any{"gh": map[string]any{
			"command": "github-mcp",
			"args":    []any{"serve", "--gh", token},
			"env":     map[string]any{"GH": token},
		}},
	})))
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(mustJSON(t, map[string]any{
		"apiKeyHelper": "echo " + token,
	})))
	got := discover(t, New(Options{}), root)
	if len(got.Items) != 2 {
		t.Fatalf("items = %+v", got.Items)
	}
	for _, item := range got.Items {
		if strings.Contains(string(item.Payload), token) {
			t.Fatalf("%s leaks the token: %s", item.Kind, item.Payload)
		}
		parts := strings.Join(keyParts(t, discovery{Items: []model.ConfigItem{item}}, item.Kind), " ")
		if strings.Count(parts, "sig:") != 2 {
			t.Fatalf("%s key %q has no discriminator", item.Kind, parts)
		}
	}
}
