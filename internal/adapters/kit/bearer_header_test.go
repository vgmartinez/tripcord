package kit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestSafeValueRedactsHeaderBearerElement(t *testing.T) {
	t.Parallel()
	for _, args := range [][]any{
		{"mcp-remote", "--header", "Authorization: Bearer", "SEPBEARERTOK"},
		{"mcp-remote", "--header=Authorization: Bearer", "GLUEDBEARERTOK"},
	} {
		s := source(model.ScopeRepo, "a")
		raw, _ := json.Marshal(s.SafeValue("args", args))
		if secret := args[len(args)-1].(string); strings.Contains(string(raw), secret) {
			t.Errorf("SafeValue(%q) = %s leaks the token", args, raw)
		}
		if !strings.Contains(string(raw), "Authorization: Bearer") {
			t.Errorf("SafeValue(%q) = %s dropped the header name", args, raw)
		}
	}
	s := source(model.ScopeRepo, "a")
	raw, _ := json.Marshal(s.SafeValue("args", []any{"--note", "no bearer", "kept"}))
	if !strings.Contains(string(raw), `"kept"`) {
		t.Errorf("an element merely ending in the word bearer redacted the next: %s", raw)
	}
}
