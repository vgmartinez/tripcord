package kit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestSafeToolArgv(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      []any
		want    string
		removed bool
	}{
		{"tool flag", []any{"docker", "login", "-p", "s3cr3t", "registry.example"}, `["docker","login","-p","[REDACTED]","registry.example"]`, true},
		{"tool flag only after its subcommand", []any{"docker", "run", "-p", "8080:80"}, `["docker","run","-p","8080:80"]`, false},
		{"generic flag", []any{"npx", "srv", "--token", "abc"}, `["npx","srv","--token","[REDACTED]"]`, true},
		{"url query", []any{"curl", "https://h.example/x?k=abc"}, `["curl","https://h.example/x"]`, true},
		{"non-string element", []any{"node", json.Number("1"), true}, `["node",1,true]`, false},
		{"plain", []any{"npm", "test"}, `["npm","test"]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := source(model.ScopeRepo, "a")
			raw, err := json.Marshal(s.SafeValue("", s.SafeToolArgv(tc.in)))
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != tc.want {
				t.Fatalf("SafeValue(SafeToolArgv) = %s, want %s", raw, tc.want)
			}
			if (len(s.removed) > 0) != tc.removed {
				t.Fatalf("removed = %q, want removed %v", s.removed, tc.removed)
			}
		})
	}
}

func TestSafeToolArgvDiscriminatesToolFlagSecrets(t *testing.T) {
	t.Parallel()
	key := func(secret string) string {
		s := source(model.ScopeRepo, "a")
		s.Add(model.ConfigKindMCPServer, []string{"mcp", "x"}, map[string]any{"command": s.SafeValue("", s.SafeToolArgv([]any{"docker", "login", "-p", secret}))})
		items := s.c.Items()
		if len(items) != 1 {
			t.Fatalf("items = %+v", items)
		}
		if strings.Contains(string(items[0].Payload), secret) {
			t.Fatalf("payload leaks %q: %s", secret, items[0].Payload)
		}
		var payload map[string]any
		if err := json.Unmarshal(items[0].Payload, &payload); err != nil {
			t.Fatal(err)
		}
		return payload["key"].(string)
	}
	one, two, again := key("one"), key("two"), key("one")
	if one == two {
		t.Fatal("argv entries that differ only by a tool-flag secret share a key")
	}
	if one != again {
		t.Fatal("key is not deterministic")
	}
}
