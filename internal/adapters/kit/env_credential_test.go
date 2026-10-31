package kit

import (
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Env-style credential names (AWS_SECRET_ACCESS_KEY, PRIVATE_KEY,
// DB_PASS) are redacted in hook commands and in hook and MCP env maps.
//
// The hook and MCP shapes below are Windsurf's hooks.json and
// mcp_config.json and Gemini CLI's settings.json, driven through
// File.Hook and File.MCPServers, which both adapters call. Those
// adapters are in PR #9; once it lands, add the same cases to their own
// discover tests.
func TestEnvCredentialNamesAreRedactedInHooksAndMCP(t *testing.T) {
	t.Parallel()
	secrets := []string{"AWSSAKVAL", "PKVAL", "DBPASSVAL", "ENVSAKVAL", "ENVPKVAL", "ENVPASSVAL"}
	command := "docker run -e AWS_SECRET_ACCESS_KEY=AWSSAKVAL -e PRIVATE_KEY=PKVAL -e DB_PASS=DBPASSVAL img"
	env := map[string]any{"AWS_SECRET_ACCESS_KEY": "ENVSAKVAL", "PRIVATE_KEY": "ENVPKVAL", "DB_PASS": "ENVPASSVAL"}
	cases := map[string]func(s *Source){
		"windsurf hook": func(s *Source) {
			s.Hook("pre_run_command", "", map[string]any{"command": command, "powershell": command, "env": env}, []string{"command", "powershell"})
		},
		"gemini hook": func(s *Source) {
			s.Hook("BeforeTool", "run_shell_command", map[string]any{"type": "command", "command": command, "env": env}, []string{"command"})
		},
		"windsurf mcp": func(s *Source) {
			s.MCPServers(map[string]any{"db": map[string]any{"command": "sh", "args": []any{"-c", command}, "env": env}}, "mcpServers")
		},
		"gemini mcp": func(s *Source) {
			s.MCPServers(map[string]any{"db": map[string]any{"command": "sh", "args": []any{"-c", command}, "env": env, "trust": true}}, "mcpServers")
		},
	}
	for name, add := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := source(model.ScopeRepo, "a")
			add(s)
			if len(s.c.Items()) != 1 {
				t.Fatalf("%d items", len(s.c.Items()))
			}
			payload := string(s.c.Items()[0].Payload)
			for _, secret := range secrets {
				if strings.Contains(payload, secret) {
					t.Errorf("payload leaks %q: %s", secret, payload)
				}
			}
			if !strings.Contains(addedKey(t, s.c), "sig:") {
				t.Errorf("key has no discriminator for the removed values: %s", addedKey(t, s.c))
			}
		})
	}
}

// gh auth login --with-token is a boolean flag, in a command string or
// in an argv list: the element after it is not marked as a secret.
func TestWithTokenIsNotASecretFlagAtTheSource(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"gh auth login --with-token < token.txt",
		"gh auth login --with-token=true",
		"gh auth login --with-token --hostname ghe.example",
	} {
		if got := source(model.ScopeRepo, "a").Sanitize(in); got.Value != in || len(got.Removed) != 0 {
			t.Errorf("Sanitize(%q) = %q, %q; want unchanged", in, got.Value, got.Removed)
		}
	}
	args := []any{"auth", "login", "--with-token", "ghe.example"}
	s := source(model.ScopeRepo, "a")
	got, ok := s.SafeValue("args", args).([]any)
	if !ok || len(got) != len(args) || got[3] != "ghe.example" {
		t.Errorf("SafeValue(%v) = %v", args, got)
	}
}
