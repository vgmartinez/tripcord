package claude

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// keyParts returns the decoded evidence key of the only item of kind in
// got.
func keyParts(t *testing.T, got discovery, kind model.ConfigKind) []string {
	t.Helper()
	var parts []string
	for _, item := range got.Items {
		if item.Kind != kind {
			continue
		}
		if parts != nil {
			t.Fatalf("more than one %s item", kind)
		}
		var payload map[string]any
		if err := json.Unmarshal(item.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		key, _ := payload["key"].(string)
		if err := json.Unmarshal([]byte(key), &parts); err != nil {
			t.Fatalf("key %q: %v", key, err)
		}
	}
	if parts == nil {
		t.Fatalf("no %s item", kind)
	}
	return parts
}

func discoverSettings(t *testing.T, settings string) discovery {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), settings)
	return discover(t, New(Options{}), root)
}

// The payload digest must be computed over the sanitized entry, never
// over a value this adapter keeps raw (fingerprint.md: credential values
// are never inputs). Two apiKeyHelper commands that differ only in a
// token output.DefaultRedactor recognizes therefore share the digest
// part, and only the discriminator over the removed token tells them
// apart.
func TestPayloadDigestIgnoresRawSecrets(t *testing.T) {
	t.Parallel()
	tokenA := "ghp_" + strings.Repeat("a", 36)
	tokenB := "ghp_" + strings.Repeat("b", 36)
	a := keyParts(t, discoverSettings(t, `{"apiKeyHelper":"echo `+tokenA+`"}`), model.ConfigKindEnvSetup)
	b := keyParts(t, discoverSettings(t, `{"apiKeyHelper":"echo `+tokenB+`"}`), model.ConfigKindEnvSetup)
	if len(a) != 4 || len(b) != 4 {
		t.Fatalf("want setting, name, digest, discriminator: %v / %v", a, b)
	}
	if a[2] != b[2] {
		t.Errorf("digest depends on the raw token: %s vs %s", a[2], b[2])
	}
	if a[3] == b[3] {
		t.Errorf("discriminator does not separate the tokens: %v", a)
	}
	for _, part := range append(a, b...) {
		if strings.Contains(part, "ghp_") {
			t.Errorf("key leaks the token: %v", part)
		}
	}
}

// Two hooks that differ only in a redacted header value, or a redacted
// field other than the action, must not share a key.
func TestHookKeysDiscriminateRedactedFields(t *testing.T) {
	t.Parallel()
	hookKey := func(hook string) string {
		got := discoverSettings(t, `{"hooks":{"Stop":[{"hooks":[`+hook+`]}]}}`)
		return strings.Join(keyParts(t, got, model.ConfigKindHook), "\x00")
	}
	pairs := [][2]string{
		{
			`{"type":"http","url":"https://h.example/","headers":{"Authorization":"Bearer one"}}`,
			`{"type":"http","url":"https://h.example/","headers":{"Authorization":"Bearer two"}}`,
		},
		{
			`{"type":"command","command":"./stop.sh","statusMessage":"--token one"}`,
			`{"type":"command","command":"./stop.sh","statusMessage":"--token two"}`,
		},
	}
	for _, p := range pairs {
		if hookKey(p[0]) == hookKey(p[1]) {
			t.Errorf("hooks share a key:\n%s\n%s", p[0], p[1])
		}
	}
}

func TestMCPKeysDiscriminateRedactedEnv(t *testing.T) {
	t.Parallel()
	mcpKey := func(env string) string {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"x":{"command":"x","env":`+env+`}}}`)
		return strings.Join(keyParts(t, discover(t, New(Options{}), root), model.ConfigKindMCPServer), "\x00")
	}
	if mcpKey(`{"API_TOKEN":"one"}`) == mcpKey(`{"API_TOKEN":"two"}`) {
		t.Error("MCP servers differing only in a redacted env value share a key")
	}
}
