package claude

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules"
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
	return discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
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

// TestS1DiscriminatorIgnoresHeaderSecretShape is blocker 1 from the
// researcher's review: hook() redacts hook["headers"] twice (once in the
// generic sortedKeys loop via safePayloadValue, once more explicitly a
// few lines later) and redactValues itself can add a further removal
// when output.DefaultRedactor's secretPatterns also recognize the
// value's shape (ghp_, sk-, xoxb, AKIA, a JWT, ...). Under the old
// removal-log-based StructuralDiscriminator that gave a provider-shaped
// X-Api-Key header one more "headers[n]" entry than a generic one of the
// same length, so rotating to a different-shaped token changed the s1
// fingerprint and the discriminator leaked which provider's token shape
// was present. The new discriminator scans only the final sanitized
// payload for [REDACTED] markers, so it must stay identical across every
// shape: internal/adapters/conformance.TestS1DiscriminatorShapeIndependent
// is the cross-adapter version of this same guarantee.
func TestS1DiscriminatorIgnoresHeaderSecretShape(t *testing.T) {
	t.Parallel()
	discriminatorFor := func(secret string) string {
		hook := `{"matcher":"Bash","hooks":[{"type":"http","url":"https://audit.example.test/hook","headers":{"X-Api-Key":"` + secret + `"}}]}`
		root := t.TempDir()
		writeFile(t, filepath.Join(root, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[`+hook+`]}}`)
		got := discover(t, New(Options{}), root)
		parts := keyParts(t, got, model.ConfigKindHook)
		return parts[len(parts)-1]
	}
	shapes := []string{
		"zsG01q-opaque-token-value-0123456789",
		"ghp_" + strings.Repeat("a1B2c3", 7),
		"github_pat_" + strings.Repeat("a1B2c3", 4),
		"glpat-" + strings.Repeat("a1B2c3", 4),
		"sk-" + strings.Repeat("a1B2c3", 4),
		"sk_live_" + strings.Repeat("a1B2c3", 4),
		"xoxb-" + strings.Repeat("a1B2c3", 2),
		"npm_" + strings.Repeat("a1B2c3", 4),
		"hf_" + strings.Repeat("a1B2c3", 4),
		"ya29." + strings.Repeat("a1B2c3", 4),
		"AIza" + strings.Repeat("a1B2c3d4e", 3) + "aaaaaaaa",
		"AKIA" + "ABCD1234EFGH5678",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}
	want := discriminatorFor(shapes[0])
	if m := s1Pattern.FindStringSubmatch(want); m == nil {
		t.Fatalf("discriminator %q is not s1", want)
	}
	for _, shape := range shapes[1:] {
		if got := discriminatorFor(shape); got != want {
			t.Fatalf("discriminator %q for %q, want %q (same as the first shape)", got, shape, want)
		}
	}
}

var s1Pattern = regexp.MustCompile(`^sig:s1:`)

// hookItem returns the sole ConfigKindHook item in got.
func hookItem(t *testing.T, got discovery) model.ConfigItem {
	t.Helper()
	var found *model.ConfigItem
	for _, item := range got.Items {
		if item.Kind != model.ConfigKindHook {
			continue
		}
		if found != nil {
			t.Fatalf("more than one hook item")
		}
		item := item
		found = &item
	}
	if found == nil {
		t.Fatalf("no hook item")
	}
	return *found
}

// TestFingerprintModeIgnoresMarkerTextInCommand is the researcher
// review's bug 1: model.FingerprintMode must look only at the LAST
// element of the evidence key, anchored, never scan the whole key text
// as a substring. A hook whose command is itself literal text shaped
// like a discriminator (nothing was actually redacted here) must not be
// mislabeled: hookAction puts the sanitized command directly into an
// earlier key part (see kit.Source.Hook), so a command that happens to
// read "echo sig:s1:x[0]" would, under the old Contains-based check,
// make a mode-independent finding (Q2) falsely render fingerprintMode
// "s1" and break its byte-identical output.
func TestFingerprintModeIgnoresMarkerTextInCommand(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".claude", "settings.json"),
		`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo sig:s1:x[0]"}]}]}}`)
	got := discover(t, New(Options{}), root)
	item := hookItem(t, got)
	key := rules.ConfigEvidenceKey(item)
	if !strings.Contains(key, "sig:s1:x[0]") {
		t.Fatalf("test setup: key %q does not contain the marker text", key)
	}
	evidence := []model.Evidence{{Config: &model.ConfigRef{ID: "x", Key: key}}}
	if mode := model.FingerprintMode(evidence); mode != "" {
		t.Fatalf("FingerprintMode(%q) = %q, want \"\" (nothing was redacted)", key, mode)
	}
}

// TestFingerprintModeIgnoresMarkerTextElsewhereInKey is the same bug's
// other direction: an entry that IS genuinely discriminated in s1 must
// keep reporting s1 even when its command text happens to contain the
// literal "sig:k1:" marker, since only the key's last element decides
// the mode, never a substring match anywhere in it.
func TestFingerprintModeIgnoresMarkerTextElsewhereInKey(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".claude", "settings.json"),
		`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo sig:k1:deadbeef --token zsM01q"}]}]}}`)
	got := discover(t, New(Options{}), root)
	item := hookItem(t, got)
	key := rules.ConfigEvidenceKey(item)
	if !strings.Contains(key, "sig:k1:deadbeef") {
		t.Fatalf("test setup: key %q does not contain the marker text", key)
	}
	evidence := []model.Evidence{{Config: &model.ConfigRef{ID: "x", Key: key}}}
	if mode := model.FingerprintMode(evidence); mode != "s1" {
		t.Fatalf("FingerprintMode(%q) = %q, want \"s1\"", key, mode)
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
		return strings.Join(keyParts(t, discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root), model.ConfigKindMCPServer), "\x00")
	}
	if mcpKey(`{"API_TOKEN":"one"}`) == mcpKey(`{"API_TOKEN":"two"}`) {
		t.Error("MCP servers differing only in a redacted env value share a key")
	}
}
