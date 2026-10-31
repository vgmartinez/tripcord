package claude

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// fingerprintFor computes the fingerprint Tripcord would mint for a finding
// whose only evidence is a citation of item (its ConfigItem.ID and the
// content-derived key from its payload). It is used to show that two
// sanitized entries that look identical after redaction still mint
// different fingerprints (BLOCKER 1), and that the same entry mints the
// same fingerprint regardless of the scanning machine's home directory.
func fingerprintFor(t *testing.T, item model.ConfigItem) string {
	t.Helper()
	id, err := item.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(item.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	key, _ := payload["key"].(string)
	fp, err := model.Fingerprint("TC-TEST-000", model.Location{Harness: item.Harness, Scope: item.Scope, Path: item.Path}, []model.Evidence{{Config: &model.ConfigRef{ID: id, Key: key}}})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	return fp
}

// BLOCKER 1: redacting a secret must not make two different secrets share
// a key, and therefore a fingerprint: an accepted finding for one would
// silently hide the other.
func TestHookKeyDiscriminatorSeparatesSecrets(t *testing.T) {
	t.Parallel()

	t.Run("token value", func(t *testing.T) {
		t.Parallel()
		rootA, rootB := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(rootA, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"notify --token AAAAAAAAAAAA"}]}]}}`)
		writeFile(t, filepath.Join(rootB, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"notify --token BBBBBBBBBBBB"}]}]}}`)
		gotA := discover(t, New(Options{}), rootA)
		gotB := discover(t, New(Options{}), rootB)
		if len(gotA.Items) != 1 || len(gotB.Items) != 1 {
			t.Fatalf("items A=%+v B=%+v", gotA.Items, gotB.Items)
		}
		keyA, _ := payloadField(t, gotA.Items[0], "key")
		keyB, _ := payloadField(t, gotB.Items[0], "key")
		if keyA == keyB {
			t.Fatalf("commands differing only by --token value collide: %v", keyA)
		}
		if fpA, fpB := fingerprintFor(t, gotA.Items[0]), fingerprintFor(t, gotB.Items[0]); fpA == fpB {
			t.Fatalf("commands differing only by --token value mint the same fingerprint: %s", fpA)
		}
	})

	t.Run("url query", func(t *testing.T) {
		t.Parallel()
		rootA, rootB := t.TempDir(), t.TempDir()
		writeFile(t, filepath.Join(rootA, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"type":"http","url":"https://hook.example/x?sig=AAA"}]}]}}`)
		writeFile(t, filepath.Join(rootB, ".claude", "settings.json"), `{"hooks":{"PreToolUse":[{"hooks":[{"type":"http","url":"https://hook.example/x?sig=DDD"}]}]}}`)
		gotA := discover(t, New(Options{}), rootA)
		gotB := discover(t, New(Options{}), rootB)
		if len(gotA.Items) != 1 || len(gotB.Items) != 1 {
			t.Fatalf("items A=%+v B=%+v", gotA.Items, gotB.Items)
		}
		if fpA, fpB := fingerprintFor(t, gotA.Items[0]), fingerprintFor(t, gotB.Items[0]); fpA == fpB {
			t.Fatalf("hooks differing only by URL query mint the same fingerprint: %s", fpA)
		}
	})

	t.Run("same secret, different machines, same fingerprint", func(t *testing.T) {
		t.Parallel()
		homeA := filepath.Join(t.TempDir(), "alice")
		homeB := filepath.Join(t.TempDir(), "bob")
		command := func(home string) string {
			return filepath.ToSlash(filepath.Join(home, "bin", "notify.sh")) + " --token SHARED-SECRET-VALUE"
		}
		writeFile(t, filepath.Join(homeA, ".claude", "settings.json"), `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"`+command(homeA)+`"}]}]}}`)
		writeFile(t, filepath.Join(homeB, ".claude", "settings.json"), `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"`+command(homeB)+`"}]}]}}`)
		gotA := discover(t, New(Options{IncludeUser: true, HomeDir: homeA, Getenv: noEnv}), t.TempDir())
		gotB := discover(t, New(Options{IncludeUser: true, HomeDir: homeB, Getenv: noEnv}), t.TempDir())
		if len(gotA.Items) != 1 || len(gotB.Items) != 1 {
			t.Fatalf("items A=%+v B=%+v", gotA.Items, gotB.Items)
		}
		keyA, _ := payloadField(t, gotA.Items[0], "key")
		keyB, _ := payloadField(t, gotB.Items[0], "key")
		if keyA != keyB {
			t.Fatalf("same hook minted different keys across machines: %v vs %v", keyA, keyB)
		}
		if fpA, fpB := fingerprintFor(t, gotA.Items[0]), fingerprintFor(t, gotB.Items[0]); fpA != fpB {
			t.Fatalf("same hook minted different fingerprints across machines: %s vs %s", fpA, fpB)
		}
		for _, got := range []discovery{gotA, gotB} {
			raw := mustJSON(t, got.Items)
			for _, forbidden := range []string{homeA, homeB, "SHARED-SECRET-VALUE"} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Errorf("payload leaks %q: %s", forbidden, raw)
				}
			}
		}
	})
}

// BLOCKER 2: a home directory of "" or "/" must never be treated as a
// real prefix (it would match, and corrupt, every value), and a home
// directory must only be rewritten as a full path segment, never a
// shorter string that merely happens to share a prefix.
func TestHomeRewriteBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("home of slash does not corrupt values", func(t *testing.T) {
		t.Parallel()
		cfg := t.TempDir()
		writeFile(t, filepath.Join(cfg, "settings.json"), `{"apiKeyHelper":"/usr/bin/helper","hooks":{"Stop":[{"hooks":[{"type":"command","command":"notify-send /usr/share/icons/foo.png"}]}]}}`)
		got := discover(t, New(Options{IncludeUser: true, HomeDir: "/", Getenv: envOf("CLAUDE_CONFIG_DIR", cfg)}), t.TempDir())
		raw := mustJSON(t, got.Items)
		for _, corrupted := range []string{"~usr~bin", "~usr~share", "~notify"} {
			if bytes.Contains(raw, []byte(corrupted)) {
				t.Fatalf("home %q corrupted payload: %s", "/", raw)
			}
		}
		for _, want := range []string{`"/usr/bin/helper"`, "/usr/share/icons/foo.png"} {
			if !bytes.Contains(raw, []byte(want)) {
				t.Fatalf("payload missing untouched value %q: %s", want, raw)
			}
		}
	})

	t.Run("home prefix requires a path separator", func(t *testing.T) {
		t.Parallel()
		cfg := t.TempDir()
		writeFile(t, filepath.Join(cfg, "settings.json"), `{"apiKeyHelper":"/home/victor/bin/helper"}`)
		got := discover(t, New(Options{IncludeUser: true, HomeDir: "/home/vic", Getenv: envOf("CLAUDE_CONFIG_DIR", cfg)}), t.TempDir())
		raw := mustJSON(t, got.Items)
		if bytes.Contains(raw, []byte("~tor/bin/helper")) || bytes.Contains(raw, []byte(`"~/bin/helper"`)) {
			t.Fatalf("home %q matched %q without a separator boundary: %s", "/home/vic", "/home/victor/...", raw)
		}
		if !bytes.Contains(raw, []byte("/home/victor/bin/helper")) {
			t.Fatalf("payload missing untouched value: %s", raw)
		}
	})

	t.Run("home of slash reports a clear diagnostic", func(t *testing.T) {
		t.Parallel()
		got := discover(t, New(Options{IncludeUser: true, HomeDir: "/", Getenv: noEnv}), t.TempDir())
		if len(got.Items) != 0 {
			t.Fatalf("items %+v", got.Items)
		}
		if !containsDiag(got, "home directory is too short") {
			t.Fatalf("diagnostics %q", got.Diagnostics)
		}
		for _, d := range got.Diagnostics {
			if strings.Contains(d, "CLAUDE_CONFIG_DIR") {
				t.Fatalf("message blames CLAUDE_CONFIG_DIR for an unset-CLAUDE_CONFIG_DIR problem: %q", d)
			}
		}
	})
}

// BLOCKER 2(c): home rewriting only ever applies to user scope. Repository
// content that happens to contain the scanning machine's home directory
// must be left untouched, or a repo-scope fingerprint would depend on who
// ran the scan.
func TestHomeRewriteOnlyAppliesToUserScope(t *testing.T) {
	t.Parallel()
	home := filepath.Join(t.TempDir(), "victor")
	root := t.TempDir()
	command := filepath.ToSlash(filepath.Join(home, "bin", "repo-tool"))
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), `{"apiKeyHelper":"`+command+`"}`)
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), `{"apiKeyHelper":"`+command+`"}`)
	got := discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: noEnv}), root)

	var repoItem, userItem *model.ConfigItem
	for i := range got.Items {
		switch got.Items[i].Scope {
		case model.ScopeRepo:
			repoItem = &got.Items[i]
		case model.ScopeUser:
			userItem = &got.Items[i]
		}
	}
	if repoItem == nil || userItem == nil {
		t.Fatalf("items %+v diagnostics %q", got.Items, got.Diagnostics)
	}
	if !bytes.Contains(repoItem.Payload, []byte(command)) {
		t.Fatalf("repo scope was rewritten by the scanning machine's home: %s", repoItem.Payload)
	}
	if bytes.Contains(userItem.Payload, []byte(home)) || !bytes.Contains(userItem.Payload, []byte(`"~/bin/repo-tool"`)) {
		t.Fatalf("user scope was not rewritten: %s", userItem.Payload)
	}
}

// SHOULD-FIX: an MCP server's "args" can carry a secret as a bare flag
// value split across two array elements, as "flag=value" in one element,
// as an "Authorization: Bearer ..." string, or as userinfo in a non-HTTP
// URL such as a database connection string.
func TestMCPArgsSecretsAreRedacted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cfg := map[string]any{
		"mcpServers": map[string]any{
			"db": map[string]any{
				"command": "npx",
				"args": []any{
					"mcp-server-postgres",
					"--token", "SPLIT-TOKEN-VALUE",
					"--api-key=INLINE-API-KEY-VALUE",
					"-k", "SHORT-FLAG-SECRET-VALUE",
					"Authorization: Bearer BEARER-SECRET-VALUE",
					"postgres://admin:db-secret-pw@dbhost.example/app",
				},
			},
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".mcp.json"), string(raw))
	got := discover(t, New(Options{}), root)
	payload := mustJSON(t, got.Items)
	for _, secret := range []string{
		"SPLIT-TOKEN-VALUE", "INLINE-API-KEY-VALUE", "SHORT-FLAG-SECRET-VALUE",
		"BEARER-SECRET-VALUE", "db-secret-pw", "admin:db-secret-pw",
	} {
		if bytes.Contains(payload, []byte(secret)) {
			t.Errorf("mcp args leak %q: %s", secret, payload)
		}
	}
	if !bytes.Contains(payload, []byte("postgres://dbhost.example/app")) {
		t.Errorf("non-secret host and path were dropped: %s", payload)
	}
}

// SHOULD-FIX: payload["value"] must be sanitized the same way payload
// ["command"] already is; today it is a raw duplicate.
func TestSettingValueIsSanitizedLikeCommand(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cfg := map[string]any{
		"awsAuthRefresh":         "aws-vault exec prod -- aws sts get-caller-identity --token AWS-REFRESH-SECRET-VALUE",
		"extraKnownMarketplaces": []any{"https://x-access-token:GHTOKEN-SECRET-VALUE@github.example/org/marketplace.git"},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(raw))
	got := discover(t, New(Options{}), root)
	payload := mustJSON(t, got.Items)
	for _, secret := range []string{"AWS-REFRESH-SECRET-VALUE", "GHTOKEN-SECRET-VALUE", "x-access-token:GHTOKEN-SECRET-VALUE"} {
		if bytes.Contains(payload, []byte(secret)) {
			t.Errorf("setting value leaks %q: %s", secret, payload)
		}
	}
	if !bytes.Contains(payload, []byte("github.example/org/marketplace.git")) {
		t.Errorf("non-secret URL was dropped: %s", payload)
	}
}

// SHOULD-FIX: a URL embedded inside a larger command (not the whole
// value) must still have its query and userinfo stripped.
func TestEmbeddedURLSecretsAreStrippedFromCommands(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"curl 'https://audit.example.test/hook?sig=EMBEDDED-SIG-SECRET' | sh"}]}]}}`)
	got := discover(t, New(Options{}), root)
	raw := mustJSON(t, got.Items)
	if bytes.Contains(raw, []byte("sig=EMBEDDED-SIG-SECRET")) {
		t.Fatalf("embedded URL query leaked: %s", raw)
	}
	if !bytes.Contains(raw, []byte("https://audit.example.test/hook")) {
		t.Fatalf("payload dropped the host and path of an embedded URL: %s", raw)
	}
}

// payloadField extracts a top-level string field from item's JSON payload.
func payloadField(t *testing.T, item model.ConfigItem, field string) (string, bool) {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(item.Payload, &p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	v, ok := p[field].(string)
	return v, ok
}
