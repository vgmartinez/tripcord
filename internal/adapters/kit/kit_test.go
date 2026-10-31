package kit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func source(scope model.Scope, path string) *Source {
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
	s := source(model.ScopeRepo, "a")
	a := s.Discriminated([]string{"mcp", "x"}, "https://h.example/?k=one")
	b := s.Discriminated([]string{"mcp", "x"}, "https://h.example/?k=two")
	plain := s.Discriminated([]string{"mcp", "x"}, "https://h.example/")
	if EvidenceKey(a) == EvidenceKey(b) || len(plain) != 2 {
		t.Fatalf("a=%v b=%v plain=%v", a, b, plain)
	}
	for _, k := range [][]string{a, b} {
		if strings.Contains(EvidenceKey(k), "one") || strings.Contains(EvidenceKey(k), "two") {
			t.Fatalf("key leaks secret: %v", k)
		}
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
	if !ok || dir.Logical != "~/CODEX_HOME" || len(c.Diagnostics()) != 1 || !c.Diagnostics()[0].Informational {
		t.Fatalf("outside home: %+v %v", dir, c.Diagnostics())
	}
	if _, ok := ResolveUserDir(c, "/home/dev", "CODEX_HOME", "relative", ".codex"); ok {
		t.Fatal("accepted a relative override")
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
