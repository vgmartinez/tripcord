package gemini

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

const fixtureManagedDir = "/etc/gemini-cli"

// fixtureSecrets are the values planted in testdata that no item may
// carry.
var fixtureSecrets = []string{"gm-key-111", "gm-tok-222", "gm-q-333", "gm-bearer-444", "gm-q-555", "gm-q-666", "gm-home-777", "gm-q-888"}

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	for _, version := range kittest.Versions(t) {
		t.Run(version, func(t *testing.T) {
			t.Parallel()
			root := kittest.CopyTree(t, kittest.Tree(version, "repo"))
			home := kittest.CopyTree(t, kittest.Tree(version, "home"))
			managed := kittest.CopyTree(t, kittest.Tree(version, "managed"))
			a := New(Options{IncludeUser: true, IncludeManaged: true, HomeDir: home, ManagedDir: managed, Getenv: kittest.Env()})
			got := kittest.Discover(t, a, root)
			kittest.AssertGolden(t, filepath.Join(version, "discover.golden"), kittest.GoldenJSON(t, got, map[string]string{filepath.ToSlash(managed): fixtureManagedDir}))
			raw := string(kittest.GoldenJSON(t, got, nil))
			for _, leak := range append([]string{home}, fixtureSecrets...) {
				if strings.Contains(raw, leak) {
					t.Fatalf("discovery leaks %q", leak)
				}
			}
			for _, item := range got.Items {
				if strings.EqualFold(filepath.Base(item.Path), "AGENTS.md") {
					t.Fatalf("gemini reported %s, which the generic adapter owns", item.Path)
				}
			}
		})
	}
}

func TestHooksShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		hooks     string
		hookItems int
		opaque    int
		setting   int
		diag      string
	}{
		{"documented", `{"BeforeTool":[{"matcher":"x","hooks":[{"type":"command","command":"a"},{"type":"command","command":"b"}]}]}`, 2, 0, 0, ""},
		{"flat handler", `{"BeforeTool":[{"type":"command","command":"a"}]}`, 1, 1, 0, "hooks.BeforeTool has an unrecognized shape"},
		{"handler not object", `{"BeforeTool":[{"hooks":["a"]}]}`, 1, 1, 0, "unrecognized shape"},
		{"entry not object", `{"BeforeTool":["a"]}`, 1, 1, 0, "unrecognized shape"},
		{"matcher not string", `{"BeforeTool":[{"matcher":1,"hooks":[{"type":"command","command":"a"}]}]}`, 1, 1, 0, "unrecognized shape"},
		{"hooks not object", `["a"]`, 1, 1, 0, "hooks has an unrecognized shape"},
		{"inline flag", `{"enabled":true,"BeforeTool":[{"hooks":[{"type":"command","command":"a"}]}]}`, 1, 0, 1, ""},
		{"unknown type", `{"BeforeTool":[{"hooks":[{"type":"http","url":"https://h.example/"}]}]}`, 1, 0, 0, `handler type "http" is not documented`},
		{"no type", `{"BeforeTool":[{"hooks":[{"command":"a"}]}]}`, 1, 0, 0, "handler has no type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), `{"hooks":`+tc.hooks+`}`)
			got := kittest.Discover(t, New(Options{}), root)
			hooks := got.Find(".gemini/settings.json", model.ConfigKindHook)
			opaque := 0
			for _, item := range hooks {
				if kittest.Payload(t, item)["opaque"] == true {
					opaque++
				}
			}
			settings := got.Find(".gemini/settings.json", model.ConfigKindPermissions)
			if len(hooks) != tc.hookItems || opaque != tc.opaque || len(settings) != tc.setting {
				t.Fatalf("hooks = %d (opaque %d), settings = %d; want %d (%d), %d: %+v", len(hooks), opaque, len(settings), tc.hookItems, tc.opaque, tc.setting, got.Items)
			}
			if tc.diag == "" {
				if len(got.Diagnostics) != 0 {
					t.Fatalf("diagnostics = %v", got.Diagnostics)
				}
				return
			}
			if !got.HasDiag(tc.diag) {
				t.Fatalf("diagnostics = %v, want %q", got.Diagnostics, tc.diag)
			}
			if tc.name == "unknown type" && !kittest.Blocking(t, New(Options{}), root, tc.diag) {
				t.Fatal("a handler type other than command was not blocking")
			}
		})
	}
}

func TestHooksConfigDisabledStillReportsHooks(t *testing.T) {
	t.Parallel()
	const secret = "gm-disabled-token-should-not-appear"
	cases := []struct {
		name   string
		body   string
		hooks  int
		note   string
		absent []string
		secret string
	}{
		{
			name:  "name",
			body:  `{"hooksConfig":{"disabled":["h1"]},"hooks":{"BeforeTool":[{"matcher":"x","hooks":[{"type":"command","name":"h1","command":"./lint.sh"}]}]}}`,
			hooks: 1,
			note:  "hook h1 is named in hooksConfig.disabled",
			absent: []string{
				"BeforeTool is named",
				"hook ./lint.sh is named",
			},
		},
		{
			name:  "command when the handler has no name",
			body:  `{"hooksConfig":{"disabled":["./lint.sh"]},"hooks":{"BeforeTool":[{"matcher":"x","hooks":[{"type":"command","command":"./lint.sh"}]}]}}`,
			hooks: 1,
			note:  "hook ./lint.sh is named in hooksConfig.disabled",
			absent: []string{
				"BeforeTool is named",
			},
		},
		{
			name:  "command does not match when the handler has a name",
			body:  `{"hooksConfig":{"disabled":["./lint.sh"]},"hooks":{"BeforeTool":[{"matcher":"x","hooks":[{"type":"command","name":"h1","command":"./lint.sh"}]}]}}`,
			hooks: 1,
			absent: []string{
				"hooksConfig.disabled",
				"BeforeTool is named",
			},
		},
		{
			name:  "event name does not match",
			body:  `{"hooksConfig":{"disabled":["BeforeTool"]},"hooks":{"BeforeTool":[{"matcher":"x","hooks":[{"type":"command","name":"h1","command":"./lint.sh"}]}]}}`,
			hooks: 1,
			absent: []string{
				"hooksConfig.disabled",
				"hook h1 is named",
				"hook ./lint.sh is named",
			},
		},
		{
			name:   "secret command is redacted in the note",
			body:   `{"hooksConfig":{"disabled":["./lint.sh --token ` + secret + `"]},"hooks":{"BeforeTool":[{"hooks":[{"type":"command","command":"./lint.sh --token ` + secret + `"}]}]}}`,
			hooks:  1,
			note:   "hook ./lint.sh --token [REDACTED] is named in hooksConfig.disabled",
			secret: secret,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), tc.body)
			got := kittest.Discover(t, New(Options{}), root)
			if len(got.Find(".gemini/settings.json", model.ConfigKindHook)) != tc.hooks {
				t.Fatalf("hooks = %+v", got.Items)
			}
			if tc.note != "" && !got.HasDiag(tc.note) {
				t.Fatalf("diagnostics = %v", got.Diagnostics)
			}
			for _, absent := range tc.absent {
				if got.HasDiag(absent) {
					t.Fatalf("diagnostic %q was present: %v", absent, got.Diagnostics)
				}
			}
			if tc.note != "" && kittest.Blocking(t, New(Options{}), root, "hooksConfig.disabled") {
				t.Fatal("a disabled hook was blocking")
			}
			if tc.secret == "" {
				return
			}
			for _, diag := range got.Diagnostics {
				if strings.Contains(diag, tc.secret) {
					t.Fatalf("diagnostic contains the secret: %s", diag)
				}
			}
			for _, item := range got.Items {
				if strings.Contains(string(item.Payload), tc.secret) {
					t.Fatalf("item contains the secret: %s", item.Payload)
				}
			}
		})
	}

	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), `{"hooksConfig":{"enabled":false},"hooks":{"BeforeTool":[{"hooks":[{"type":"command","command":"a"}]}]}}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".gemini/settings.json", model.ConfigKindHook)) != 1 || !got.HasDiag("hooksConfig.enabled is false") {
		t.Fatalf("got %+v", got)
	}
}

func TestTrailingCommaIsNotBlocking(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), "{\n  // kept\n  \"mcpServers\": {\"a\": {\"command\": \"x\",},},\n}\n")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".gemini/settings.json", model.ConfigKindMCPServer)) != 1 || !got.HasDiag("trailing comma") {
		t.Fatalf("got %+v", got)
	}
	if kittest.Blocking(t, New(Options{}), root, "trailing comma") {
		t.Fatal("a trailing comma was blocking")
	}
	root = t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), "{\n  \"hooks\": {\"BeforeTool\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"a\"}]}]}\n}\n")
	got = kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".gemini/settings.json", model.ConfigKindHook)) != 1 || len(got.Diagnostics) != 0 {
		t.Fatalf("a file without a trailing comma was reported: %+v", got)
	}
}

func TestOpaqueHooksSeparateSecrets(t *testing.T) {
	t.Parallel()
	key := func(token string) string {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), `{"hooks":{"BeforeTool":[{"type":"command","command":"run --token `+token+`"}]}}`)
		got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
		if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), token) {
			t.Fatalf("items = %+v", got.Items)
		}
		return kittest.Fingerprint(t, got.Items[0])
	}
	if key("one") == key("two") {
		t.Fatal("opaque hooks that differ only by a secret share a fingerprint")
	}
}

func TestSequentialIsKeptOnHandlers(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".gemini", "settings.json"), `{"hooks":{"BeforeTool":[
		{"sequential":true,"hooks":[{"type":"command","command":"a"}]},
		{"sequential":false,"hooks":[{"type":"command","command":"a"}]}
	]}}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".gemini/settings.json", model.ConfigKindHook)
	if len(items) != 2 {
		t.Fatalf("items = %+v", got.Items)
	}
	a, b := kittest.Payload(t, items[0]), kittest.Payload(t, items[1])
	if a["key"] == b["key"] || a["group_sequential"] == b["group_sequential"] {
		t.Fatalf("payloads = %v, %v", a, b)
	}
}

func TestHostileInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		file    string
		content string
		diag    string
		items   int
	}{
		{"malformed", ".gemini/settings.json", `{"mcpServers":`, "invalid JSON", 0},
		{"not object", ".gemini/settings.json", `[]`, "must be a JSON object", 0},
		{"comments and bom", ".gemini/settings.json", "\ufeff{/* c */\"mcpServers\":{\"a\":{\"command\":\"x\"}} // t\n}", "", 1},
		{"deep", ".gemini/settings.json", `{"mcpServers":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`, "nesting", 0},
		{"duplicate server", ".gemini/settings.json", `{"mcpServers":{"a":{"command":"x"},"a":{"command":"y"}}}`, "duplicate key", 1},
		{"case-variant keys", ".gemini/settings.json", `{"mcpServers":{"a":{"command":"x"}},"MCPServers":{}}`, "case-variant", 1},
		{"servers not object", ".gemini/settings.json", `{"mcpServers":[]}`, "mcpServers must be an object", 0},
		{"oversize", ".gemini/settings.json", `{"x":"` + strings.Repeat("a", 2<<20) + `"}`, "cannot read", 0},
		{"context unclosed frontmatter", "GEMINI.md", "---\nx: y\n", "", 1},
		{"context deep frontmatter", "GEMINI.md", "---\nx: " + strings.Repeat("[", 300) + strings.Repeat("]", 300) + "\n---\nbody", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, filepath.FromSlash(tc.file)), tc.content)
			got := kittest.Discover(t, New(Options{}), root)
			if len(got.Items) != tc.items {
				t.Fatalf("items = %d, want %d: %+v", len(got.Items), tc.items, got.Items)
			}
			if tc.diag == "" {
				if len(got.Diagnostics) != 0 {
					t.Fatalf("diagnostics = %v", got.Diagnostics)
				}
				return
			}
			if !got.HasDiag(tc.file+": ") || !got.HasDiag(tc.diag) {
				t.Fatalf("diagnostics = %v, want %q", got.Diagnostics, tc.diag)
			}
		})
	}
}

func TestSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	kittest.WriteFile(t, filepath.Join(outside, "settings.json"), `{"mcpServers":{"a":{"command":"x"}}}`)
	kittest.WriteFile(t, filepath.Join(root, "GEMINI.md"), "ok")
	if err := os.MkdirAll(filepath.Join(root, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "settings.json"), filepath.Join(root, ".gemini", "settings.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 1 || !got.HasDiag(".gemini/settings.json: symlink resolves outside the repository; Gemini CLI may load its target") {
		t.Fatalf("got %+v", got)
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".Gemini", "Settings.JSON"), `{"tools":{"sandbox":false}}`)
	kittest.WriteFile(t, filepath.Join(root, "sub", "gemini.md"), "x")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".Gemini/Settings.JSON", model.ConfigKindPermissions)) != 1 || len(got.Find("sub/gemini.md", model.ConfigKindInstructions)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestGeminiCLIHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	inside := filepath.Join(home, "alt")
	kittest.WriteFile(t, filepath.Join(inside, ".gemini", "settings.json"), `{"mcpServers":{"a":{"command":"`+filepath.ToSlash(home)+`/bin/x"}}}`)
	got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env("GEMINI_CLI_HOME", inside)}), t.TempDir())
	items := got.Find("~/alt/.gemini/settings.json", model.ConfigKindMCPServer)
	if len(items) != 1 || kittest.Payload(t, items[0])["command"] != "~/bin/x" || len(got.Diagnostics) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestGeminiCLIHomeOutsideHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	alt := t.TempDir()
	kittest.WriteFile(t, filepath.Join(alt, ".gemini", "settings.json"), `{"mcpServers":{"a":{"command":"x"}}}`)
	opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env("GEMINI_CLI_HOME", alt)}
	got := kittest.Discover(t, New(opts), t.TempDir())
	if len(got.Find("~/GEMINI_CLI_HOME/.gemini/settings.json", model.ConfigKindMCPServer)) != 1 || !got.HasDiag("outside the home directory") {
		t.Fatalf("got %+v", got)
	}
	if !kittest.Blocking(t, New(opts), t.TempDir(), "outside the home directory") {
		t.Fatal("GEMINI_CLI_HOME outside home did not produce a blocking diagnostic")
	}
}

func TestGeminiCLIHomeRelative(t *testing.T) {
	t.Parallel()
	opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: t.TempDir(), Getenv: kittest.Env("GEMINI_CLI_HOME", "rel")}
	if !kittest.Blocking(t, New(opts), t.TempDir(), "GEMINI_CLI_HOME is not an absolute path") {
		t.Fatal("a relative GEMINI_CLI_HOME was not reported")
	}
}

func TestSystemSettingsPathOverride(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	override := filepath.Join(dir, "custom.json")
	kittest.WriteFile(t, override, `{"tools":{"sandbox":"docker"}}`)
	opts := Options{SkipRepo: true, IncludeManaged: true, ManagedDir: t.TempDir(), Getenv: kittest.Env("GEMINI_CLI_SYSTEM_SETTINGS_PATH", override)}
	got := kittest.Discover(t, New(opts), t.TempDir())
	if len(got.Find(kit.ManagedPath(override), model.ConfigKindPermissions)) != 1 || len(got.Diagnostics) != 0 {
		t.Fatalf("got %+v", got)
	}
	opts.Getenv = kittest.Env("GEMINI_CLI_SYSTEM_DEFAULTS_PATH", "rel.json")
	if !kittest.Blocking(t, New(opts), t.TempDir(), "GEMINI_CLI_SYSTEM_DEFAULTS_PATH is not an absolute path") {
		t.Fatal("a relative system defaults path was not reported")
	}
}

func TestDefaultManagedDir(t *testing.T) {
	t.Parallel()
	cases := []struct{ goos, programData, want string }{
		{"linux", "", "/etc/gemini-cli"},
		{"darwin", "", "/Library/Application Support/GeminiCli"},
		{"windows", "", `C:\ProgramData\gemini-cli`},
		{"windows", `D:\PD`, `D:\PD\gemini-cli`},
	}
	for _, tc := range cases {
		if got := defaultManagedDir(tc.goos, kittest.Env("ProgramData", tc.programData)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.goos, got, tc.want)
		}
	}
}

func TestFingerprintsIgnoreMachinePaths(t *testing.T) {
	t.Parallel()
	run := func() []string {
		root := kittest.CopyTree(t, kittest.Tree(kittest.Baseline("gemini"), "repo"))
		home := t.TempDir()
		h := filepath.ToSlash(home)
		kittest.WriteFile(t, filepath.Join(home, ".gemini", "settings.json"), `{"mcpServers":{"a":{"command":"`+h+`/bin/mcp","args":["--token","x"]}},"hooks":{"AfterTool":[{"hooks":[{"type":"command","command":"`+h+`/hooks/a.sh"}]}]}}`)
		got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), root)
		var out []string
		for _, item := range got.Items {
			if strings.Contains(string(item.Payload), home) {
				t.Fatalf("payload contains the home directory: %s", item.Payload)
			}
			out = append(out, kittest.Fingerprint(t, item)+" "+string(item.Payload))
		}
		return out
	}
	a, b := run(), run()
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("fingerprints differ across machines:\n%v\n%v", a, b)
	}
}

func TestRepoScanDoesNotReadHome(t *testing.T) {
	t.Parallel()
	home := kittest.CopyTree(t, kittest.Tree(kittest.Baseline("gemini"), "home"))
	managed := kittest.CopyTree(t, kittest.Tree(kittest.Baseline("gemini"), "managed"))
	got := kittest.Discover(t, New(Options{HomeDir: home, ManagedDir: managed, Getenv: kittest.Env()}), t.TempDir())
	if len(got.Items) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("repository-only scan read user or managed files: %+v", got)
	}
}

func TestDetect(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "AGENTS.md"), "x")
	if New(Options{}).Detect(root) {
		t.Fatal("Detect claimed AGENTS.md")
	}
	kittest.WriteFile(t, filepath.Join(root, "GEMINI.md"), "x")
	if !New(Options{}).Detect(root) || New(Options{SkipRepo: true}).Detect(root) {
		t.Fatal("Detect mismatch")
	}
}

func FuzzParseConfig(f *testing.F) {
	seeds := map[string]string{
		"settings": "testdata/gemini-baseline/repo/.gemini/settings.json",
		"user":     "testdata/gemini-baseline/home/.gemini/settings.json",
		"context":  "testdata/gemini-baseline/repo/GEMINI.md",
	}
	for kind, path := range seeds {
		if data, err := kittest.ReadFixture(path); err == nil {
			if kind == "user" {
				kind = "settings"
			}
			f.Add(kind, data)
		}
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.HarnessGemini, product)
		for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeUser} {
			path := ".gemini/settings.json"
			if scope == model.ScopeUser {
				path = "~/.gemini/settings.json"
			}
			f := &file{Source: c.Source(scope, path, data)}
			switch kind {
			case "settings":
				f.settings(data)
			default:
				f.Markdown(model.ConfigKindInstructions, "gemini", data, kit.LooseFrontmatter)
			}
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}
