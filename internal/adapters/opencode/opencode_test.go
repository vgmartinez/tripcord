package opencode

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

const fixtureManagedDir = "/etc/opencode"

// fixtureSecrets are the values planted in testdata that no item may
// carry. oc-code-000 sits in plugin source, oc-auth-999 in auth.json:
// neither file's content may be read into an item.
var fixtureSecrets = []string{"oc-key-111", "oc-tok-222", "oc-q-333", "oc-bearer-444", "oc-q-555", "oc-home-777", "oc-q-888", "oc-auth-999", "oc-code-000"}

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	home := kittest.CopyTree(t, filepath.Join("testdata", "home"))
	managed := kittest.CopyTree(t, filepath.Join("testdata", "managed"))
	a := New(Options{IncludeUser: true, IncludeManaged: true, HomeDir: home, ManagedDir: managed, Getenv: kittest.Env()})
	got := kittest.Discover(t, a, root)
	kittest.AssertGolden(t, "discover.golden", kittest.GoldenJSON(t, got, map[string]string{filepath.ToSlash(managed): fixtureManagedDir}))
	raw := string(kittest.GoldenJSON(t, got, nil))
	for _, leak := range append([]string{home}, fixtureSecrets...) {
		if strings.Contains(raw, leak) {
			t.Fatalf("discovery leaks %q", leak)
		}
	}
	for _, item := range got.Items {
		if item.Scope == model.ScopeRepo && strings.EqualFold(filepath.Base(item.Path), "AGENTS.md") {
			t.Fatalf("opencode reported %s, which the generic adapter owns", item.Path)
		}
		if strings.Contains(item.Path, "node_modules") || strings.Contains(item.Path, "lib/helper") {
			t.Fatalf("opencode reported %s, which it does not load as a plugin", item.Path)
		}
	}
}

func TestCodeFilesAreReferencesOnly(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "a.ts"), "secret-in-code-1")
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugin", "b.mjs"), "x")
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "tools", "c.js"), "x")
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "README.md"), "x")
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "sub", "d.ts"), "x")
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "lib", "helper.ts"), "secret-nested")
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "node_modules", "pkg", "index.js"), "x")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 3 || !got.HasDiag("nested plugin or tool file") || got.HasDiag("node_modules") {
		t.Fatalf("got %+v", got)
	}
	if kittest.Blocking(t, New(Options{}), root, "nested plugin or tool file") {
		t.Fatal("a nested plugin file was blocking")
	}
	for _, item := range got.Items {
		if strings.Contains(string(item.Payload), "secret-nested") || strings.Contains(item.Path, "helper") {
			t.Fatalf("nested file was reported as an item: %+v", item)
		}
	}
	p := kittest.Payload(t, got.Find(".opencode/plugins/a.ts", model.ConfigKindPlugin)[0])
	if p["executable"] != true || p["language"] != "ts" || p["role"] != "plugin" || strings.Contains(string(got.Items[0].Payload), "secret-in-code") {
		t.Fatalf("payload = %v", p)
	}
	if kittest.Payload(t, got.Find(".opencode/tools/c.js", model.ConfigKindPlugin)[0])["role"] != "tool" {
		t.Fatal("tool file not reported as a tool")
	}
}

func TestConfigContentIsNotedNotRead(t *testing.T) {
	t.Parallel()
	const secret = "oc-inline-secret-should-not-appear"
	opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: t.TempDir(), Getenv: kittest.Env("OPENCODE_CONFIG_CONTENT", `{"plugin":["`+secret+`"]}`)}
	got := kittest.Discover(t, New(opts), t.TempDir())
	if len(got.Items) != 0 || !got.HasDiag("OPENCODE_CONFIG_CONTENT is set") {
		t.Fatalf("got %+v", got)
	}
	for _, diag := range got.Diagnostics {
		if strings.Contains(diag, secret) {
			t.Fatalf("diagnostic contains the inline config: %s", diag)
		}
	}
	if kittest.Blocking(t, New(opts), t.TempDir(), "OPENCODE_CONFIG_CONTENT") {
		t.Fatal("OPENCODE_CONFIG_CONTENT was blocking")
	}
}

func TestUserNestedPluginIsNoted(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".config", "opencode", "plugins", "top.ts"), "x")
	kittest.WriteFile(t, filepath.Join(home, ".config", "opencode", "plugins", "lib", "helper.ts"), "nested-secret")
	kittest.WriteFile(t, filepath.Join(home, ".config", "opencode", "plugins", "node_modules", "pkg", "index.js"), "x")
	got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), t.TempDir())
	if len(got.Find("~/.config/opencode/plugins/top.ts", model.ConfigKindPlugin)) != 1 || !got.HasDiag("plugins/lib/helper.ts") {
		t.Fatalf("got %+v", got)
	}
	for _, item := range got.Items {
		if strings.Contains(item.Path, "helper") || strings.Contains(item.Path, "node_modules") {
			t.Fatalf("nested file was an item: %+v", item)
		}
	}
	if got.HasDiag("node_modules") {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
}

func TestRepoNestedPluginNotesAreCapped(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for i := 0; i < maxNestedNotes+3; i++ {
		kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "helpers", fmt.Sprintf("p%02d.ts", i)), "nested-secret")
	}
	got := kittest.Discover(t, New(Options{}), root)
	var nested, summaries int
	for _, diag := range got.Diagnostics {
		switch {
		case strings.Contains(diag, nestedNote):
			nested++
		case strings.Contains(diag, "further 3 nested plugin or tool files"):
			summaries++
		}
	}
	if nested != maxNestedNotes || summaries != 1 {
		t.Fatalf("nested notes = %d, summaries = %d: %v", nested, summaries, got.Diagnostics)
	}
	if kittest.Blocking(t, New(Options{}), root, "nested plugin or tool") {
		t.Fatal("nested plugin notes were blocking")
	}

	root = t.TempDir()
	for i := 0; i < maxNestedNotes+1; i++ {
		kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "helpers", fmt.Sprintf("q%02d.ts", i)), "nested-secret")
	}
	got = kittest.Discover(t, New(Options{}), root)
	if !got.HasDiag("further 1 nested plugin or tool file was not listed") || got.HasDiag("further 1 nested plugin or tool files") {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
}

func TestCodeFileShaPinsContent(t *testing.T) {
	t.Parallel()
	key := func(content string) string {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".opencode", "plugins", "a.ts"), content)
		got := kittest.Discover(t, New(Options{}), root)
		if len(got.Items) != 1 {
			t.Fatalf("items = %+v", got.Items)
		}
		return got.Items[0].SHA256
	}
	if key("one") == key("two") {
		t.Fatal("plugin files with different code share a sha256")
	}
}

func TestMCPCommandArgv(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "opencode.json"), `{"mcp":{
		"a":{"type":"local","command":["docker","login","-p","dock-1"],"environment":{"X_TOKEN":"tok-1","PLAIN":"v"}},
		"b":{"type":"remote","url":"https://h.example/","headers":{"Authorization":"Bearer hdr-1"}},
		"c":{"type":"local","command":7}
	}}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find("opencode.json", model.ConfigKindMCPServer)
	if len(items) != 3 || !got.HasDiag(`MCP server "c" command must be an array`) {
		t.Fatalf("got %+v", got)
	}
	for _, item := range items {
		for _, leak := range []string{"dock-1", "tok-1", "hdr-1"} {
			if strings.Contains(string(item.Payload), leak) {
				t.Fatalf("payload leaks %q: %s", leak, item.Payload)
			}
		}
	}
	byName := map[string]map[string]any{}
	for _, item := range items {
		p := kittest.Payload(t, item)
		byName[p["name"].(string)] = p
	}
	if keys, _ := byName["a"]["env_keys"].([]any); len(keys) != 2 {
		t.Fatalf("payload = %v", byName["a"])
	}
	if keys, _ := byName["b"]["header_keys"].([]any); len(keys) != 1 {
		t.Fatalf("payload = %v", byName["b"])
	}
}

func TestMCPSecretsSeparateFingerprints(t *testing.T) {
	t.Parallel()
	key := func(secret string) string {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, "opencode.json"), `{"mcp":{"a":{"type":"local","command":["docker","login","-p","`+secret+`"]}}}`)
		got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
		if len(got.Items) != 1 {
			t.Fatalf("items = %+v", got.Items)
		}
		return kittest.Fingerprint(t, got.Items[0])
	}
	if key("one") == key("two") {
		t.Fatal("servers that differ only by a tool-flag secret share a fingerprint")
	}
}

func TestPlugins(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "opencode.json"), `{"plugin":["a@1","b",3]}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find("opencode.json", model.ConfigKindPlugin)) != 3 || !got.HasDiag("plugin entries must be strings") {
		t.Fatalf("got %+v", got)
	}
	root = t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "opencode.json"), `{"plugin":"a"}`)
	got = kittest.Discover(t, New(Options{}), root)
	if len(got.Find("opencode.json", model.ConfigKindPlugin)) != 1 || !got.HasDiag("plugin must be an array") {
		t.Fatalf("got %+v", got)
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
		{"malformed", "opencode.json", `{"mcp":`, "invalid JSON", 0},
		{"not object", "opencode.jsonc", `[]`, "must be a JSON object", 0},
		{"jsonc", "opencode.jsonc", "\ufeff{/* c */\"mcp\":{\"a\":{\"type\":\"local\",\"command\":[\"x\",],},}, // t\n}", "", 1},
		{"trailing comma in .json", ".opencode/opencode.json", `{"plugin":["a",],}`, "", 1},
		{"deep", "opencode.json", `{"mcp":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`, "nesting", 0},
		{"duplicate server", "opencode.json", `{"mcp":{"a":{"command":["x"]},"a":{"command":["y"]}}}`, "duplicate key", 1},
		{"mcp not object", "opencode.json", `{"mcp":[]}`, "mcp must be an object", 0},
		{"agent not object", "opencode.json", `{"agent":"x"}`, "agent must be an object", 0},
		{"oversize", "opencode.json", `{"x":"` + strings.Repeat("a", 2<<20) + `"}`, "cannot read", 0},
		{"agent unclosed frontmatter", ".opencode/agents/a.md", "---\nx: y\n", "no closing --- line", 1},
		{"agent deep frontmatter", ".opencode/agents/a.md", "---\nx: " + strings.Repeat("[", 300) + strings.Repeat("]", 300) + "\n---\nbody", "nesting", 1},
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
	kittest.WriteFile(t, filepath.Join(outside, "evil.ts"), "x")
	kittest.WriteFile(t, filepath.Join(root, "opencode.json"), `{}`)
	if err := os.MkdirAll(filepath.Join(root, ".opencode", "plugins"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "evil.ts"), filepath.Join(root, ".opencode", "plugins", "evil.ts")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 0 || !got.HasDiag(".opencode/plugins/evil.ts: symlink resolves outside the repository; OpenCode may load its target") {
		t.Fatalf("got %+v", got)
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".OpenCode", "Plugins", "X.TS"), "x")
	kittest.WriteFile(t, filepath.Join(root, "sub", "OpenCode.JSON"), `{"permission":{"bash":"allow"}}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".OpenCode/Plugins/X.TS", model.ConfigKindPlugin)) != 1 || len(got.Find("sub/OpenCode.JSON", model.ConfigKindPermissions)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestCredentialFilesAreNeverRead(t *testing.T) {
	t.Parallel()
	sha := func(secret string) string {
		home := t.TempDir()
		kittest.WriteFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"), `{"a":{"key":"`+secret+`"}}`)
		kittest.WriteFile(t, filepath.Join(home, ".local", "share", "opencode", "mcp-auth.json"), `{"a":"`+secret+`"}`)
		got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), t.TempDir())
		items := got.Find("~/.local/share/opencode/auth.json", model.ConfigKindEnvSetup)
		if len(items) != 1 || len(got.Find("~/.local/share/opencode/mcp-auth.json", model.ConfigKindEnvSetup)) != 1 {
			t.Fatalf("got %+v", got)
		}
		p := kittest.Payload(t, items[0])
		if p["secret_bearing"] != true || p["value"] != kit.Redacted || strings.Contains(string(items[0].Payload), secret) {
			t.Fatalf("payload = %v", p)
		}
		return items[0].SHA256 + kittest.Fingerprint(t, items[0])
	}
	if sha("one") != sha("two") {
		t.Fatal("credential file item depends on the file's content")
	}
}

func TestConfigDirOverrides(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	h := filepath.ToSlash(home)
	kittest.WriteFile(t, filepath.Join(home, "oc", "opencode.json"), `{"mcp":{"a":{"type":"local","command":["`+h+`/bin/x"]}}}`)
	kittest.WriteFile(t, filepath.Join(home, "oc", "agents", "r.md"), "x")
	kittest.WriteFile(t, filepath.Join(home, "one.json"), `{"permission":{"edit":"ask"}}`)
	kittest.WriteFile(t, filepath.Join(home, "xdg", "opencode", "opencode.jsonc"), `{"plugin":["p"],}`)
	env := kittest.Env("OPENCODE_CONFIG_DIR", filepath.Join(home, "oc"), "OPENCODE_CONFIG", filepath.Join(home, "one.json"), "XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: env}), t.TempDir())
	items := got.Find("~/oc/opencode.json", model.ConfigKindMCPServer)
	if len(items) != 1 || len(got.Diagnostics) != 0 {
		t.Fatalf("got %+v", got)
	}
	if cmd, _ := kittest.Payload(t, items[0])["command"].([]any); len(cmd) != 1 || cmd[0] != "~/bin/x" {
		t.Fatalf("payload = %v", kittest.Payload(t, items[0]))
	}
	if len(got.Find("~/oc/agents/r.md", model.ConfigKindInstructions)) != 1 ||
		len(got.Find("~/one.json", model.ConfigKindPermissions)) != 1 ||
		len(got.Find("~/xdg/opencode/opencode.jsonc", model.ConfigKindPlugin)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestOverridesOutsideHomeAreBlocking(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"OPENCODE_CONFIG_DIR"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: t.TempDir(), Getenv: kittest.Env(name, t.TempDir())}
			if !kittest.Blocking(t, New(opts), t.TempDir(), "outside the home directory") {
				t.Fatalf("%s outside home did not produce a blocking diagnostic", name)
			}
		})
	}
	t.Run("OPENCODE_CONFIG", func(t *testing.T) {
		t.Parallel()
		outside := t.TempDir()
		kittest.WriteFile(t, filepath.Join(outside, "c.json"), `{"permission":{"bash":"allow"}}`)
		opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: t.TempDir(), Getenv: kittest.Env("OPENCODE_CONFIG", filepath.Join(outside, "c.json"))}
		got := kittest.Discover(t, New(opts), t.TempDir())
		if len(got.Find("~/OPENCODE_CONFIG/c.json", model.ConfigKindPermissions)) != 1 {
			t.Fatalf("got %+v", got)
		}
		if !kittest.Blocking(t, New(opts), t.TempDir(), "outside the home directory") {
			t.Fatal("OPENCODE_CONFIG outside home did not produce a blocking diagnostic")
		}
	})
}

func TestXDGOverrideOutsideHomeIsInformational(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			outside := t.TempDir()
			if name == "XDG_CONFIG_HOME" {
				kittest.WriteFile(t, filepath.Join(outside, "opencode", "opencode.json"), `{"plugin":["from-xdg"]}`)
			} else {
				kittest.WriteFile(t, filepath.Join(outside, "opencode", "auth.json"), `{"key":"should-not-be-read"}`)
			}
			opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env(name, outside)}
			got := kittest.Discover(t, New(opts), t.TempDir())
			if !got.HasDiag("outside the home directory") {
				t.Fatalf("diagnostics = %v", got.Diagnostics)
			}
			if kittest.Blocking(t, New(opts), t.TempDir(), "outside the home directory") {
				t.Fatalf("%s outside home was blocking", name)
			}
			if name == "XDG_CONFIG_HOME" && len(got.Find("~/XDG_CONFIG_HOME/opencode/opencode.json", model.ConfigKindPlugin)) != 1 {
				t.Fatalf("xdg config was not scanned: %+v", got.Items)
			}
			if name == "XDG_DATA_HOME" {
				items := got.Find("~/XDG_DATA_HOME/opencode/auth.json", model.ConfigKindEnvSetup)
				if len(items) != 1 || strings.Contains(string(items[0].Payload), "should-not-be-read") {
					t.Fatalf("items = %+v", got.Items)
				}
			}
		})
	}
}

func TestRelativeXDGUsesDefault(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".config", "opencode", "opencode.json"), `{"plugin":["from-default"]}`)
	kittest.WriteFile(t, filepath.Join(home, "rel", "opencode", "opencode.json"), `{"plugin":["from-relative"]}`)
	kittest.WriteFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"), `{"key":"x"}`)
	opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env("XDG_CONFIG_HOME", "rel", "XDG_DATA_HOME", "also-rel")}
	got := kittest.Discover(t, New(opts), t.TempDir())
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
	if len(got.Find("~/.config/opencode/opencode.json", model.ConfigKindPlugin)) != 1 || len(got.Find("~/.local/share/opencode/auth.json", model.ConfigKindEnvSetup)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	for _, item := range got.Items {
		if strings.Contains(string(item.Payload), "from-relative") || strings.Contains(item.Path, "rel/") {
			t.Fatalf("relative XDG was used: %+v", item)
		}
	}
}

func TestRelativeOPENCODEConfigDirIsBlocking(t *testing.T) {
	t.Parallel()
	t.Run("relative", func(t *testing.T) {
		t.Parallel()
		opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: t.TempDir(), Getenv: kittest.Env("OPENCODE_CONFIG_DIR", "rel")}
		if !kittest.Blocking(t, New(opts), t.TempDir(), "OPENCODE_CONFIG_DIR is not an absolute path") {
			t.Fatal("a relative OPENCODE_CONFIG_DIR was not reported")
		}
	})
}

func TestDefaultManagedDir(t *testing.T) {
	t.Parallel()
	cases := []struct{ goos, programData, want string }{
		{"linux", "", "/etc/opencode"},
		{"darwin", "", "/Library/Application Support/opencode"},
		{"windows", "", `C:\ProgramData\opencode`},
		{"windows", `D:\PD`, `D:\PD\opencode`},
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
		root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
		home := t.TempDir()
		h := filepath.ToSlash(home)
		kittest.WriteFile(t, filepath.Join(home, ".config", "opencode", "opencode.json"), `{"mcp":{"a":{"type":"local","command":["`+h+`/bin/mcp","--token","x"]}}}`)
		kittest.WriteFile(t, filepath.Join(home, ".config", "opencode", "plugins", "p.ts"), h)
		kittest.WriteFile(t, filepath.Join(home, ".local", "share", "opencode", "auth.json"), h)
		got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), root)
		var out []string
		for _, item := range got.Items {
			if strings.Contains(string(item.Payload), home) {
				t.Fatalf("payload contains the home directory: %s", item.Payload)
			}
			if item.Path != "~/.config/opencode/plugins/p.ts" {
				out = append(out, kittest.Fingerprint(t, item)+" "+string(item.Payload))
			}
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
	home := kittest.CopyTree(t, filepath.Join("testdata", "home"))
	managed := kittest.CopyTree(t, filepath.Join("testdata", "managed"))
	got := kittest.Discover(t, New(Options{HomeDir: home, ManagedDir: managed, Getenv: kittest.Env()}), t.TempDir())
	if len(got.Items) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("repository-only scan read user or managed files: %+v", got)
	}
}

func TestDetect(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, "AGENTS.md"), "x")
	kittest.WriteFile(t, filepath.Join(root, ".opencode", "AGENTS.md"), "x")
	if New(Options{}).Detect(root) {
		t.Fatal("Detect claimed AGENTS.md")
	}
	kittest.WriteFile(t, filepath.Join(root, "opencode.jsonc"), "{}")
	if !New(Options{}).Detect(root) || New(Options{SkipRepo: true}).Detect(root) {
		t.Fatal("Detect mismatch")
	}
}

func FuzzParseConfig(f *testing.F) {
	seeds := map[string]string{
		"config": "testdata/repo/opencode.jsonc",
		"user":   "testdata/home/.config/opencode/opencode.json",
		"agent":  "testdata/repo/.opencode/agents/security.md",
	}
	for kind, path := range seeds {
		if data, err := os.ReadFile(path); err == nil {
			if kind == "user" {
				kind = "config"
			}
			f.Add(kind, data)
		}
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.HarnessOpenCode, product)
		for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeUser} {
			rel := "opencode.json"
			if scope == model.ScopeUser {
				rel = "~/.config/opencode/opencode.json"
			}
			src := c.Source(scope, rel, data)
			switch kind {
			case "config":
				normalize(src, roleConfig, rel, data)
			case "plugin":
				normalize(src, rolePlugin, ".opencode/plugins/x.ts", data)
			default:
				normalize(src, roleAgent, ".opencode/agents/x.md", data)
			}
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}
