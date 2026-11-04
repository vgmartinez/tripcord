package windsurf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

const fixtureManagedDir = "/etc/windsurf"

// fixtureSecrets are the values planted in testdata that no item may
// carry.
var fixtureSecrets = []string{"ws-tok-111", "ws-q-222", "ws-key-333", "ws-q-444", "ws-home-555", "ws-bearer-666", "ws-q-777"}

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
					t.Fatalf("windsurf reported %s, which the generic adapter owns", item.Path)
				}
			}
			if len(got.Find("web/.windsurf/hooks.json", model.ConfigKindHook)) != 1 {
				t.Fatal("nested .windsurf/hooks.json not read")
			}
			if len(got.Find("~/.codeium/windsurf/memories/global_rules.md", model.ConfigKindInstructions)) != 1 {
				t.Fatal("global rules were not read")
			}
			if len(got.Find(".windsurf/global_rules.md", model.ConfigKindInstructions)) != 1 {
				t.Fatal("repository global rules were not read")
			}
		})
	}
}

func TestDevinAndWindsurfHooksAreBothReported(t *testing.T) {
	t.Parallel()
	cases := map[string]map[string]string{
		"same directory": {
			".devin/hooks.json":    `{"hooks":{}}`,
			".windsurf/hooks.json": `{"hooks":{"pre_run_command":[{"command":"windsurf-hook"}]}}`,
		},
		"separate directories": {
			"pkg/.devin/hooks.json": `{"hooks":{}}`,
			".windsurf/hooks.json":  `{"hooks":{"pre_run_command":[{"command":"windsurf-hook"}]}}`,
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			for rel, content := range files {
				kittest.WriteFile(t, filepath.Join(root, filepath.FromSlash(rel)), content)
			}
			got := kittest.Discover(t, New(Options{}), root)
			if len(got.Find(".windsurf/hooks.json", model.ConfigKindHook)) != 1 {
				t.Fatalf("Windsurf hooks were suppressed: %+v", got)
			}
			for _, item := range got.Items {
				if strings.Contains(string(item.Payload), "windsurf-hook") {
					return
				}
			}
			t.Fatalf("Windsurf hook was not reported: %+v", got.Items)
		})
	}
}

func TestDevinSystemHooksAlsoReportsWindsurf(t *testing.T) {
	t.Parallel()
	hooks := func(command string) string {
		return `{"hooks":{"pre_run_command":[{"command":"` + command + `"}]}}`
	}
	devin := t.TempDir()
	windsurf := t.TempDir()
	kittest.WriteFile(t, filepath.Join(devin, "hooks.json"), hooks("from-devin"))
	kittest.WriteFile(t, filepath.Join(windsurf, "hooks.json"), hooks("from-windsurf"))
	opts := Options{SkipRepo: true, IncludeManaged: true, ManagedDir: windsurf, DevinManagedDir: devin}
	got := kittest.Discover(t, New(opts), t.TempDir())
	if len(got.Find(kit.ManagedPath(devin)+"/hooks.json", model.ConfigKindHook)) != 1 ||
		len(got.Find(kit.ManagedPath(windsurf)+"/hooks.json", model.ConfigKindHook)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	if !got.HasDiag("override this Windsurf file") || kittest.Blocking(t, New(opts), t.TempDir(), "override this Windsurf file") {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
	for _, item := range got.Items {
		if !strings.Contains(string(item.Payload), "from-windsurf") &&
			!strings.Contains(string(item.Payload), "from-devin") {
			t.Fatalf("unexpected hooks item: %s", item.Payload)
		}
	}
}

func TestChannelDirsAndGlobalRules(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	for _, dir := range []string{"windsurf", "windsurf-next", "windsurf-insiders"} {
		kittest.WriteFile(t, filepath.Join(home, ".codeium", dir, "memories", "global_rules.md"), "rules for "+dir)
		kittest.WriteFile(t, filepath.Join(home, ".codeium", dir, "hooks.json"), `{"hooks":{"pre_read_code":[{"command":"`+dir+`"}]}}`)
		kittest.WriteFile(t, filepath.Join(home, ".codeium", dir, "mcp_config.json"), `{"mcpServers":{"`+dir+`":{"command":"x"}}}`)
	}
	got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home}), t.TempDir())
	for _, dir := range []string{"windsurf", "windsurf-next", "windsurf-insiders"} {
		base := "~/.codeium/" + dir
		if len(got.Find(base+"/memories/global_rules.md", model.ConfigKindInstructions)) != 1 ||
			len(got.Find(base+"/hooks.json", model.ConfigKindHook)) != 1 ||
			len(got.Find(base+"/mcp_config.json", model.ConfigKindMCPServer)) != 1 {
			t.Fatalf("%s not fully read: %+v", dir, got.Items)
		}
	}
}

func TestDevinSystemHooksFallback(t *testing.T) {
	t.Parallel()
	hooks := func(command string) string {
		return `{"hooks":{"pre_run_command":[{"command":"` + command + `"}]}}`
	}
	t.Run("fallback", func(t *testing.T) {
		t.Parallel()
		windsurf := t.TempDir()
		kittest.WriteFile(t, filepath.Join(windsurf, "hooks.json"), hooks("from-windsurf"))
		got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeManaged: true, ManagedDir: windsurf, DevinManagedDir: t.TempDir()}), t.TempDir())
		if len(got.Find(kit.ManagedPath(windsurf)+"/hooks.json", model.ConfigKindHook)) != 1 || len(got.Diagnostics) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("devin wins", func(t *testing.T) {
		t.Parallel()
		devin := t.TempDir()
		windsurf := t.TempDir()
		kittest.WriteFile(t, filepath.Join(devin, "hooks.json"), hooks("from-devin"))
		kittest.WriteFile(t, filepath.Join(windsurf, "hooks.json"), hooks("from-windsurf"))
		got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeManaged: true, ManagedDir: windsurf, DevinManagedDir: devin}), t.TempDir())
		if len(got.Find(kit.ManagedPath(devin)+"/hooks.json", model.ConfigKindHook)) != 1 || len(got.Find(kit.ManagedPath(windsurf)+"/hooks.json", model.ConfigKindHook)) != 1 {
			t.Fatalf("items = %+v", got.Items)
		}
		if !got.HasDiag("override this Windsurf file") || kittest.Blocking(t, New(Options{SkipRepo: true, IncludeManaged: true, ManagedDir: windsurf, DevinManagedDir: devin}), t.TempDir(), "override this Windsurf file") {
			t.Fatalf("diagnostics = %v", got.Diagnostics)
		}
		for _, item := range got.Items {
			if !strings.Contains(string(item.Payload), "from-windsurf") &&
				!strings.Contains(string(item.Payload), "from-devin") {
				t.Fatalf("unexpected hooks item: %s", item.Payload)
			}
		}
	})
}

func TestDevinManagedDir(t *testing.T) {
	t.Parallel()
	cases := []struct{ goos, programData, want string }{
		{"linux", "", "/etc/devin"},
		{"darwin", "", "/Library/Application Support/Devin"},
		{"windows", "", `C:\ProgramData\Devin`},
		{"windows", `D:\PD`, `D:\PD\Devin`},
	}
	for _, tc := range cases {
		if got := devinManagedDir(tc.goos, kittest.Env("ProgramData", tc.programData)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.goos, got, tc.want)
		}
	}
}

func TestHooksShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		hooks string
		items int
		diag  string
	}{
		{"documented", `{"hooks":{"pre_run_command":[{"command":"a"},{"command":"b"}]}}`, 2, ""},
		{"powershell only", `{"hooks":{"pre_run_command":[{"powershell":"a.ps1"}]}}`, 1, ""},
		{"unknown event", `{"hooks":{"pre_everything":[{"command":"a"}]}}`, 1, "not a documented Cascade hook event"},
		{"no hooks object", `{"pre_run_command":[{"command":"a"}]}`, 0, "no hooks object"},
		{"hooks not object", `{"hooks":[]}`, 0, "hooks must be an object"},
		{"event not array", `{"hooks":{"pre_run_command":{"command":"a"}}}`, 0, "hooks.pre_run_command must be an array"},
		{"handler not object", `{"hooks":{"pre_run_command":["a"]}}`, 0, "entry must be an object"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".windsurf", "hooks.json"), tc.hooks)
			got := kittest.Discover(t, New(Options{}), root)
			if n := len(got.Find(".windsurf/hooks.json", model.ConfigKindHook)); n != tc.items {
				t.Fatalf("hooks = %d, want %d: %+v", n, tc.items, got.Items)
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
		})
	}
}

func TestHookSecretsSeparateFingerprints(t *testing.T) {
	t.Parallel()
	key := func(token string) string {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".windsurf", "hooks.json"), `{"hooks":{"pre_run_command":[{"command":"run --token `+token+`"}]}}`)
		got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
		if len(got.Items) != 1 || strings.Contains(string(got.Items[0].Payload), token) {
			t.Fatalf("items = %+v", got.Items)
		}
		return kittest.Fingerprint(t, got.Items[0])
	}
	if key("one") == key("two") {
		t.Fatal("hooks that differ only by a secret share a fingerprint")
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
		{"malformed", ".windsurf/hooks.json", `{"hooks":`, "invalid JSON", 0},
		{"not object", ".windsurf/hooks.json", `[]`, "must be a JSON object", 0},
		{"jsonc", ".windsurf/hooks.json", "\ufeff{/* c */\"hooks\":{\"pre_read_code\":[{\"command\":\"x\",},],}, // t\n}", "", 1},
		{"deep", ".windsurf/hooks.json", `{"hooks":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`, "nesting", 0},
		{"duplicate event", ".windsurf/hooks.json", `{"hooks":{"pre_read_code":[{"command":"x"}],"pre_read_code":[{"command":"y"}]}}`, "duplicate key", 1},
		{"oversize", ".windsurf/hooks.json", `{"x":"` + strings.Repeat("a", 2<<20) + `"}`, "cannot read", 0},
		{"rule unclosed frontmatter", ".windsurf/rules/a.md", "---\nx: y\n", "", 1},
		{"rule deep frontmatter", ".windsurf/rules/a.md", "---\nx: " + strings.Repeat("[", 300) + strings.Repeat("]", 300) + "\n---\nbody", "", 1},
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

func TestMCPConfig(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	h := filepath.ToSlash(home)
	kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{"mcpServers":{
		"a":{"command":"`+h+`/bin/x","args":["--api-key","k-1"],"env":{"A_TOKEN":"t-1"}},
		"b":{"serverUrl":"https://h.example/?token=q-1","headers":{"Authorization":"Bearer b-1"}}
	}}`)
	got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home}), t.TempDir())
	items := got.Find("~/.codeium/windsurf/mcp_config.json", model.ConfigKindMCPServer)
	if len(items) != 2 || len(got.Diagnostics) != 0 {
		t.Fatalf("got %+v", got)
	}
	for _, item := range items {
		for _, leak := range []string{"k-1", "t-1", "q-1", "b-1", home} {
			if strings.Contains(string(item.Payload), leak) {
				t.Fatalf("payload leaks %q: %s", leak, item.Payload)
			}
		}
	}
	kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{"servers":{}}`)
	if got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home}), t.TempDir()); !got.HasDiag("no mcpServers object") {
		t.Fatalf("got %+v", got)
	}
}

func TestSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	kittest.WriteFile(t, filepath.Join(outside, "hooks.json"), `{"hooks":{"pre_read_code":[{"command":"x"}]}}`)
	kittest.WriteFile(t, filepath.Join(root, ".windsurfrules"), "ok")
	if err := os.MkdirAll(filepath.Join(root, ".windsurf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "hooks.json"), filepath.Join(root, ".windsurf", "hooks.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 1 || !got.HasDiag(".windsurf/hooks.json: symlink resolves outside the repository; Windsurf may load its target") {
		t.Fatalf("got %+v", got)
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".Windsurf", "Hooks.JSON"), `{"hooks":{"pre_read_code":[{"command":"x"}]}}`)
	kittest.WriteFile(t, filepath.Join(root, ".windsurf", "RULES", "A.MD"), "x")
	kittest.WriteFile(t, filepath.Join(root, "sub", ".windsurfrules"), "not read below the root")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 2 || len(got.Find(".Windsurf/Hooks.JSON", model.ConfigKindHook)) != 1 || len(got.Find(".windsurf/RULES/A.MD", model.ConfigKindInstructions)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestDefaultManagedDir(t *testing.T) {
	t.Parallel()
	cases := []struct{ goos, programData, want string }{
		{"linux", "", "/etc/windsurf"},
		{"darwin", "", "/Library/Application Support/Windsurf"},
		{"windows", "", `C:\ProgramData\Windsurf`},
		{"windows", `D:\PD`, `D:\PD\Windsurf`},
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
		root := kittest.CopyTree(t, kittest.Tree(kittest.Baseline("windsurf"), "repo"))
		home := t.TempDir()
		h := filepath.ToSlash(home)
		kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{"mcpServers":{"a":{"command":"`+h+`/bin/mcp","args":["--token","x"]}}}`)
		kittest.WriteFile(t, filepath.Join(home, ".codeium", "windsurf", "hooks.json"), `{"hooks":{"post_write_code":[{"command":"`+h+`/hooks/a.sh"}]}}`)
		got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home}), root)
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
	home := kittest.CopyTree(t, kittest.Tree(kittest.Baseline("windsurf"), "home"))
	managed := kittest.CopyTree(t, kittest.Tree(kittest.Baseline("windsurf"), "managed"))
	got := kittest.Discover(t, New(Options{HomeDir: home, ManagedDir: managed}), t.TempDir())
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
	kittest.WriteFile(t, filepath.Join(root, ".windsurf", "rules", "a.md"), "x")
	if !New(Options{}).Detect(root) || New(Options{SkipRepo: true}).Detect(root) {
		t.Fatal("Detect mismatch")
	}
}

func FuzzParseConfig(f *testing.F) {
	seeds := map[string]string{
		"hooks": "testdata/windsurf-baseline/repo/.windsurf/hooks.json",
		"mcp":   "testdata/windsurf-baseline/home/.codeium/windsurf/mcp_config.json",
		"rule":  "testdata/windsurf-baseline/repo/.windsurf/rules/backend/db.md",
	}
	for kind, path := range seeds {
		if data, err := kittest.ReadFixture(path); err == nil {
			f.Add(kind, data)
		}
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.HarnessWindsurf, product)
		for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeUser} {
			path := ".windsurf/hooks.json"
			if scope == model.ScopeUser {
				path = "~/.codeium/windsurf/hooks.json"
			}
			f := &file{Source: c.Source(scope, path, data)}
			switch kind {
			case "hooks":
				f.hooks(data)
			case "mcp":
				f.mcpConfig(data)
			default:
				f.Markdown(model.ConfigKindInstructions, "rule", data, kit.LooseFrontmatter)
			}
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}
