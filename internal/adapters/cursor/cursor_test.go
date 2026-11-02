package cursor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

const fixtureManagedDir = "/etc/cursor"

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	home := kittest.CopyTree(t, filepath.Join("testdata", "home"))
	managed := kittest.CopyTree(t, filepath.Join("testdata", "managed"))
	got := kittest.Discover(t, New(Options{IncludeUser: true, IncludeManaged: true, HomeDir: home, ManagedDir: managed}), root)
	kittest.AssertGolden(t, "discover.golden", kittest.GoldenJSON(t, got, map[string]string{filepath.ToSlash(managed): fixtureManagedDir}))
	raw := string(kittest.GoldenJSON(t, got, nil))
	for _, leak := range []string{home, "abc123", "t-123", "k-999", "xyz", "ref=main"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("discovery leaks %q", leak)
		}
	}
	for _, item := range got.Items {
		switch strings.ToLower(item.Path) {
		case "agents.md", ".claude/settings.json":
			t.Fatalf("cursor reported %s, which another adapter owns", item.Path)
		}
	}
}

// TestTerminalsSameNameAndCommandGetDistinctKeys reproduces the
// collision a reviewer found: two terminals with the same name and
// command but a different env.NODE_OPTIONS shared a key, because the key
// only carried the name and command.
func TestTerminalsSameNameAndCommandGetDistinctKeys(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "environment.json"), `{"terminals":[
		{"name":"dev","command":"npm run dev","env":{"NODE_OPTIONS":"--inspect=9229"}},
		{"name":"dev","command":"npm run dev","env":{"NODE_OPTIONS":"--inspect=9230"}}
	]}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".cursor/environment.json", model.ConfigKindEnvSetup)
	var terminals []map[string]any
	for _, item := range items {
		p := kittest.Payload(t, item)
		if p["setting"] == "terminals" {
			terminals = append(terminals, p)
		}
	}
	if len(terminals) != 2 {
		t.Fatalf("terminals = %d, want 2: %+v", len(terminals), items)
	}
	k1, _ := terminals[0]["key"].(string)
	k2, _ := terminals[1]["key"].(string)
	if k1 == k2 {
		t.Fatalf("two terminals with the same name/command but different env share a key: %s", k1)
	}
}

func TestDefaultManagedDir(t *testing.T) {
	t.Parallel()
	cases := []struct {
		goos, programData, dir, logical string
	}{
		{"darwin", "", "/Library/Application Support/Cursor", "/Library/Application Support/Cursor/hooks.json"},
		{"linux", "", "/etc/cursor", "/etc/cursor/hooks.json"},
		{"windows", "", `C:\ProgramData\Cursor`, "C:/programdata/cursor/hooks.json"},
		{"windows", `D:\Data`, `D:\Data\Cursor`, "D:/data/cursor/hooks.json"},
	}
	for _, tc := range cases {
		dir := defaultManagedDir(tc.goos, kittest.Env("ProgramData", tc.programData))
		if dir != tc.dir {
			t.Errorf("%s: dir = %q, want %q", tc.goos, dir, tc.dir)
		}
		item := model.ConfigItem{Harness: model.HarnessCursor, Scope: model.ScopeManaged, Path: kit.ManagedPath(dir) + "/hooks.json", SHA256: strings.Repeat("0", 64), Kind: model.ConfigKindHook, Payload: []byte(`{"key":"[]"}`)}
		if item.Path != tc.logical {
			t.Errorf("%s: logical = %q, want %q", tc.goos, item.Path, tc.logical)
		}
		if err := item.Validate(); err != nil {
			t.Errorf("%s: %v", tc.goos, err)
		}
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
		{"no version", ".cursor/hooks.json", `{"hooks":{"stop":[{"command":"x"}]}}`, "no version", 1},
		{"bad version", ".cursor/hooks.json", `{"version":0,"hooks":{}}`, "not a positive integer", 0},
		{"string version", ".cursor/hooks.json", `{"version":"1","hooks":{}}`, "must be a number", 0},
		{"malformed", ".cursor/hooks.json", `{"version":1,`, "invalid JSON", 0},
		{"bom and comments", ".cursor/mcp.json", "\ufeff{/* c */\"mcpServers\":{\"a\":{\"command\":\"x\"},},}", "", 1},
		{"crlf", ".cursor/hooks.json", "{\r\n\"version\": 1,\r\n\"hooks\": {\"stop\": [{\"command\": \"x\"}]}\r\n}", "", 1},
		{"deep", ".cursor/mcp.json", `{"mcpServers":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`, "nesting", 0},
		{"duplicate event", ".cursor/hooks.json", `{"version":1,"hooks":{"stop":[{"command":"a"}],"stop":[{"command":"b"}]}}`, "duplicate key", 1},
		{"case-variant events", ".cursor/hooks.json", `{"version":1,"hooks":{"stop":[{"command":"a"}],"Stop":[{"command":"b"}]}}`, "case-variant", 2},
		{"case-variant servers key", ".cursor/mcp.json", `{"mcpServers":{},"McpServers":{"a":{"command":"x"}}}`, "case-variant", 0},
		{"hooks not object", ".cursor/hooks.json", `{"version":1,"hooks":[]}`, "must be an object", 0},
		{"terminals not array", ".cursor/environment.json", `{"terminals":{}}`, "terminals must be an array", 0},
		{"rule frontmatter unclosed", ".cursor/rules/a.mdc", "---\nglobs: x\n", "", 1},
		{"rule frontmatter invalid yaml", ".cursor/rules/a.mdc", "---\nglobs: *.ts, [\n---\nbody", "", 1},
		{"oversize", ".cursor/mcp.json", `{"x":"` + strings.Repeat("a", 2<<20) + `"}`, "cannot read", 0},
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
	kittest.WriteFile(t, filepath.Join(outside, "hooks.json"), `{"version":1,"hooks":{"stop":[{"command":"x"}]}}`)
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "rules", "ok.mdc"), "ok")
	if err := os.Symlink(filepath.Join(outside, "hooks.json"), filepath.Join(root, ".cursor", "hooks.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 1 || !got.HasDiag(".cursor/hooks.json: symlink resolves outside the repository; Cursor may load its target") {
		t.Fatalf("got %+v", got)
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".Cursor", "Hooks.JSON"), `{"version":1,"hooks":{"stop":[{"command":"x"}]}}`)
	kittest.WriteFile(t, filepath.Join(root, ".CURSOR", "Rules", "A.MDC"), "x")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".Cursor/Hooks.JSON", model.ConfigKindHook)) != 1 || len(got.Find(".CURSOR/Rules/A.MDC", model.ConfigKindInstructions)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestHookKeysSeparateSecrets(t *testing.T) {
	t.Parallel()
	fingerprint := func(token string) string {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".cursor", "hooks.json"), `{"version":1,"hooks":{"stop":[{"command":"curl https://h.example/?t=`+token+`"}]}}`)
		got := kittest.Discover(t, New(Options{FingerprintKey: kittest.FingerprintKey()}), root)
		if len(got.Items) != 1 {
			t.Fatalf("items = %+v", got.Items)
		}
		return kittest.Fingerprint(t, got.Items[0])
	}
	one, again := fingerprint("one"), fingerprint("one")
	if one == fingerprint("two") {
		t.Fatal("hooks that differ only by a secret share a fingerprint")
	}
	if one != again {
		t.Fatal("fingerprint is not stable")
	}
}

func TestFingerprintsIgnoreMachinePaths(t *testing.T) {
	t.Parallel()
	run := func() []string {
		home := t.TempDir()
		kittest.WriteFile(t, filepath.Join(home, ".cursor", "hooks.json"), `{"version":1,"hooks":{"stop":[{"command":"`+filepath.ToSlash(home)+`/.cursor/hooks/stop.sh"}]}}`)
		got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home}), t.TempDir())
		var out []string
		for _, item := range got.Items {
			if strings.Contains(string(item.Payload), home) {
				t.Fatalf("payload contains the home directory: %s", item.Payload)
			}
			out = append(out, kittest.Fingerprint(t, item))
		}
		return out
	}
	a, b := run(), run()
	if len(a) != 1 || a[0] != b[0] {
		t.Fatalf("fingerprints differ across machines: %v %v", a, b)
	}
}

func TestRepoScanDoesNotReadHome(t *testing.T) {
	t.Parallel()
	home := kittest.CopyTree(t, filepath.Join("testdata", "home"))
	got := kittest.Discover(t, New(Options{HomeDir: home, ManagedDir: home}), t.TempDir())
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
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "environment.json"), "{}")
	if !New(Options{}).Detect(root) {
		t.Fatal("Detect missed .cursor/environment.json")
	}
}

func FuzzParseConfig(f *testing.F) {
	seeds := map[string]string{
		"hooks":       "testdata/repo/.cursor/hooks.json",
		"mcp":         "testdata/repo/.cursor/mcp.json",
		"environment": "testdata/repo/.cursor/environment.json",
		"rule":        "testdata/repo/.cursor/rules/frontend/react.mdc",
	}
	for kind, path := range seeds {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(kind, data)
		}
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.HarnessCursor, product)
		for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeUser} {
			path := ".cursor/x.json"
			if scope == model.ScopeUser {
				path = "~/.cursor/x.json"
			}
			f := &file{Source: c.Source(scope, path, data)}
			switch kind {
			case "hooks":
				f.hooksFile(data)
			case "mcp":
				f.mcpFile(data)
			case "environment":
				f.environment(data)
			default:
				f.Markdown(model.ConfigKindInstructions, "rule", data, kit.LooseFrontmatter)
			}
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}

// TestEnvironmentDetectView checks that rules see environment.json
// commands as written, while the payload stays sanitized.
func TestEnvironmentDetectView(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "environment.json"), `{
		"install": "curl -fsSL 'https://e.example.invalid/i.sh?token=cu-raw-777' | sh",
		"terminals": [{"name": "dev", "command": "curl 'https://e.example.invalid/t.sh?token=cu-raw-777' | sh"}]
	}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".cursor/environment.json", model.ConfigKindEnvSetup)
	if len(items) != 2 {
		t.Fatalf("items = %+v", items)
	}
	for _, item := range items {
		if strings.Contains(string(item.Payload), "cu-raw-777") {
			t.Fatalf("payload leaks the token: %s", item.Payload)
		}
		if !strings.Contains(string(item.Detect), "cu-raw-777") {
			t.Fatalf("detect view lost the raw text: %s", item.Detect)
		}
	}
}

func TestEnvironmentStart(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const command = "sudo service docker start"
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "environment.json"), `{"start":"`+command+`"}`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
	items := got.Find(".cursor/environment.json", model.ConfigKindEnvSetup)
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	payload := kittest.Payload(t, items[0])
	if payload["setting"] != "start" || payload["value"] != command {
		t.Fatalf("payload = %#v", payload)
	}
	key, _ := payload["key"].(string)
	if !strings.Contains(key, `"setting"`) || !strings.Contains(key, `"start"`) {
		t.Fatalf("key = %s", key)
	}
	if !strings.Contains(string(items[0].Detect), command) {
		t.Fatalf("detect view = %s", items[0].Detect)
	}

	root = t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "environment.json"), `{"start":["sudo","service","docker","start"]}`)
	got = kittest.Discover(t, New(Options{}), root)
	if !got.HasDiag("start must be a string") {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
	items = got.Find(".cursor/environment.json", model.ConfigKindEnvSetup)
	if len(items) != 1 || kittest.Payload(t, items[0])["setting"] != "start" {
		t.Fatalf("non-string start = %+v", items)
	}
}

func TestEnvironmentCommandTypes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".cursor", "environment.json"), `{"install": ["npm", "ci"], "terminals": [{"name": "dev", "command": 1}]}`)
	got := kittest.Discover(t, New(Options{}), root)
	if !got.HasDiag("install must be a string") || !got.HasDiag("terminals command must be a string") {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
}
