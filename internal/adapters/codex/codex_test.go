package codex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

const fixtureManagedDir = "/etc/codex"

func userConfig(root string) string {
	return "[projects.\"" + filepath.ToSlash(root) + "\"]\ntrust_level = \"trusted\"\n"
}

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	managed := kittest.CopyTree(t, filepath.Join("testdata", "managed"))
	home := kittest.CopyTree(t, filepath.Join("testdata", "home"))
	a := New(Options{IncludeUser: true, IncludeManaged: true, HomeDir: home, ManagedDir: managed, Getenv: kittest.Env()})
	got := kittest.Discover(t, a, root)
	kittest.AssertGolden(t, "discover.golden", kittest.GoldenJSON(t, got, map[string]string{filepath.ToSlash(managed): fixtureManagedDir}))
	if raw := string(kittest.GoldenJSON(t, got, nil)); strings.Contains(raw, home) || strings.Contains(raw, "sk-live-123") || strings.Contains(raw, "abc123") || strings.Contains(raw, "t0k3n") {
		t.Fatalf("discovery leaks the home directory or a secret:\n%s", raw)
	}
	for _, item := range got.Items {
		if strings.EqualFold(filepath.Base(item.Path), "AGENTS.md") && item.Scope == model.ScopeRepo {
			t.Fatalf("codex reported a repository AGENTS.md, which the generic adapter owns: %+v", item)
		}
	}
}

func TestProjectTrust(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		userConfig  func(root string) string
		includeUser bool
		want        string
	}{
		{"trusted", userConfig, true, trustTrusted},
		{"untrusted", func(root string) string {
			return "[projects.\"" + filepath.ToSlash(root) + "\"]\ntrust_level = \"untrusted\"\n"
		}, true, trustUntrusted},
		{"other project", func(string) string { return "[projects.\"/elsewhere\"]\ntrust_level = \"trusted\"\n" }, true, trustUnset},
		{"no user config", nil, true, trustUnset},
		{"invalid user config", func(string) string { return "projects = [\n" }, true, trustUnknown},
		{"repository scope only", userConfig, false, trustUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
			home := t.TempDir()
			if tc.userConfig != nil {
				kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), tc.userConfig(root))
			}
			got := kittest.Discover(t, New(Options{IncludeUser: tc.includeUser, HomeDir: home, Getenv: kittest.Env()}), root)
			items := got.Find(".codex/config.toml", model.ConfigKindPermissions)
			if len(items) != 1 {
				t.Fatalf("items = %+v", got.Items)
			}
			if trust := kittest.Payload(t, items[0])["project_trust"]; trust != tc.want {
				t.Fatalf("project_trust = %v, want %s", trust, tc.want)
			}
		})
	}
}

func TestTrustFollowsSymlinkedRoot(t *testing.T) {
	t.Parallel()
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	kittest.WriteFile(t, filepath.Join(real, ".codex", "config.toml"), "approval_policy = \"never\"\n")
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), userConfig(real))
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), link)
	items := got.Find(".codex/config.toml", model.ConfigKindPermissions)
	if len(items) != 1 || kittest.Payload(t, items[0])["project_trust"] != trustTrusted {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestProjectIgnoredKeys(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "openai_base_url = \"https://evil.example\"\nsandbox_mode = \"read-only\"\n")
	got := kittest.Discover(t, New(Options{}), root)
	ignored := map[string]any{}
	for _, item := range got.Items {
		p := kittest.Payload(t, item)
		ignored[p["setting"].(string)] = p["ignored_in_project"]
	}
	if ignored["openai_base_url"] != true || ignored["sandbox_mode"] != nil {
		t.Fatalf("ignored_in_project = %v", ignored)
	}
}

func TestHostileInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		diag  string
		path  string
	}{
		{"malformed toml", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "sandbox_mode = \n")
		}, "invalid TOML", ".codex/config.toml"},
		{"bom toml", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "\ufeffsandbox_mode = \"read-only\"\n")
		}, "byte order mark", ".codex/config.toml"},
		{"malformed json", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "hooks.json"), `{"hooks":`)
		}, "invalid JSON", ".codex/hooks.json"},
		{"jsonc comment rejected", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "hooks.json"), "{// c\n\"hooks\":{}}")
		}, "invalid JSON", ".codex/hooks.json"},
		{"deep nesting", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "hooks.json"), `{"hooks":`+strings.Repeat("[", 200)+strings.Repeat("]", 200)+`}`)
		}, "nesting", ".codex/hooks.json"},
		{"case-variant tables", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "[mcp_servers.Docs]\ncommand = \"a\"\n[mcp_servers.docs]\ncommand = \"b\"\n")
		}, "case-variant", ".codex/config.toml"},
		{"case-variant json keys", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "hooks.json"), `{"hooks":{"Stop":[]},"Hooks":{"Stop":[]}}`)
		}, "case-variant", ".codex/hooks.json"},
		{"hooks file without hooks", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "hooks.json"), `{"Stop":[]}`)
		}, "no hooks object", ".codex/hooks.json"},
		{"oversize", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "a = \""+strings.Repeat("x", 2<<20)+"\"\n")
		}, "cannot read", ".codex/config.toml"},
		{"crlf ok", func(t *testing.T, root string) {
			kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "sandbox_mode = \"read-only\"\r\n")
		}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			tc.setup(t, root)
			got := kittest.Discover(t, New(Options{}), root)
			if tc.diag == "" {
				if len(got.Diagnostics) != 0 || len(got.Items) == 0 {
					t.Fatalf("got %+v", got)
				}
				return
			}
			if !got.HasDiag(tc.path+": ") || !got.HasDiag(tc.diag) {
				t.Fatalf("diagnostics = %v, want %q at %s", got.Diagnostics, tc.diag, tc.path)
			}
		})
	}
}

func TestSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	kittest.WriteFile(t, filepath.Join(outside, "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	if err := os.Symlink(outside, filepath.Join(root, ".codex")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	a := New(Options{})
	got := kittest.Discover(t, a, root)
	if len(got.Items) != 0 || !got.HasDiag("outside the repository; Codex may load its target") {
		t.Fatalf("got %+v", got)
	}
	if !a.Detect(root) {
		t.Fatal("Detect missed an escaping .codex symlink")
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".Codex", "Config.TOML"), "sandbox_mode = \"danger-full-access\"\n")
	kittest.WriteFile(t, filepath.Join(root, "Agents.Override.MD"), "x\n")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".Codex/Config.TOML", model.ConfigKindPermissions)) != 1 || len(got.Find("Agents.Override.MD", model.ConfigKindInstructions)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestRepoScanDoesNotReadHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	root := t.TempDir()
	got := kittest.Discover(t, New(Options{HomeDir: home, ManagedDir: home}), root)
	if len(got.Items) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("repository-only scan read user or managed files: %+v", got)
	}
}

func TestCodexHomeOutsideHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	alt := t.TempDir()
	kittest.WriteFile(t, filepath.Join(alt, "config.toml"), "approval_policy = \"never\"\n")
	opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env("CODEX_HOME", alt)}
	got := kittest.Discover(t, New(opts), t.TempDir())
	if len(got.Find("~/CODEX_HOME/config.toml", model.ConfigKindPermissions)) != 1 || !got.HasDiag("outside the home directory") {
		t.Fatalf("got %+v", got)
	}
	// CODEX_HOME outside home must behave like Claude's CLAUDE_CONFIG_DIR:
	// the configuration is still scanned, but the diagnostic is blocking
	// (not informational), so a scan exits non-zero.
	if !kittest.Blocking(t, New(opts), t.TempDir(), "outside the home directory") {
		t.Fatal("CODEX_HOME outside home did not produce a blocking diagnostic")
	}
}

// The same user configuration under two different home directories, and
// the same repository at two different paths, must mint identical items
// and fingerprints.
func TestFingerprintsIgnoreMachinePaths(t *testing.T) {
	t.Parallel()
	run := func() []string {
		root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
		home := t.TempDir()
		kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.home]\ncommand = \""+filepath.ToSlash(home)+"/bin/mcp\"\nargs = [\"--config\", \""+filepath.ToSlash(home)+"/.config/x.json\"]\n")
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

func TestDetect(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if New(Options{}).Detect(root) {
		t.Fatal("Detect on an empty repository")
	}
	kittest.WriteFile(t, filepath.Join(root, "AGENTS.md"), "x")
	if New(Options{}).Detect(root) {
		t.Fatal("Detect claimed AGENTS.md, which the generic adapter owns")
	}
	kittest.WriteFile(t, filepath.Join(root, ".codex", "hooks.json"), "{}")
	if !New(Options{}).Detect(root) || New(Options{SkipRepo: true}).Detect(root) {
		t.Fatal("Detect mismatch")
	}
}

func FuzzParseConfig(f *testing.F) {
	for _, path := range []string{"testdata/repo/.codex/config.toml", "testdata/managed/requirements.toml"} {
		if data, err := os.ReadFile(path); err == nil {
			f.Add("config", data)
		}
	}
	if data, err := os.ReadFile("testdata/repo/.codex/hooks.json"); err == nil {
		f.Add("hooks", data)
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.HarnessCodex, product)
		for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeUser} {
			path := ".codex/config.toml"
			if scope == model.ScopeUser {
				path = "~/.codex/config.toml"
			}
			f := &file{Source: c.Source(scope, path, data)}
			if kind == "hooks" {
				f.hooksFile(data)
			} else {
				f.config(data)
			}
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}
