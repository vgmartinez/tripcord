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

func TestUserSkillsScanned(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "skills", "deploy", "SKILL.md"), "---\nname: deploy\n---\nbody\n")
	root := t.TempDir()
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), root)
	items := got.Find("~/.codex/skills/deploy/SKILL.md", model.ConfigKindSkill)
	if len(items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	if items[0].Harness != model.HarnessCodex || items[0].Scope != model.ScopeUser {
		t.Fatalf("item = %+v", items[0])
	}
}

func TestUserSkillsNotScannedWithoutIncludeUser(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "skills", "deploy", "SKILL.md"), "---\nname: deploy\n---\n")
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	got := kittest.Discover(t, New(Options{HomeDir: home, Getenv: kittest.Env()}), root)
	if len(got.Find("~/.codex/skills/deploy/SKILL.md", model.ConfigKindSkill)) != 0 {
		t.Fatalf("items = %+v, want no user-scope skill without IncludeUser", got.Items)
	}
}

func TestUserSkillsFollowCodexHomeOverride(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	alt := t.TempDir()
	kittest.WriteFile(t, filepath.Join(alt, "skills", "deploy", "SKILL.md"), "---\nname: deploy\n---\n")
	root := t.TempDir()
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env("CODEX_HOME", alt)}), root)
	if len(got.Find("~/CODEX_HOME/skills/deploy/SKILL.md", model.ConfigKindSkill)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

// TestProjectTrustExtendsToSubfolders is Follow-up 5: Codex extends a
// trusted project's trust to its subfolders, so scanning
// <repo>/sub/dir finds the repo's own trust entry by walking up, not
// just an exact match on the scanned root.
func TestProjectTrustExtendsToSubfolders(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub", "dir")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	kittest.WriteFile(t, filepath.Join(sub, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), userConfig(repo))
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), sub)
	items := got.Find(".codex/config.toml", model.ConfigKindPermissions)
	if len(items) != 1 || kittest.Payload(t, items[0])["project_trust"] != trustTrusted {
		t.Fatalf("items = %+v, want the subfolder to inherit the repo's trust", got.Items)
	}
}

// TestProjectTrustMostSpecificAncestorWins pins the tie-break when both
// a repo and one of its subfolders have their own project_trust entry:
// the more specific (longer) path wins over the shorter ancestor.
func TestProjectTrustMostSpecificAncestorWins(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	tree := "[projects.\"" + filepath.ToSlash(repo) + "\"]\ntrust_level = \"trusted\"\n" +
		"[projects.\"" + filepath.ToSlash(sub) + "\"]\ntrust_level = \"untrusted\"\n"
	kittest.WriteFile(t, filepath.Join(sub, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), tree)
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), sub)
	items := got.Find(".codex/config.toml", model.ConfigKindPermissions)
	if len(items) != 1 || kittest.Payload(t, items[0])["project_trust"] != trustUntrusted {
		t.Fatalf("items = %+v, want the more specific (sub) entry to win", got.Items)
	}
}

// TestProjectTrustDoesNotExtendToSiblingWithSharedPrefix guards the
// string-prefix pitfall: "/repo-untrusted" must not match the ancestor
// entry for "/repo" just because the directory name shares a prefix.
func TestProjectTrustDoesNotExtendToSiblingWithSharedPrefix(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	sibling := filepath.Join(parent, "repo-sibling")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	kittest.WriteFile(t, filepath.Join(sibling, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), userConfig(repo))
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), sibling)
	items := got.Find(".codex/config.toml", model.ConfigKindPermissions)
	if len(items) != 1 || kittest.Payload(t, items[0])["project_trust"] != trustUnset {
		t.Fatalf("items = %+v, want no trust inherited from a sibling with a shared name prefix", got.Items)
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

// TestProjectIgnoredKeysAreAllEmitted guards the gap docs/adapters/codex.md
// documents and projectIgnored's own comment warns about: a key listed in
// projectIgnored but missing from settingKinds is silently dropped by the
// main config loop instead of being reported with ignored_in_project.
func TestProjectIgnoredKeysAreAllEmitted(t *testing.T) {
	t.Parallel()
	for name := range projectIgnored {
		if _, ok := settingKinds[name]; !ok && name != "profiles" {
			t.Errorf("%q is in projectIgnored but not settingKinds (and is not the profiles table, which has its own code path), so it is never emitted", name)
		}
	}
}

// TestInstructionsFileRedirectIsReported covers the real repo vector a
// trusted project's own config.toml can use: redirecting the file Codex
// loads as model instructions instead of AGENTS.md. Unlike
// projectIgnored's keys, Codex does honor these from a project config, so
// they must be reported as effective, not ignored_in_project.
func TestInstructionsFileRedirectIsReported(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"),
		"model_instructions_file = \"/etc/passwd\"\n"+
			"experimental_instructions_file = \"/etc/shadow\"\n"+
			"project_doc_fallback_filenames = [\"README.md\"]\n")
	got := kittest.Discover(t, New(Options{}), root)
	found := map[string]any{}
	for _, item := range got.Items {
		if item.Kind != model.ConfigKindInstructions {
			continue
		}
		p := kittest.Payload(t, item)
		found[p["setting"].(string)] = p["value"]
	}
	if found["model_instructions_file"] != "/etc/passwd" || found["experimental_instructions_file"] != "/etc/shadow" {
		t.Fatalf("instructions file settings = %+v", found)
	}
	if _, ok := found["project_doc_fallback_filenames"]; !ok {
		t.Fatalf("project_doc_fallback_filenames not reported: %+v", found)
	}
	for _, item := range got.Items {
		if p := kittest.Payload(t, item); p["setting"] == "model_instructions_file" {
			if p["ignored_in_project"] != nil {
				t.Fatalf("model_instructions_file must not be marked ignored_in_project: %+v", p)
			}
		}
	}
}

// TestMCPServerArgsRedactsBearerScheme is the Codex repro: an MCP
// server's args array splits a bearer token across two elements,
// ["Bearer", "<token>"], so Sanitize's bearerToken regex (which needs
// "Bearer <token>" in one string) never sees it.
func TestMCPServerArgsRedactsBearerScheme(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"),
		"[mcp_servers.remote]\ncommand = \"npx\"\nargs = [\"mcp-remote\", \"--header\", \"Authorization\", \"Bearer\", \"sk-live-secret-token\"]\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/config.toml", model.ConfigKindMCPServer)
	if len(items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	raw := string(items[0].Payload)
	if strings.Contains(raw, "sk-live-secret-token") {
		t.Fatalf("payload leaks the bearer token: %s", raw)
	}
	for _, kept := range []string{"mcp-remote", "--header", "Authorization", "Bearer"} {
		if !strings.Contains(raw, kept) {
			t.Fatalf("payload dropped non-secret arg %q: %s", kept, raw)
		}
	}
}

// TestMCPServerArgsRedactsToolSpecificFlag is the Codex repro for
// output.RedactToolArgv: "docker login -p X" is a credential only
// because the command is docker's login subcommand, which SafeValue's
// generic secret-flag scan does not know (a bare "-p" is not in
// output.SecretFlags, since it means something unrelated for most
// commands, such as "publish a port" for docker run).
func TestMCPServerArgsRedactsToolSpecificFlag(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"),
		"[mcp_servers.registry]\ncommand = \"docker\"\nargs = [\"login\", \"-u\", \"alice\", \"-p\", \"sk-live-secret-token\", \"registry.example\"]\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/config.toml", model.ConfigKindMCPServer)
	if len(items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	raw := string(items[0].Payload)
	if strings.Contains(raw, "sk-live-secret-token") {
		t.Fatalf("payload leaks the docker login password: %s", raw)
	}
	for _, kept := range []string{"login", "alice", "registry.example"} {
		if !strings.Contains(raw, kept) {
			t.Fatalf("payload dropped non-secret arg %q: %s", kept, raw)
		}
	}
}

// TestRulesFileNormalized is the discovery-level counterpart of
// rules_parse_test.go: a project .rules file with two prefix_rule calls
// is normalized into two permissions items, each carrying project_trust
// like hooksFile and config do.
func TestRulesFileNormalized(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		"prefix_rule(pattern = [\"git\", \"add\"], decision = \"allow\")\n"+
			"prefix_rule(pattern = [\"rm\", \"-rf\"], decision = \"forbidden\", justification = \"destructive\")\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 2 {
		t.Fatalf("items = %+v, want 2", got.Items)
	}
	byDecision := map[string]map[string]any{}
	for _, item := range items {
		p := kittest.Payload(t, item)
		byDecision[p["decision"].(string)] = p
	}
	allow, ok := byDecision["allow"]
	if !ok || allow["role"] != "rule" || allow["project_trust"] != trustUnknown {
		t.Fatalf("allow rule = %+v", allow)
	}
	forbidden, ok := byDecision["forbidden"]
	if !ok || forbidden["justification"] != "destructive" {
		t.Fatalf("forbidden rule = %+v", forbidden)
	}
}

// TestRulesFileDecisionDefaultsToAllow mirrors Codex's own documented
// default: a prefix_rule with no decision kwarg allows the command.
func TestRulesFileDecisionDefaultsToAllow(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"), "prefix_rule(pattern = [\"npm\", \"test\"])\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 1 || kittest.Payload(t, items[0])["decision"] != "allow" {
		t.Fatalf("items = %+v", got.Items)
	}
}

// TestRulesFileOpaqueOnUnknownConstruct is the conservative fallback: a
// construct rules_parse.go does not model makes the whole file opaque
// instead of silently dropping the rule or guessing at its meaning, and
// the diagnostic is blocking, since the unparsed part may hold an allow
// rule.
func TestRulesFileOpaqueOnUnknownConstruct(t *testing.T) {
	t.Parallel()
	for name, extra := range map[string]string{
		"unknown call":       "exec_rule(pattern = [\"git\"])\n",
		"uppercase decision": "prefix_rule(pattern = [\"rm\"], decision = \"ALLOW\")\n",
	} {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
			"prefix_rule(pattern = [\"git\", \"add\"], decision = \"allow\")\n"+extra)
		a := New(Options{})
		got := kittest.Discover(t, a, root)
		items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
		if len(items) != 1 {
			t.Fatalf("%s: items = %+v, want one opaque item", name, got.Items)
		}
		p := kittest.Payload(t, items[0])
		if p["role"] != "rules-file" || p["parsed"] != false {
			t.Fatalf("%s: payload = %+v", name, p)
		}
		if !strings.Contains(p["content"].(string), strings.TrimSpace(extra)) {
			t.Fatalf("%s: opaque content dropped the file body: %+v", name, p)
		}
		if !kittest.Blocking(t, a, root, "does not parse conservatively") {
			t.Fatalf("%s: opaque rules file is not a blocking diagnostic: %v", name, got.Diagnostics)
		}
	}
}

func TestRulesFileHostExecutable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		"host_executable(name = \"git\", paths = [\"/usr/bin/git\", \"/opt/homebrew/bin/git\"])\n"+
			"prefix_rule(pattern = [\"git\", \"status\"])\n")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
	var host map[string]any
	for _, item := range got.Find(".codex/rules/default.rules", model.ConfigKindPermissions) {
		if p := kittest.Payload(t, item); p["role"] == "host-executable" {
			host = p
		}
	}
	if host == nil || host["name"] != "git" {
		t.Fatalf("no host-executable item: %+v", got.Items)
	}
	paths, _ := host["paths"].([]any)
	if len(paths) != 2 || paths[0] != "/usr/bin/git" || host["project_trust"] != trustUnknown {
		t.Fatalf("host-executable payload = %+v", host)
	}
}

// TestRulesFileRedactsSecretsInOpaqueFallback guards the opaque path
// against the same leak the parsed path is tested for in the discover
// golden: a secret in a file this parser cannot model must still be
// redacted, not reported verbatim just because parsing gave up.
func TestRulesFileRedactsSecretsInOpaqueFallback(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"),
		"prefix_rule(pattern = [\"env\", \"PGPASSWORD=sk-live-secret-token\", \"psql\"]) + unknown\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 1 {
		t.Fatalf("items = %+v, want one opaque item", got.Items)
	}
	raw := string(items[0].Payload)
	if strings.Contains(raw, "sk-live-secret-token") {
		t.Fatalf("opaque fallback leaks a secret: %s", raw)
	}
}

// TestUserRulesScanned is the ~/.codex/rules/*.rules counterpart of
// TestUserSkillsScanned: Codex's always-active global rules layer, not
// gated by project trust.
func TestUserRulesScanned(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "rules", "default.rules"), "prefix_rule(pattern = [\"npm\", \"test\"], decision = \"allow\")\n")
	root := t.TempDir()
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), root)
	items := got.Find("~/.codex/rules/default.rules", model.ConfigKindPermissions)
	if len(items) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
	if items[0].Harness != model.HarnessCodex || items[0].Scope != model.ScopeUser {
		t.Fatalf("item = %+v", items[0])
	}
}

func TestUserRulesNotScannedWithoutIncludeUser(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "rules", "default.rules"), "prefix_rule(pattern = [\"npm\", \"test\"])\n")
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
	got := kittest.Discover(t, New(Options{HomeDir: home, Getenv: kittest.Env()}), root)
	if len(got.Find("~/.codex/rules/default.rules", model.ConfigKindPermissions)) != 0 {
		t.Fatalf("items = %+v, want no user-scope rules without IncludeUser", got.Items)
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

// TestHooksSameCommandDifferentCommandWindowsGetDistinctKeys reproduces
// the collision a reviewer found: two hooks with the same primary action
// field ("command") but a different "commandWindows" shared a key,
// because the key only carries the first present action field.
func TestHooksSameCommandDifferentCommandWindowsGetDistinctKeys(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".codex", "hooks.json"), `{"hooks":{"Stop":[
		{"hooks":[{"type":"command","command":"./stop.sh","commandWindows":"stop1.bat"}]},
		{"hooks":[{"type":"command","command":"./stop.sh","commandWindows":"stop2.bat"}]}
	]}}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".codex/hooks.json", model.ConfigKindHook)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2: %+v", len(items), items)
	}
	k1, _ := kittest.Payload(t, items[0])["key"].(string)
	k2, _ := kittest.Payload(t, items[1])["key"].(string)
	if k1 == k2 {
		t.Fatalf("two hooks with the same command but different commandWindows share a key: %s", k1)
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
		if data, err := kittest.ReadFixture(path); err == nil {
			f.Add("config", data)
		}
	}
	if data, err := kittest.ReadFixture("testdata/repo/.codex/hooks.json"); err == nil {
		f.Add("hooks", data)
	}
	for _, path := range []string{"testdata/repo/.codex/rules/default.rules", "testdata/home/.codex/rules/default.rules"} {
		if data, err := kittest.ReadFixture(path); err == nil {
			f.Add("rules", data)
		}
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.HarnessCodex, product)
		for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeUser} {
			path := ".codex/config.toml"
			if scope == model.ScopeUser {
				path = "~/.codex/config.toml"
			}
			f := &file{Source: c.Source(scope, path, data)}
			switch kind {
			case "hooks":
				f.hooksFile(data)
			case "rules":
				f.rulesFile(data)
			default:
				f.config(data)
			}
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}

// Several keys can name the same directory. The result must not depend
// on Go's map order: a key already in canonical form wins, and between
// non-canonical spellings, untrusted wins.
func TestProjectTrustTieBreakIsDeterministic(t *testing.T) {
	t.Parallel()
	repo := canonical(t.TempDir())
	link := filepath.Join(canonical(t.TempDir()), "link")
	if err := os.Symlink(repo, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	entry := func(level string) map[string]any { return map[string]any{"trust_level": level} }
	cases := []struct {
		name     string
		projects map[string]any
		want     string
	}{
		{"exact key beats trailing slash", map[string]any{repo: entry("trusted"), repo + "/": entry("untrusted")}, trustTrusted},
		{"exact key beats dot segment", map[string]any{repo: entry("untrusted"), repo + "/.": entry("trusted")}, trustUntrusted},
		{"exact key beats symlink", map[string]any{repo: entry("trusted"), link: entry("untrusted")}, trustTrusted},
		{"untrusted wins between spellings", map[string]any{repo + "/": entry("trusted"), repo + "/.": entry("untrusted")}, trustUntrusted},
		{"untrusted wins against symlink", map[string]any{link: entry("trusted"), repo + "/": entry("untrusted")}, trustUntrusted},
	}
	for _, tc := range cases {
		tree := map[string]any{"projects": tc.projects}
		for i := 0; i < 200; i++ {
			if got := projectTrust(tree, repo); got != tc.want {
				t.Fatalf("%s: run %d: trust = %s, want %s", tc.name, i, got, tc.want)
			}
		}
	}
}

func TestProjectTrustAcceptsOnlyCanonicalLevels(t *testing.T) {
	t.Parallel()
	repo := canonical(t.TempDir())
	for _, level := range []string{"Trusted", "TRUSTED", "trusted ", "Untrusted"} {
		tree := map[string]any{"projects": map[string]any{repo: map[string]any{"trust_level": level}}}
		if got := projectTrust(tree, repo); got != trustUnset {
			t.Errorf("trust_level %q: trust = %s, want %s", level, got, trustUnset)
		}
	}
}

// A nested .codex directory takes the trust of the directory holding it,
// so a subfolder the user marked untrusted is not reported as trusted
// just because the repository root is.
func TestNestedCodexUsesItsOwnProjectTrust(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	sub := filepath.Join(repo, "sub")
	other := filepath.Join(repo, "other")
	tree := "[projects.\"" + filepath.ToSlash(repo) + "\"]\ntrust_level = \"trusted\"\n" +
		"[projects.\"" + filepath.ToSlash(sub) + "\"]\ntrust_level = \"untrusted\"\n"
	for _, dir := range []string{repo, sub, other} {
		kittest.WriteFile(t, filepath.Join(dir, ".codex", "config.toml"), "sandbox_mode = \"danger-full-access\"\n")
		kittest.WriteFile(t, filepath.Join(dir, ".codex", "hooks.json"), `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"./stop.sh"}]}]}}`)
		kittest.WriteFile(t, filepath.Join(dir, ".codex", "rules", "a.rules"), `prefix_rule(pattern=["ls"], decision="allow")`)
	}
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), tree)
	got := kittest.Discover(t, New(Options{IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), repo)
	want := map[string]string{"": trustTrusted, "sub/": trustUntrusted, "other/": trustTrusted}
	for prefix, trust := range want {
		for _, name := range []string{".codex/config.toml", ".codex/hooks.json", ".codex/rules/a.rules"} {
			var found bool
			for _, item := range got.Items {
				if item.Path != prefix+name {
					continue
				}
				found = true
				if got := kittest.Payload(t, item)["project_trust"]; got != trust {
					t.Errorf("%s%s: project_trust = %v, want %s", prefix, name, got, trust)
				}
			}
			if !found {
				t.Errorf("no item for %s%s", prefix, name)
			}
		}
	}
}

func TestCodexProjectDir(t *testing.T) {
	t.Parallel()
	for rel, want := range map[string]string{
		".codex/config.toml":          "",
		"a/b/.codex/hooks.json":       "a/b",
		"a/.codex/rules/x.rules":      "a",
		".codex/x/.codex/config.toml": ".codex/x",
	} {
		if got := codexProjectDir(rel); got != want {
			t.Errorf("codexProjectDir(%q) = %q, want %q", rel, got, want)
		}
	}
}
