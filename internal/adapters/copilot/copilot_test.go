package copilot

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

const fixturePolicyDir = "/etc/github-copilot/policy.d"

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	home := kittest.CopyTree(t, filepath.Join("testdata", "home"))
	policy := kittest.CopyTree(t, filepath.Join("testdata", "policy"))
	got := kittest.Discover(t, New(Options{IncludeUser: true, IncludeManaged: true, HomeDir: home, PolicyDir: policy, Getenv: kittest.Env()}), root)
	kittest.AssertGolden(t, "discover.golden", kittest.GoldenJSON(t, got, map[string]string{filepath.ToSlash(policy): fixturePolicyDir}))
	raw := string(kittest.GoldenJSON(t, got, nil))
	for _, leak := range []string{home, "s3cr3t", "Bearer abc", "tok-1", "ghp_example", "channel=beta"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("discovery leaks %q", leak)
		}
	}
	for _, item := range got.Items {
		switch {
		case strings.EqualFold(item.Path, "AGENTS.md"), item.Path == ".mcp.json":
			t.Fatalf("copilot reported %s, which another adapter owns", item.Path)
		case strings.HasPrefix(item.Path, "services/"):
			t.Fatalf("copilot reported a nested .github file Copilot does not load: %s", item.Path)
		}
	}
}

func TestDisableAllHooksMarksHooks(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	got := kittest.Discover(t, New(Options{}), root)
	hooks := got.Find(".github/hooks/disabled.json", model.ConfigKindHook)
	if len(hooks) != 1 || kittest.Payload(t, hooks[0])["hooks_disabled"] != true {
		t.Fatalf("hooks = %+v", hooks)
	}
	for _, item := range got.Find(".github/hooks/guard.json", model.ConfigKindHook) {
		if _, ok := kittest.Payload(t, item)["hooks_disabled"]; ok {
			t.Fatalf("an enabled file was marked disabled: %s", item.Payload)
		}
	}
}

func TestSetupStepsJobOnly(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	got := kittest.Discover(t, New(Options{}), root)
	var steps, jobs int
	for _, item := range got.Find(".github/workflows/copilot-setup-steps.yml", model.ConfigKindEnvSetup) {
		p := kittest.Payload(t, item)
		switch p["setting"] {
		case "step":
			steps++
			if strings.Contains(string(item.Payload), "not copilot") {
				t.Fatalf("emitted a step of another job: %s", item.Payload)
			}
		case "job":
			jobs++
			if env, _ := p["env"].(map[string]any); env["NPM_TOKEN"] != kit.Redacted {
				t.Fatalf("job env not redacted: %s", item.Payload)
			}
		}
	}
	if steps != 3 || jobs != 1 {
		t.Fatalf("steps = %d jobs = %d", steps, jobs)
	}

	missing := t.TempDir()
	kittest.WriteFile(t, filepath.Join(missing, ".github", "workflows", "copilot-setup-steps.yml"), "on: push\njobs:\n  build:\n    runs-on: x\n")
	d := kittest.Discover(t, New(Options{}), missing)
	if !d.HasDiag("no copilot-setup-steps job") {
		t.Fatalf("diagnostics = %v", d.Diagnostics)
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
		{"no version", ".github/hooks/a.json", `{"hooks":{"sessionStart":[{"bash":"x"}]}}`, "no version", 1},
		{"version 2", ".github/hooks/a.json", `{"version":2,"hooks":{}}`, "not 1", 0},
		{"malformed", ".github/hooks/a.json", `{"version":1,"hooks":{`, "invalid JSON", 0},
		{"jsonc rejected", ".github/hooks/a.json", "{\"version\":1, // c\n\"hooks\":{}}", "invalid JSON", 0},
		{"bom rejected", ".github/copilot/settings.json", "\ufeff{}", "byte order mark", 0},
		{"crlf", ".github/hooks/a.json", "{\r\n\"version\": 1,\r\n\"hooks\": {\"sessionStart\": [{\"bash\": \"x\"}]}\r\n}", "", 1},
		{"deep", ".github/hooks/a.json", `{"version":1,"hooks":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`, "nesting", 0},
		{"event aliases both load", ".github/hooks/a.json", `{"version":1,"hooks":{"sessionStart":[{"bash":"a"}],"SessionStart":[{"bash":"b"}]}}`, "", 2},
		{"case-variant top-level keys", ".github/hooks/a.json", `{"version":1,"hooks":{},"Hooks":{"sessionStart":[{"bash":"a"}]}}`, "case-variant", 0},
		{"duplicate event", ".github/hooks/a.json", `{"version":1,"hooks":{"sessionStart":[{"bash":"a"}],"sessionStart":[{"bash":"b"}]}}`, "duplicate key", 1},
		{"agent bad frontmatter", ".github/agents/a.agent.md", "---\nhooks: [\n---\nbody", "invalid frontmatter", 1},
		{"agent unclosed frontmatter", ".github/agents/a.agent.md", "---\nhooks: {}\n", "no closing", 1},
		{"agent yaml alias", ".github/agents/a.agent.md", "---\na: &x 1\nb: *x\n---\n", "aliases", 1},
		{"instructions loose frontmatter", ".github/instructions/a.instructions.md", "---\napplyTo: **/*.go, [\n---\nbody", "", 1},
		{"workflow malformed", ".github/workflows/copilot-setup-steps.yml", "jobs: [\n", "invalid YAML", 0},
		{"workflow steps not sequence", ".github/workflows/copilot-setup-steps.yml", "jobs:\n  copilot-setup-steps:\n    steps: {}\n", "must be a sequence", 2},
		{"oversize", ".github/hooks/a.json", `{"x":"` + strings.Repeat("a", 2<<20) + `"}`, "cannot read", 0},
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

// TestSetupStepsAliasesExpand checks that copilot-setup-steps.yml, unlike
// generic frontmatter, follows YAML anchors and aliases: GitHub Actions
// supports them, and rejecting a workflow that uses one would break
// legitimate CI.
// TestDistinctStepsGetDistinctKeys reproduces the collision a reviewer
// found: two unnamed `uses: actions/github-script@v7` steps with
// different `with.script` previously shared a key (and so a fingerprint)
// because the key only carried "uses", not "with". A benign step could
// then hide a hostile one in a tool that merges findings by fingerprint.
func TestDistinctStepsGetDistinctKeys(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".github", "workflows", "copilot-setup-steps.yml"), `on: push
jobs:
  copilot-setup-steps:
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("one")
      - uses: actions/github-script@v7
        with:
          script: console.log("two")
`)
	got := kittest.Discover(t, New(Options{}), root)
	steps := got.Find(".github/workflows/copilot-setup-steps.yml", model.ConfigKindEnvSetup)
	var scriptKeys []string
	for _, item := range steps {
		p := kittest.Payload(t, item)
		if p["uses"] != "actions/github-script@v7" {
			continue
		}
		key, _ := p["key"].(string)
		scriptKeys = append(scriptKeys, key)
	}
	if len(scriptKeys) != 2 {
		t.Fatalf("got %d github-script steps, want 2: %+v", len(scriptKeys), steps)
	}
	if scriptKeys[0] == scriptKeys[1] {
		t.Fatalf("two steps with different with.script share a key: %s", scriptKeys[0])
	}
}

// TestHooksSameActionDifferentSecondaryFieldGetDistinctKeys reproduces
// the collision a reviewer found: two hooks with the same primary action
// field ("bash") but a different secondary field ("powershell") shared a
// key, because the key only carries the first present action field.
func TestHooksSameActionDifferentSecondaryFieldGetDistinctKeys(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".github", "hooks", "a.json"), `{"version":1,"hooks":{"sessionStart":[
		{"bash":"run.sh","powershell":"run1.ps1"},
		{"bash":"run.sh","powershell":"run2.ps1"}
	]}}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".github/hooks/a.json", model.ConfigKindHook)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2: %+v", len(items), items)
	}
	k1, _ := kittest.Payload(t, items[0])["key"].(string)
	k2, _ := kittest.Payload(t, items[1])["key"].(string)
	if k1 == k2 {
		t.Fatalf("two hooks with the same bash but different powershell share a key: %s", k1)
	}
}

func TestSetupStepsAliasesExpand(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".github", "workflows", "copilot-setup-steps.yml"), `on: push
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    env: &shared_env
      NODE_ENV: production
    steps:
      - name: install
        run: npm ci
        env: *shared_env
`)
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
	steps := got.Find(".github/workflows/copilot-setup-steps.yml", model.ConfigKindEnvSetup)
	var install model.ConfigItem
	found := false
	for _, item := range steps {
		if kittest.Payload(t, item)["name"] == "install" {
			install, found = item, true
		}
	}
	if !found {
		t.Fatalf("install step not found in %+v", steps)
	}
	env, ok := kittest.Payload(t, install)["env"].(map[string]any)
	if !ok || env["NODE_ENV"] != "production" {
		t.Fatalf("alias did not expand to the anchored env block: %+v", install.Payload)
	}
}

// TestSetupStepsAliasBombRejected checks that a "billion laughs" style
// alias bomb in copilot-setup-steps.yml is rejected with a blocking
// diagnostic and no items, instead of expanding without bound.
func TestSetupStepsAliasBombRejected(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	letters := "abcdefghi"
	for i, letter := range letters {
		fmt.Fprintf(&b, "%c: &%c [", letter, letter)
		if i == 0 {
			b.WriteString(`"lol","lol","lol","lol","lol","lol","lol","lol","lol"`)
		} else {
			prev := letters[i-1]
			for j := 0; j < 9; j++ {
				if j > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, "*%c", prev)
			}
		}
		b.WriteString("]\n")
	}
	b.WriteString("jobs:\n  copilot-setup-steps:\n    steps: []\n")
	root := t.TempDir()
	path := filepath.Join(".github", "workflows", "copilot-setup-steps.yml")
	kittest.WriteFile(t, filepath.Join(root, path), b.String())
	opts := Options{}
	got := kittest.Discover(t, New(opts), root)
	if len(got.Find(path, model.ConfigKindEnvSetup)) != 0 {
		t.Fatalf("alias bomb produced items: %+v", got.Items)
	}
	if !kittest.Blocking(t, New(opts), root, path) {
		t.Fatalf("alias bomb did not produce a blocking diagnostic: %v", got.Diagnostics)
	}
}

func TestSymlinkEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	kittest.WriteFile(t, filepath.Join(outside, "a.json"), `{"version":1,"hooks":{"sessionStart":[{"bash":"x"}]}}`)
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".github", "hooks")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Items) != 0 || !got.HasDiag(".github/hooks: symlink resolves outside the repository; Copilot may load its target") {
		t.Fatalf("got %+v", got)
	}
}

// TestSymlinkEscapeOutsideCopilotDirsNotReported is Follow-up 6's
// Copilot half: an escaping symlink at .github/skills is generic's
// shared skill root, not Copilot's, so Copilot's own diagnostic should
// not duplicate generic's (see internal/adapters.
// DedupeEscapingSymlinkDiagnostics for the remaining Claude overlap this
// narrower Relevant does not need to cover).
func TestSymlinkEscapeOutsideCopilotDirsNotReported(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".github", "skills")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none: .github/skills is generic's shared skill root, not Copilot's", got.Diagnostics)
	}
}

// TestAgentMCPServersBothSpellingsReported is Follow-up 7: a custom
// agent's frontmatter can declare mcp-servers and mcpServers side by
// side (see docs/adapters/copilot.md). A server of the same name under
// each spelling, with different definitions, must produce two separate
// items; neither the second key processed nor a same-named entry from
// the other spelling may silently overwrite or suppress the first.
func TestAgentMCPServersBothSpellingsReported(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".github", "agents", "a.agent.md"),
		"---\n"+
			"mcp-servers:\n"+
			"  fmt:\n"+
			"    command: fmt-kebab\n"+
			"mcpServers:\n"+
			"  fmt:\n"+
			"    command: fmt-camel\n"+
			"---\nbody\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".github/agents/a.agent.md", model.ConfigKindMCPServer)
	if len(items) != 2 {
		t.Fatalf("items = %+v, want one per spelling", got.Items)
	}
	commands := map[string]bool{}
	keys := map[string]bool{}
	for _, item := range items {
		p := kittest.Payload(t, item)
		commands[p["command"].(string)] = true
		key, _ := p["key"].(string)
		if keys[key] {
			t.Fatalf("items share an evidence key, so one would hide the other: %+v", items)
		}
		keys[key] = true
	}
	if !commands["fmt-kebab"] || !commands["fmt-camel"] {
		t.Fatalf("commands = %+v, want both fmt-kebab and fmt-camel reported", commands)
	}
}

// TestAgentMCPServersSameSpellingLastNameWins pins YAML's own semantics
// for a duplicate key reused in TestAgentMCPServersBothSpellingsReported's
// setup: within one mcp-servers (or mcpServers) object, a repeated server
// name is a YAML-level duplicate key, not Copilot's spelling collision,
// and decodes to whichever value the decoder keeps.
func TestAgentMCPServersSameSpellingLastNameWins(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".github", "agents", "a.agent.md"),
		"---\n"+
			"mcp-servers:\n"+
			"  fmt:\n"+
			"    command: first\n"+
			"  fmt:\n"+
			"    command: second\n"+
			"---\nbody\n")
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".github/agents/a.agent.md", model.ConfigKindMCPServer)
	if len(items) != 1 {
		t.Fatalf("items = %+v, want the YAML decoder's one value for the duplicate key", got.Items)
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".GitHub", "Hooks", "A.JSON"), `{"version":1,"hooks":{"sessionStart":[{"bash":"x"}]}}`)
	kittest.WriteFile(t, filepath.Join(root, ".github", "Copilot-Instructions.md"), "x")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".GitHub/Hooks/A.JSON", model.ConfigKindHook)) != 1 || len(got.Find(".github/Copilot-Instructions.md", model.ConfigKindInstructions)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

func TestCopilotHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	inside := filepath.Join(home, "alt")
	kittest.WriteFile(t, filepath.Join(inside, "hooks", "a.json"), `{"version":1,"hooks":{"sessionStart":[{"bash":"`+filepath.ToSlash(home)+`/bin/x"}]}}`)
	got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env("COPILOT_HOME", inside)}), t.TempDir())
	items := got.Find("~/alt/hooks/a.json", model.ConfigKindHook)
	if len(items) != 1 || kittest.Payload(t, items[0])["bash"] != "~/bin/x" {
		t.Fatalf("got %+v", got)
	}
}

func TestCopilotHomeOutsideHome(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	alt := t.TempDir()
	kittest.WriteFile(t, filepath.Join(alt, "hooks", "a.json"), `{"version":1,"hooks":{"sessionStart":[{"bash":"x"}]}}`)
	opts := Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env("COPILOT_HOME", alt)}
	got := kittest.Discover(t, New(opts), t.TempDir())
	if len(got.Find("~/COPILOT_HOME/hooks/a.json", model.ConfigKindHook)) != 1 || !got.HasDiag("outside the home directory") {
		t.Fatalf("got %+v", got)
	}
	// COPILOT_HOME outside home must behave like Claude's CLAUDE_CONFIG_DIR:
	// the configuration is still scanned, but the diagnostic is blocking
	// (not informational), so a scan exits non-zero.
	if !kittest.Blocking(t, New(opts), t.TempDir(), "outside the home directory") {
		t.Fatal("COPILOT_HOME outside home did not produce a blocking diagnostic")
	}
}

func TestDefaultPolicyDir(t *testing.T) {
	t.Parallel()
	cases := []struct{ goos, programData, want string }{
		{"linux", "", "/etc/github-copilot/policy.d"},
		{"darwin", "", "/etc/github-copilot/policy.d"},
		{"windows", "", `C:\ProgramData\GitHub\Copilot\policy.d`},
		{"windows", `E:\PD`, `E:\PD\GitHub\Copilot\policy.d`},
	}
	for _, tc := range cases {
		if got := defaultPolicyDir(tc.goos, kittest.Env("ProgramData", tc.programData)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.goos, got, tc.want)
		}
	}
}

func TestFingerprintsIgnoreMachinePaths(t *testing.T) {
	t.Parallel()
	run := func() []string {
		home := t.TempDir()
		kittest.WriteFile(t, filepath.Join(home, ".copilot", "mcp-config.json"), `{"mcpServers":{"a":{"command":"`+filepath.ToSlash(home)+`/bin/mcp"}}}`)
		got := kittest.Discover(t, New(Options{SkipRepo: true, IncludeUser: true, HomeDir: home, Getenv: kittest.Env()}), t.TempDir())
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
	policy := kittest.CopyTree(t, filepath.Join("testdata", "policy"))
	got := kittest.Discover(t, New(Options{HomeDir: home, PolicyDir: policy}), t.TempDir())
	if len(got.Items) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("repository-only scan read user or managed files: %+v", got)
	}
}

func TestDetect(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "on: push\n")
	kittest.WriteFile(t, filepath.Join(root, ".mcp.json"), "{}")
	if New(Options{}).Detect(root) {
		t.Fatal("Detect claimed files Copilot does not own")
	}
	kittest.WriteFile(t, filepath.Join(root, ".github", "copilot-instructions.md"), "x")
	if !New(Options{}).Detect(root) {
		t.Fatal("Detect missed copilot-instructions.md")
	}
}

func FuzzParseConfig(f *testing.F) {
	seeds := map[string]string{
		"hooks":    "testdata/repo/.github/hooks/guard.json",
		"settings": "testdata/repo/.github/copilot/settings.json",
		"agent":    "testdata/repo/.github/agents/formatter.agent.md",
		"setup":    "testdata/repo/.github/workflows/copilot-setup-steps.yml",
		"mcp":      "testdata/home/.copilot/mcp-config.json",
	}
	for kind, path := range seeds {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(kind, data)
		}
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.HarnessCopilot, product)
		for _, scope := range []model.Scope{model.ScopeRepo, model.ScopeUser} {
			path := ".github/x"
			if scope == model.ScopeUser {
				path = "~/.copilot/x"
			}
			f := &file{Source: c.Source(scope, path, data)}
			switch kind {
			case "hooks":
				f.hooksFile(data)
			case "settings":
				f.settings(data)
			case "agent":
				f.agent(data)
			case "setup":
				f.setupSteps(data)
			default:
				f.mcpConfig(data)
			}
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}
