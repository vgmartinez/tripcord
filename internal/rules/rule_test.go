package rules

import (
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

const validWhen = `when: has(task.runOptions) && has(task.runOptions.runOn) && task.runOptions.runOn == "folderOpen"`

const validRule = `id: TC-CFG-002
pack: tripcord/core
title: "VS Code task that runs when the folder opens"
severity: high
harness: [vscode, cursor, windsurf]
files: [".vscode/tasks.json"]
when: has(task.runOptions) && has(task.runOptions.runOn) && task.runOptions.runOn == "folderOpen"
fix: "Remove runOn: folderOpen or move the task to an explicit script"
refs:
  - https://workos.com/blog/npm-worm-coding-agent-config-credentials
`

func testEnv(t testing.TB) *Env {
	t.Helper()
	env, err := NewEnv(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestValidID(t *testing.T) {
	for _, id := range []string{"TC-CFG-001", "TC-SEC-017", "TC-FOR-022", "ACME-001", "TEST-CFG-1234"} {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false", id)
		}
	}
	for _, id := range []string{"", "tc-cfg-001", "TC-CFG-01", "TC-CFG-", "TC_CFG_001", "001", "TC-CFG-001 ", "-TC-001", "TC--001"} {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true", id)
		}
	}
}

func TestParsePackRef(t *testing.T) {
	ref, err := ParsePackRef("tripcord/core@2026.11")
	if err != nil || ref.Name != "tripcord/core" || ref.Version != "2026.11" || ref.String() != "tripcord/core@2026.11" {
		t.Fatalf("got %+v, %v", ref, err)
	}
	if _, err := ParsePackRef("acme/org-policy@2027.01.3"); err != nil {
		t.Error(err)
	}
	for _, s := range []string{"", "tripcord/core", "core@2026.11", "Tripcord/core@2026.11", "tripcord/core@2026.13", "tripcord/core@26.11", "tripcord/core@2026.11.01", "tripcord/core@latest", "a/b/c@2026.11"} {
		if _, err := ParsePackRef(s); err == nil {
			t.Errorf("ParsePackRef(%q) succeeded", s)
		}
	}
}

func TestParseSpecValid(t *testing.T) {
	spec, err := ParseSpec([]byte(validRule))
	if err != nil {
		t.Fatal(err)
	}
	if spec.ID != "TC-CFG-002" || spec.Severity != "high" || len(spec.Harness) != 3 || len(spec.Refs) != 1 {
		t.Fatalf("spec = %+v", spec)
	}
	r, err := Compile(spec, coreManifest, testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Severity != model.SeverityHigh || r.Pack != coreManifest {
		t.Fatalf("rule = %+v", r)
	}
}

var coreManifest = PackRef{Name: "tripcord/core", Version: "2026.11"}

// withoutKey drops the top-level key from validRule, including its
// continuation lines.
func withoutKey(key string) string {
	var out []string
	skipping := false
	for _, line := range strings.Split(validRule, "\n") {
		if strings.HasPrefix(line, key+":") {
			skipping = true
			continue
		}
		if skipping && strings.HasPrefix(line, " ") {
			continue
		}
		skipping = false
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func TestParseSpecRequiredFields(t *testing.T) {
	for _, key := range []string{"id", "pack", "title", "severity", "harness", "files", "when", "fix", "refs"} {
		t.Run(key, func(t *testing.T) {
			if _, err := ParseSpec([]byte(withoutKey(key))); err == nil {
				t.Fatalf("rule without %s was accepted", key)
			}
		})
	}
}

func TestParseSpecRejects(t *testing.T) {
	cases := map[string]string{
		"empty refs":      strings.Replace(validRule, "refs:\n  - https://workos.com/blog/npm-worm-coding-agent-config-credentials\n", "refs: []\n", 1),
		"http ref":        strings.Replace(validRule, "https://workos", "http://workos", 1),
		"relative ref":    strings.Replace(validRule, "https://workos.com/blog", "/blog", 1),
		"unknown key":     validRule + "extra: 1\n",
		"duplicate key":   validRule + "id: TC-CFG-003\n",
		"two documents":   validRule + "---\n" + validRule,
		"bad severity":    strings.Replace(validRule, "severity: high", "severity: urgent", 1),
		"bad harness":     strings.Replace(validRule, "[vscode, cursor, windsurf]", "[vscode, emacs]", 1),
		"twice harness":   strings.Replace(validRule, "[vscode, cursor, windsurf]", "[cursor, cursor]", 1),
		"absolute glob":   strings.Replace(validRule, `".vscode/tasks.json"`, `"/etc/tasks.json"`, 1),
		"dotdot glob":     strings.Replace(validRule, `".vscode/tasks.json"`, `"../tasks.json"`, 1),
		"backslash glob":  strings.Replace(validRule, `".vscode/tasks.json"`, `".vscode\\tasks.json"`, 1),
		"invalid glob":    strings.Replace(validRule, `".vscode/tasks.json"`, `".vscode/[tasks.json"`, 1),
		"bad id":          strings.Replace(validRule, "id: TC-CFG-002", "id: tc-cfg-2", 1),
		"versioned pack":  strings.Replace(validRule, "pack: tripcord/core", "pack: tripcord/core@2026.11", 1),
		"bare pack name":  strings.Replace(validRule, "pack: tripcord/core", "pack: core", 1),
		"blank title":     strings.Replace(validRule, `title: "VS Code task that runs when the folder opens"`, `title: "  "`, 1),
		"not a mapping":   "- a\n- b\n",
		"empty":           "",
		"scalar document": "hello\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSpec([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestParseSpecSizeLimit(t *testing.T) {
	doc := validRule + "# " + strings.Repeat("x", MaxRuleBytes) + "\n"
	if _, err := ParseSpec([]byte(doc)); err == nil {
		t.Fatal("oversized rule accepted")
	}
}

func TestParseSpecHomeGlob(t *testing.T) {
	doc := strings.Replace(validRule, `".vscode/tasks.json"`, `"~/.claude/settings.json", ".github/instructions/**/*.instructions.md"`, 1)
	if _, err := ParseSpec([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}

func TestCompileRejectsBadWhen(t *testing.T) {
	for name, when := range map[string]string{
		"syntax":         `task.runOptions.runOn ==`,
		"not bool":       `task.runOptions.runOn`,
		"unknown var":    `env.HOME == "x"`,
		"backreference":  `has(payload.command) && payload.command.matches("(a)\\1")`,
		"unknown func":   `readFile("/etc/passwd") == ""`,
		"lookahead":      `has(payload.command) && payload.command.matches("a(?=b)")`,
		"unguarded":      `payload.command == "sh"`,
		"string literal": `"true"`,
	} {
		t.Run(name, func(t *testing.T) {
			doc := strings.Replace(validRule, validWhen, "when: '"+strings.ReplaceAll(when, "'", "''")+"'", 1)
			spec, err := ParseSpec([]byte(doc))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Compile(spec, coreManifest, testEnv(t)); err == nil {
				t.Fatalf("compiled %q", when)
			}
		})
	}
}

func TestApplies(t *testing.T) {
	spec, err := ParseSpec([]byte(strings.Replace(validRule, `".vscode/tasks.json"`, `".vscode/tasks.json", ".github/instructions/**/*.md"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compile(spec, coreManifest, testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		harness model.Harness
		path    string
		want    bool
	}{
		{model.SurfaceVSCode, ".vscode/tasks.json", true},
		{model.HarnessCursor, ".vscode/tasks.json", true},
		{model.HarnessClaude, ".vscode/tasks.json", false},
		{model.SurfaceVSCode, "sub/.vscode/tasks.json", false},
		{model.SurfaceVSCode, ".github/instructions/a/b/x.md", true},
		{model.SurfaceVSCode, ".github/instructions/x.md", true},
		{model.SurfaceVSCode, ".github/x.md", false},
	}
	for _, c := range cases {
		item := model.ConfigItem{Harness: c.harness, Path: c.path}
		if got := r.Applies(item); got != c.want {
			t.Errorf("Applies(%s, %s) = %v, want %v", c.harness, c.path, got, c.want)
		}
	}
}
