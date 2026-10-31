package codex

import (
	"strings"
	"testing"
)

func TestParseRulesFileValid(t *testing.T) {
	t.Parallel()
	src := `# comment
prefix_rule(
    pattern = ["git", "add"],
    decision = "allow",
)

prefix_rule(
    pattern = ["gh", "pr", "view"],
    decision = "prompt",
    justification = "needs approval",
    match = ["gh pr view 7888"],
    not_match = ["gh pr --repo x view 7888"],
)
`
	parsed, ok := parseRulesFile([]byte(src))
	rules := parsed.prefixRules
	if !ok {
		t.Fatalf("parseRulesFile returned ok=false for valid input")
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want 2", rules)
	}
	if rules[0].decision != "allow" || len(rules[0].pattern) != 2 {
		t.Fatalf("rules[0] = %+v", rules[0])
	}
	if rules[1].decision != "prompt" || rules[1].justification != "needs approval" {
		t.Fatalf("rules[1] = %+v", rules[1])
	}
	if len(rules[1].match) != 1 || len(rules[1].notMatch) != 1 {
		t.Fatalf("rules[1] match/not_match = %+v", rules[1])
	}
}

func TestParseRulesFileDecisionDefaultsToAllow(t *testing.T) {
	t.Parallel()
	parsed, ok := parseRulesFile([]byte(`prefix_rule(pattern = ["npm", "test"])`))
	rules := parsed.prefixRules
	if !ok || len(rules) != 1 {
		t.Fatalf("parseRulesFile = %+v, %v", rules, ok)
	}
	if rules[0].decision != "allow" {
		t.Fatalf("decision = %q, want allow", rules[0].decision)
	}
}

func TestParseRulesFileSingleQuotesAndEscapes(t *testing.T) {
	t.Parallel()
	parsed, ok := parseRulesFile([]byte(`prefix_rule(pattern = ['a\'b', "c\"d", "e\\f", "g\nh"])`))
	rules := parsed.prefixRules
	if !ok || len(rules) != 1 {
		t.Fatalf("parseRulesFile = %+v, %v", rules, ok)
	}
	want := []any{"a'b", `c"d`, `e\f`, "g\nh"}
	if len(rules[0].pattern) != len(want) {
		t.Fatalf("pattern = %+v", rules[0].pattern)
	}
	for i, w := range want {
		if rules[0].pattern[i] != w {
			t.Fatalf("pattern[%d] = %q, want %q", i, rules[0].pattern[i], w)
		}
	}
}

func TestParseRulesFileRejectsUnrecognizedConstructs(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown top-level call":           `exec_rule(pattern = ["git"])`,
		"host_executable without paths":    `host_executable(name = "git")`,
		"host_executable without name":     `host_executable(paths = ["/usr/bin/git"])`,
		"host_executable empty name":       `host_executable(name = "", paths = [])`,
		"host_executable unknown kwarg":    `host_executable(name = "git", paths = [], alias = "g")`,
		"host_executable non-string path":  `host_executable(name = "git", paths = [["/usr/bin/git"]])`,
		"host_executable paths not a list": `host_executable(name = "git", paths = "/usr/bin/git")`,
		"uppercase decision":               `prefix_rule(pattern = ["git"], decision = "ALLOW")`,
		"undocumented decision":            `prefix_rule(pattern = ["git"], decision = "deny")`,
		"unknown kwarg":                    `prefix_rule(pattern = ["a"], color = "red")`,
		"duplicate kwarg":                  `prefix_rule(pattern = ["a"], pattern = ["b"])`,
		"non-string decision":              `prefix_rule(pattern = ["a"], decision = ["allow"])`,
		"non-list pattern":                 `prefix_rule(pattern = "a")`,
		"empty pattern":                    `prefix_rule(pattern = [])`,
		"equality operator":                `prefix_rule(pattern == ["a"])`,
		"triple-quoted string":             `prefix_rule(pattern = ["""a"""])`,
		"unsupported escape":               `prefix_rule(pattern = ["\x41"])`,
		"unterminated string":              "prefix_rule(pattern = [\"a)",
		"multi-line string":                "prefix_rule(pattern = [\"a\nb\"])",
		"trailing garbage":                 `prefix_rule(pattern = ["a"]) %`,
		"missing pattern":                  `prefix_rule(decision = "allow")`,
		"positional argument":              `prefix_rule(["a"])`,
		"variable reference":               `prefix_rule(pattern = x)`,
		"string concatenation":             `prefix_rule(pattern = ["a" + "b"])`,
		"unclosed call":                    `prefix_rule(pattern = ["a"]`,
		"unclosed list":                    `prefix_rule(pattern = ["a")`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, ok := parseRulesFile([]byte(src)); ok {
				t.Fatalf("parseRulesFile(%q) = ok, want opaque fallback", src)
			}
		})
	}
}

func TestParseRulesFileEmptyIsZeroRules(t *testing.T) {
	t.Parallel()
	parsed, ok := parseRulesFile([]byte("# only a comment\n\n"))
	rules := parsed.prefixRules
	if !ok {
		t.Fatalf("parseRulesFile returned ok=false for a comment-only file")
	}
	if len(rules) != 0 {
		t.Fatalf("rules = %+v, want none", rules)
	}
}

func TestParseRulesFileNestedLists(t *testing.T) {
	t.Parallel()
	parsed, ok := parseRulesFile([]byte(`prefix_rule(pattern = ["a", ["b", "c"]])`))
	rules := parsed.prefixRules
	if !ok || len(rules) != 1 {
		t.Fatalf("parseRulesFile = %+v, %v", rules, ok)
	}
	nested, ok := rules[0].pattern[1].([]any)
	if !ok || len(nested) != 2 {
		t.Fatalf("pattern[1] = %+v", rules[0].pattern[1])
	}
}

func TestParseRulesFileHostExecutable(t *testing.T) {
	t.Parallel()
	parsed, ok := parseRulesFile([]byte(`host_executable(
    name = "git",
    paths = ["/opt/homebrew/bin/git", "/usr/bin/git"],
)
prefix_rule(pattern = ["git", "status"])
`))
	if !ok || len(parsed.hostExecutables) != 1 || len(parsed.prefixRules) != 1 {
		t.Fatalf("parseRulesFile = %+v, %v", parsed, ok)
	}
	host := parsed.hostExecutables[0]
	if host.name != "git" || len(host.paths) != 2 || host.paths[1] != "/usr/bin/git" {
		t.Fatalf("host_executable = %+v", host)
	}
}

func TestParseRulesFileDocumentedDecisions(t *testing.T) {
	t.Parallel()
	for _, decision := range []string{"allow", "prompt", "forbidden"} {
		parsed, ok := parseRulesFile([]byte(`prefix_rule(pattern = ["git"], decision = "` + decision + `")`))
		if !ok || len(parsed.prefixRules) != 1 || parsed.prefixRules[0].decision != decision {
			t.Errorf("decision %q: parseRulesFile = %+v, %v", decision, parsed, ok)
		}
	}
}

func TestParseRulesFileLimitCountsHostExecutables(t *testing.T) {
	t.Parallel()
	var src strings.Builder
	for i := 0; i <= maxRulesPerFile; i++ {
		src.WriteString(`host_executable(name = "git", paths = [])` + "\n")
	}
	if _, ok := parseRulesFile([]byte(src.String())); ok {
		t.Fatalf("%d calls parsed, want opaque past maxRulesPerFile", maxRulesPerFile+1)
	}
}

// A raw control byte inside a string (a CR, which a CRLF-aware reader
// might drop, or a NUL, which truncates the value for a C consumer) has
// no single meaning, so the file is opaque rather than decoded one way.
// CRLF line endings outside strings, and the \r escape, still parse.
func TestParseRulesFileRejectsRawControlBytesInStrings(t *testing.T) {
	t.Parallel()
	for name, src := range map[string]string{
		"raw CR":  "prefix_rule(pattern = [\"git\r\", \"push\"])",
		"raw NUL": "prefix_rule(pattern = [\"git\x00rm\"])",
		"raw ESC": "prefix_rule(pattern = ['a\x1bb'])",
	} {
		if _, ok := parseRulesFile([]byte(src)); ok {
			t.Errorf("%s: parseRulesFile(%q) = ok, want opaque fallback", name, src)
		}
	}
	for _, src := range []string{
		"prefix_rule(pattern = [\"git\", \"push\"])\r\nprefix_rule(pattern = [\"ls\"])\r\n",
		`prefix_rule(pattern = ["a\rb", "tab	here"])`,
	} {
		if _, ok := parseRulesFile([]byte(src)); !ok {
			t.Errorf("parseRulesFile(%q) = opaque, want parsed", src)
		}
	}
}
