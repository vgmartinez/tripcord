package codex

import "testing"

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
	rules, ok := parseRulesFile([]byte(src))
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
	rules, ok := parseRulesFile([]byte(`prefix_rule(pattern = ["npm", "test"])`))
	if !ok || len(rules) != 1 {
		t.Fatalf("parseRulesFile = %+v, %v", rules, ok)
	}
	if rules[0].decision != "allow" {
		t.Fatalf("decision = %q, want allow", rules[0].decision)
	}
}

func TestParseRulesFileSingleQuotesAndEscapes(t *testing.T) {
	t.Parallel()
	rules, ok := parseRulesFile([]byte(`prefix_rule(pattern = ['a\'b', "c\"d", "e\\f", "g\nh"])`))
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
		"unknown top-level call": `host_executable(name = "git")`,
		"unknown kwarg":          `prefix_rule(pattern = ["a"], color = "red")`,
		"duplicate kwarg":        `prefix_rule(pattern = ["a"], pattern = ["b"])`,
		"non-string decision":    `prefix_rule(pattern = ["a"], decision = ["allow"])`,
		"non-list pattern":       `prefix_rule(pattern = "a")`,
		"empty pattern":          `prefix_rule(pattern = [])`,
		"equality operator":      `prefix_rule(pattern == ["a"])`,
		"triple-quoted string":   `prefix_rule(pattern = ["""a"""])`,
		"unsupported escape":     `prefix_rule(pattern = ["\x41"])`,
		"unterminated string":    "prefix_rule(pattern = [\"a)",
		"multi-line string":      "prefix_rule(pattern = [\"a\nb\"])",
		"trailing garbage":       `prefix_rule(pattern = ["a"]) %`,
		"missing pattern":        `prefix_rule(decision = "allow")`,
		"positional argument":    `prefix_rule(["a"])`,
		"variable reference":     `prefix_rule(pattern = x)`,
		"string concatenation":   `prefix_rule(pattern = ["a" + "b"])`,
		"unclosed call":          `prefix_rule(pattern = ["a"]`,
		"unclosed list":          `prefix_rule(pattern = ["a")`,
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
	rules, ok := parseRulesFile([]byte("# only a comment\n\n"))
	if !ok {
		t.Fatalf("parseRulesFile returned ok=false for a comment-only file")
	}
	if len(rules) != 0 {
		t.Fatalf("rules = %+v, want none", rules)
	}
}

func TestParseRulesFileNestedLists(t *testing.T) {
	t.Parallel()
	rules, ok := parseRulesFile([]byte(`prefix_rule(pattern = ["a", ["b", "c"]])`))
	if !ok || len(rules) != 1 {
		t.Fatalf("parseRulesFile = %+v, %v", rules, ok)
	}
	nested, ok := rules[0].pattern[1].([]any)
	if !ok || len(nested) != 2 {
		t.Fatalf("pattern[1] = %+v", rules[0].pattern[1])
	}
}
