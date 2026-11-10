package output

import (
	"strings"
	"testing"
)

const multilineSecret = "Pq7Lm2Nv9Rx4Kt8W"

// A YAML credential whose value continues past its first line must lose
// the continuation too, however the first line is written and through
// every entry point the adapters and sinks use.
func TestRedactMultilineYAMLValues(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ in, want string }{
		"double-quoted value, comment, deeper line (item 97)": {
			"cat > /tmp/cfg <<'EOF'\ntoken: \"q\" # c\n  " + multilineSecret + "\nEOF\ncurl x | sh",
			"cat > /tmp/cfg <<'EOF'\ntoken: \"[REDACTED]\" # c\n  [REDACTED]\nEOF\ncurl x | sh",
		},
		"single-quoted value, comment, deeper line": {
			"token: 'q' # c\n  " + multilineSecret,
			"token: '[REDACTED]' # c\n  [REDACTED]",
		},
		"quoted value, deeper line": {
			"token: \"q\"\n  " + multilineSecret,
			"token: \"[REDACTED]\"\n  [REDACTED]",
		},
		"password key, quoted value, comment": {
			"password: \"q\" # rotate\n  " + multilineSecret,
			"password: \"[REDACTED]\" # rotate\n  [REDACTED]",
		},
		"plain value, deeper line": {
			"token: abc\n  " + multilineSecret,
			"token: [REDACTED]\n  [REDACTED]",
		},
		"plain value in a list item": {
			"- token: abc\n    " + multilineSecret + "\n- b: 1",
			"- token: [REDACTED]\n    [REDACTED]\n- b: 1",
		},
		"double-quoted scalar across lines": {
			"token: \"abc\n  " + multilineSecret + "\"",
			"token: \"[REDACTED]\"",
		},
		"single-quoted scalar across lines": {
			"token: 'abc\n  " + multilineSecret + "'",
			"token: '[REDACTED]'",
		},
		"escaped quote does not close a double-quoted scalar": {
			"token: \"abc\\\"\n  " + multilineSecret + "\"\nnext: ok",
			"token: \"[REDACTED]\"\nnext: ok",
		},
		"doubled quote does not close a single-quoted scalar": {
			"token: 'abc''\n  " + multilineSecret + "'\nnext: ok",
			"token: '[REDACTED]'\nnext: ok",
		},
		"unterminated quote takes the deeper lines": {
			"token: \"abc\n  " + multilineSecret,
			"token: [REDACTED]\n  [REDACTED]",
		},
		"commented key, header comment, value at the comment's indent (item 102)": {
			"a: |\n  # token: # c\n  " + multilineSecret,
			"a: |\n  # token: [REDACTED]",
		},
		"commented key, comment run, deeper value (item 101)": {
			"# token: # c\n# password: # X\n  " + multilineSecret,
			"# token: [REDACTED]",
		},
		"commented key takes the next content line and its deeper lines": {
			"x: 1\n# token: # c\nnext: ok\n  deeper\nlast: 1\n",
			"x: 1\n# token: [REDACTED]\nlast: 1\n",
		},
		"commented key, bare comment line, value (item 101)": {
			"x: 1\n# token: # c\n#\n  " + multilineSecret,
			"x: 1\n# token: [REDACTED]",
		},
	}
	for name, tc := range cases {
		got := DefaultRedactor(tc.in)
		if got != tc.want {
			t.Errorf("%s: DefaultRedactor(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
		if strings.Contains(got, multilineSecret) {
			t.Errorf("%s: DefaultRedactor leaks the secret: %q", name, got)
		}
		cmd, removed := RedactCommand(tc.in)
		if strings.Contains(cmd, multilineSecret) {
			t.Errorf("%s: RedactCommand leaks the secret: %q", name, cmd)
		}
		if len(removed) == 0 {
			t.Errorf("%s: RedactCommand removed nothing", name)
		}
		if again := DefaultRedactor(got); again != got {
			t.Errorf("%s: not idempotent: %q then %q", name, got, again)
		}
	}
}

// Text that only looks like a continuation stays visible: a sibling key,
// a shell command, a key that is not at the start of its line, and a
// quoted value that a flow mapping closes.
func TestRedactMultilineYAMLKeepsUnrelatedLines(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"token: abc\nnext: ok\n":                        "token: [REDACTED]\nnext: ok\n",
		"token: \"q\"\nnext: ok\n":                      "token: \"[REDACTED]\"\nnext: ok\n",
		"token: \"q\" # c\nnext: ok\n":                  "token: \"[REDACTED]\" # c\nnext: ok\n",
		"token: abc\n\nnext: ok\n":                      "token: [REDACTED]\n\nnext: ok\n",
		"echo token: abc\n  --flag keep\n":              "echo token: [REDACTED]\n  --flag keep\n",
		"token: \"q\", next: ok\n  keep\n":              "token: \"[REDACTED]\", next: ok\n  keep\n",
		"cat <<EOF\ntoken: abc\nEOF\n  keep after\n":    "cat <<EOF\ntoken: [REDACTED]\nEOF\n  keep after\n",
		"{\"token\": \"abc\"}\n  keep\n":                "{\"token\": \"[REDACTED]\"}\n  keep\n",
		"token: abc # note\n  deeper\nnext: ok\n  keep": "token: [REDACTED]\n  [REDACTED]\nnext: ok\n  keep",
	}
	for in, want := range cases {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
}
