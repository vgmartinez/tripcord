package output

import (
	"slices"
	"testing"
)

// A secret flag name that is the argument of a literal-text flag of a
// specific tool (grep -e, git commit -m) is that text, not a flag; the
// same flag of another tool is not exempt.
func TestRedactCommandLeavesLiteralFlagArgumentsAlone(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"grep -e --token file",
		`git commit -m "--token handling"`,
		"git log --grep --secret",
		"git commit -m 'fix token: handling'",
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
		if got, removed := RedactCommand(in); got != in || len(removed) != 0 {
			t.Errorf("RedactCommand(%q) = %q, %q; want unchanged", in, got, removed)
		}
	}
	for in, want := range map[string]string{
		"echo -e --token PXC21":          "echo -e --token [REDACTED]",
		"grep --regexp --password PXC22": "grep --regexp --password [REDACTED]",
	} {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
	if got := DefaultRedactor("grep -e x --token REALTOKEN"); got != "grep -e x --token [REDACTED]" {
		t.Errorf("a secret flag after the literal argument must still be redacted: %q", got)
	}
}

func TestRedactCommandStopsAtSubstitutionClose(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"$(openssl enc -k SUBK)":         "$(openssl enc -k [REDACTED])",
		"x=$(openssl enc -k SUBK)":       "x=$(openssl enc -k [REDACTED])",
		"x=`vercel -t TICKT`":            "x=`vercel -t [REDACTED]`",
		"(cli --token PARENTOK)":         "(cli --token [REDACTED])",
		"echo $(cli --password=EQPASS)":  "echo $(cli --password=[REDACTED])",
		"(FOO=1 GITHUB_TOKEN=ASSIGNTOK)": "(FOO=1 GITHUB_TOKEN=[REDACTED])",
		"$(curl -u bob:UPASS https://x)": "$(curl -u [REDACTED] https://x)",
		"`curl -u bob:TICKPASS`":         "`curl -u [REDACTED]`",
	}
	for in, want := range cases {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		if got, _ := RedactCommand(in); got != want {
			t.Errorf("RedactCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactCommandEmptyFlagValueIsNotASecret(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"cli --token=", "cli --token= --verbose", "cli --password=''", `cli --api-key=""`} {
		if got, removed := RedactCommand(in); got != in || len(removed) != 0 {
			t.Errorf("RedactCommand(%q) = %q, %q; want unchanged, nothing removed", in, got, removed)
		}
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
}

// The value removed (which feeds the source-side key discriminator) and
// the redacted output agree on quotes: the output keeps the value's own
// quotes around [REDACTED], and removed is the value without them.
func TestRedactCommandQuotesAgree(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want, removed string }{
		{"cli --token='-Q'", "cli --token='[REDACTED]'", "-Q"},
		{`cli --token="-Q"`, `cli --token="[REDACTED]"`, "-Q"},
		{"cli --token '-Q'", "cli --token '[REDACTED]'", "-Q"},
		{"cli --token=-Q", "cli --token=[REDACTED]", "-Q"},
		{`cli "--token" QUOTEDFLAG`, `cli "--token" [REDACTED]`, "QUOTEDFLAG"},
		{`cli '--token' 'QUOTED BOTH'`, `cli '--token' '[REDACTED]'`, "QUOTED BOTH"},
	}
	for _, tc := range cases {
		got, removed := RedactCommand(tc.in)
		if got != tc.want || !slices.Equal(removed, []string{tc.removed}) {
			t.Errorf("RedactCommand(%q) = %q, %q; want %q, [%q]", tc.in, got, removed, tc.want, tc.removed)
		}
		if def := DefaultRedactor(tc.in); def != tc.want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", tc.in, def, tc.want)
		}
	}
	if in := `cli "--token' X`; DefaultRedactor(in) != in {
		t.Errorf("mismatched quotes around the flag name: %q", DefaultRedactor(in))
	}
}
