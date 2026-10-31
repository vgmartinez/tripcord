package output

import (
	"strings"
	"testing"
)

// "key: value" redaction applies in header and assignment contexts
// (curl -H, YAML or env lines, JSON keys, flow mappings), not to free
// text such as a commit message.
func TestColonAssignmentsOnlyInHeaderOrAssignmentContext(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"git commit -m 'fix token: handling'",
		`git commit -m "fix secret: rotation" && git push`,
		"echo secret: foo && run",
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
		if got, removed := RedactAssignments(in); got != in || len(removed) != 0 {
			t.Errorf("RedactAssignments(%q) = %q, %q; want unchanged", in, got, removed)
		}
	}
	redacted := map[string]string{
		"curl -H 'X-Token: HDRTOK' https://x":         "curl -H 'X-Token: [REDACTED]' https://x",
		`curl --header "X-Api-Key: HDRKEY" https://x`: `curl --header "X-Api-Key: [REDACTED]" https://x`,
		"curl --header=X-Auth-Token:GLUEDHDR x":       "curl --header=X-Auth-Token:[REDACTED] x",
		"token: YAMLTOK":                              "token: [REDACTED]",
		"env:\n  - API_KEY: LISTTOK\n":                "env:\n  - API_KEY: [REDACTED]\n",
		`{"api_key": "JSONTOK"}`:                      `{"api_key": "[REDACTED]"}`,
		"env: {TOKEN: FLOWTOK, B: 1}":                 "env: {TOKEN: [REDACTED], B: 1}",
	}
	for in, want := range redacted {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactAssignmentsKeepsSpaceBeforeOperator(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"secret: foo && run":     "secret: [REDACTED] && run",
		"token: abc || fallback": "token: [REDACTED] || fallback",
		"password: pw ; next":    "password: [REDACTED] ; next",
	}
	for in, want := range cases {
		if got := DefaultRedactor(in); got != want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", in, got, want)
		}
		got, removed := RedactAssignments(in)
		if got != want || len(removed) != 1 || strings.HasSuffix(removed[0], " ") {
			t.Errorf("RedactAssignments(%q) = %q, %q", in, got, removed)
		}
	}
}
