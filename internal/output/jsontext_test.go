package output

import (
	"strings"
	"testing"
)

// JSON escaping must not hide a credential from the redactor: a quoted
// value is \"...\", a line continuation is \\ then \n, and any byte can
// be \u-escaped.
func TestRedactJSONText(t *testing.T) {
	t.Parallel()
	for in, secret := range map[string]string{
		`+  "a": "deploy --password \"correct horse JSONT01\""`:        "JSONT01",
		`   "a": "curl --token \\\n  JSONT02 https://h.invalid/"`:      "JSONT02",
		`-  "a": "curl --token=\u004aSONT03"`:                          "JSONT03",
		`   "SECRET_KEY": "JSONT04"`:                                   "JSONT04",
		`   "a": "echo ghp_JSONT05\u00300000000000000000000000000000"`: "JSONT05",
		`   "a": "git clone https://u:JSONT06@h.invalid/r"`:            "JSONT06",
		`   "a": "curl -H \"Authorization: Bearer JSONT07\""`:          "JSONT07",
	} {
		out := RedactJSONText(in)
		if strings.Contains(out, secret) || strings.Contains(out, `\u004a`) || !strings.Contains(out, redactedMarker) {
			t.Errorf("RedactJSONText(%q) = %q", in, out)
		}
	}
	for _, keep := range []string{
		`+  "start": "make dev",`,
		`   "a": "say \"hi\" \\ \u00e9 <tag> & done"`,
		`not json "unterminated`,
	} {
		if out := RedactJSONText(keep); out != keep {
			t.Errorf("RedactJSONText(%q) = %q, want it unchanged", keep, out)
		}
	}
}

func TestPreviewLines(t *testing.T) {
	t.Parallel()
	long := `+  "a": "` + strings.Repeat("x", 3*MaxFieldBytes) + `"`
	in := " {\n" + long + "\n-  \"b\": \"curl --token=PREVIEW01\x1b[2J\"\n }"
	out := PreviewLines(in)
	lines := strings.Split(out, "\n")
	if len(lines) != 4 || lines[0] != " {" || lines[3] != " }" {
		t.Fatalf("PreviewLines(%q) = %q", in, out)
	}
	if len(lines[1]) > MaxFieldBytes || !strings.HasPrefix(lines[1], `+  "a": "xxx`) {
		t.Errorf("long line = %d bytes %q", len(lines[1]), lines[1][:40])
	}
	if strings.Contains(out, "PREVIEW01") || strings.Contains(out, "\x1b") {
		t.Errorf("line 3 = %q", lines[2])
	}
	if keep := `   "dir": "C:\\dir\\new \"x\""`; PreviewLines(keep) != keep {
		t.Errorf("PreviewLines(%q) = %q, want it unchanged", keep, PreviewLines(keep))
	}
}
