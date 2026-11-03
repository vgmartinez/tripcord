package output

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

var jsonStringLiteral = regexp.MustCompile(`"(?:[^"\\\n]|\\.)*"`)

// RedactJSONText is DefaultRedactor for text that quotes JSON, such as
// a diff of a settings file. JSON escaping hides what the redactor
// keys on (a quote around a value is \", a line continuation is \\ and
// \n, any byte can be \u-escaped), so each string literal is decoded,
// redacted, and re-encoded when redaction changed it, and then the
// whole text is redacted.
func RedactJSONText(text string) string {
	text = jsonStringLiteral.ReplaceAllStringFunc(text, func(lit string) string {
		var value string
		if err := json.Unmarshal([]byte(lit), &value); err != nil {
			return lit
		}
		redacted := DefaultRedactor(value)
		if redacted == value {
			return lit
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(redacted); err != nil {
			return `"` + redactedMarker + `"`
		}
		return strings.TrimSuffix(b.String(), "\n")
	})
	return DefaultRedactor(text)
}

// PreviewLines is RedactJSONText for a multi-line preview of files, such
// as init's --dry-run diff. Each line is capped at MaxFieldBytes, so a
// long minified line is not an unbounded excerpt, and a line with a
// control, bidi, or invalid byte is escaped so it prints as one inert
// line. A line without one is shown as written: escaping it would double
// the backslashes of a JSON escape such as \\n.
func PreviewLines(text string) string {
	lines := strings.SplitAfter(RedactJSONText(text), "\n")
	for i, line := range lines {
		body, nl := strings.CutSuffix(line, "\n")
		if hasEscapedRune(body) {
			body = escapeControlsKeepBackslash(body)
		}
		lines[i] = truncateSanitized(body, MaxFieldBytes)
		if nl {
			lines[i] += "\n"
		}
	}
	return strings.Join(lines, "")
}

func hasEscapedRune(s string) bool {
	for i := range s {
		if s[i] != '\\' && willBeEscaped(s[i:]) {
			return true
		}
	}
	return false
}
