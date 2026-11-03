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
