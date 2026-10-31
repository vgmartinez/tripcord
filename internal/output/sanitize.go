package output

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxFieldBytes is the maximum sanitized length of one displayed field,
	// including the truncation marker. It is applied after redaction and
	// after the sink's own escaping. Markdown's mention breaker counts
	// toward this limit.
	MaxFieldBytes = 1024
	// MaxMarkdownBytes is the maximum length of a Markdown comment. It stays
	// under GitHub's 65536-character limit, with margin for the omission line.
	MaxMarkdownBytes = 60000
	// GitHubCommentLimit is the documented maximum length of a GitHub
	// issue or pull request comment.
	GitHubCommentLimit = 65536
)

// escapeControls makes value safe to print inside one line. It escapes
// backslash, every C0 and C1 control, DEL, ESC, the Unicode line and
// paragraph separators, and bidi controls, so the result cannot end the
// line, move the cursor, or reorder surrounding text. Invalid UTF-8 bytes
// are escaped as \xNN.
func escapeControls(value string) string {
	return escapeLine(value, true)
}

// escapeControlsKeepBackslash is escapeControls for contexts that show text
// literally, such as markdown code, where doubling "\" would misquote it.
// A literal backslash is still doubled when it would otherwise read as one
// of this function's own escapes for a real control character (\xNN,
// \uXXXX, \UXXXXXXXX); see isHexEscapeBody.
func escapeControlsKeepBackslash(value string) string {
	return escapeLine(value, false)
}

func escapeLine(value string, escapeBackslash bool) string {
	var b strings.Builder
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, value[i])
		case r == '\\' && escapeBackslash:
			b.WriteString(`\\`)
		case r == '\\' && isHexEscapeBody(value[i+size:]):
			// A literal backslash in text that keeps backslashes (paths,
			// code) would otherwise read exactly like \xNN, \uXXXX, or
			// \UXXXXXXXX, our own escape for a real control character.
			// Double it so the two stay visually distinct.
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case isUnsafeRune(r):
			b.WriteString(runeEscape(r))
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// isUnsafeRune reports runes that must not be printed raw. That is DEL,
// C1 controls (U+0085 NEL and U+009B CSI among them), line and paragraph
// separators, Unicode format characters (category Cf: U+00AD, U+200B–U+200D,
// U+2060, U+FEFF, and the bidi controls), and the tag block U+E0000–U+E007F.
// Format and tag characters can carry hidden instructions to a reviewer.
func isUnsafeRune(r rune) bool {
	switch {
	case r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return true
	case r == 0x2028 || r == 0x2029:
		return true
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	case unicode.Is(unicode.Cf, r):
		return true
	default:
		return false
	}
}

// runeEscape is the visible form of an unsafe rune. Non-BMP runes use
// \UXXXXXXXX so the escape stays one token; \u is only four hex digits.
func runeEscape(r rune) string {
	if r <= 0xFFFF {
		return fmt.Sprintf(`\u%04x`, r)
	}
	return fmt.Sprintf(`\U%08x`, r)
}

// escapeJSONUnsafe rewrites unsafe runes in encoded JSON as \uXXXX escapes.
// encoding/json already escapes C0 controls; this covers the rest. The
// result decodes to the same value, so JSON documents stay faithful.
func escapeJSONUnsafe(encoded []byte) []byte {
	var b bytes.Buffer
	b.Grow(len(encoded))
	for i := 0; i < len(encoded); {
		r, size := utf8.DecodeRune(encoded[i:])
		if isUnsafeRune(r) {
			b.WriteString(jsonRuneEscape(r))
		} else {
			b.Write(encoded[i : i+size])
		}
		i += size
	}
	return b.Bytes()
}

// jsonRuneEscape is a JSON \u escape. Non-BMP runes use a surrogate pair
// so the document stays valid JSON and still decodes to the same rune.
func jsonRuneEscape(r rune) string {
	if r <= 0xFFFF {
		return fmt.Sprintf(`\u%04x`, r)
	}
	r -= 0x10000
	hi := 0xD800 + (r >> 10)
	lo := 0xDC00 + (r & 0x3FF)
	return fmt.Sprintf(`\u%04x\u%04x`, hi, lo)
}

// present sanitizes value and caps it. Sinks use it for every field.
func present(value string) string {
	return truncateSanitized(escapeControlsKeepBackslash(value), MaxFieldBytes)
}

// truncateSanitized caps value, which is already sanitized or is raw text
// whose backslash escapes must stay intact. The cut is on a UTF-8 boundary
// and never splits \n, \xNN, \uXXXX, \UXXXXXXXX, \\, \[, or \].
func truncateSanitized(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	best := 0
	for i := 0; i < len(value); {
		next := i + nextToken(value, i)
		marker := truncationMarker(len(value) - next)
		if next+len(marker) > limit {
			break
		}
		best = next
		i = next
	}
	if best == 0 {
		return truncationMarker(len(value))
	}
	return value[:best] + truncationMarker(len(value)-best)
}

func truncationMarker(dropped int) string {
	return fmt.Sprintf("…[truncated %d bytes]", dropped)
}

func nextToken(value string, i int) int {
	if n := escapeTokenLen(value[i:]); n > 0 {
		return n
	}
	r, n := utf8.DecodeRuneInString(value[i:])
	if n <= 0 {
		return 1
	}
	// "@" plus the Markdown mention breaker is one token, so a cap cannot
	// leave a bare "@" by cutting between them.
	if r == '@' && i+n < len(value) {
		r2, n2 := utf8.DecodeRuneInString(value[i+n:])
		if r2 == '\u200b' && n2 > 0 {
			return n + n2
		}
	}
	return n
}

// isHexEscapeBody reports whether s, the text right after a backslash, is
// the body of one of this package's hex-digit control escapes: xXX,
// uXXXX, or UXXXXXXXX. It deliberately excludes the single-letter bodies
// n, r, and t: those are common in ordinary Windows path fragments (e.g.
// "\new", "\temp"), and escaping every one of them would defeat keeping
// backslashes unescaped in text that shows paths literally.
func isHexEscapeBody(s string) bool {
	if s == "" {
		return false
	}
	switch s[0] {
	case 'x':
		return len(s) >= 3 && isHex(s[1]) && isHex(s[2])
	case 'u':
		return len(s) >= 5 && isHexString(s[1:5])
	case 'U':
		return len(s) >= 9 && isHexString(s[1:9])
	default:
		return false
	}
}

func escapeTokenLen(s string) int {
	if len(s) < 2 || s[0] != '\\' {
		return 0
	}
	switch s[1] {
	case '\\', 'n', 'r', 't', '[', ']':
		return 2
	case 'x':
		if len(s) >= 4 && isHex(s[2]) && isHex(s[3]) {
			return 4
		}
	case 'u':
		if len(s) >= 6 && isHexString(s[2:6]) {
			return 6
		}
	case 'U':
		if len(s) >= 10 && isHexString(s[2:10]) {
			return 10
		}
	}
	return 0
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
