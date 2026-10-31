package output

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"
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
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case isUnsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// isUnsafeRune reports runes above C0 that a terminal or renderer can treat
// as a control: DEL, C1 controls (U+0085 NEL and U+009B CSI among them),
// line and paragraph separators, and bidi embedding, override, isolate, and
// mark characters.
func isUnsafeRune(r rune) bool {
	switch {
	case r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r == 0x2028, r == 0x2029:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	default:
		return false
	}
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
			fmt.Fprintf(&b, `\u%04x`, r)
		} else {
			b.Write(encoded[i : i+size])
		}
		i += size
	}
	return b.Bytes()
}
