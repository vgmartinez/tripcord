// Package pathx redacts a local filesystem path, typically the operator's
// home directory, out of text that otherwise shows it. It is shared by
// the scan CLI's git error messages and the Claude Code adapter's
// evidence keys and payloads, so both redact a home directory the same
// way.
package pathx

import (
	"path/filepath"
	"strings"
)

// TildeHome rewrites every occurrence of home in text that sits on a path
// segment boundary to "~". home is filepath.Clean-ed first, so a home
// with a trailing separator ("/home/vic/") still matches, and matches
// consume only the cleaned form, leaving the following separator intact
// in the output (producing "~/x", not "~x"). An empty home, or one that
// cleans to "/" or a bare drive root such as "C:\", is left alone,
// because either would otherwise match every absolute path.
//
// A match must be bounded on both sides, not only on the right: the
// character before it must be the start of text or one that cannot
// continue a path segment (so a shorter home such as "/home/vic" does
// not match inside the longer, unrelated "/home/victor"), and the
// character after it must be the end of text or one that cannot continue
// a path segment either (so home embedded mid-path, such as
// "/home/victor" appearing inside the unrelated "/mnt/x/home/victor/y",
// does not match: that occurrence is preceded by "x", which continues a
// path segment, so the left boundary fails and the text is returned
// unchanged). This mirrors tar and shell path-segment semantics: a path
// segment continues through letters, digits, and the handful of
// characters common inside one segment (".", "_", "-", "+", "@", "~",
// and any non-ASCII byte), and ends at everything else, in particular at
// "/" and "\\".
func TildeHome(home, text string) string {
	home = filepath.Clean(home)
	if tooShortToRewrite(home) {
		return text
	}
	var b strings.Builder
	start := 0
	for {
		i := strings.Index(text[start:], home)
		if i < 0 {
			b.WriteString(text[start:])
			return b.String()
		}
		matchStart := start + i
		matchEnd := matchStart + len(home)
		leftOK := matchStart == 0 || !continuesPathSegment(text[matchStart-1])
		rightOK := matchEnd == len(text) || !continuesPathSegment(text[matchEnd])
		if leftOK && rightOK {
			b.WriteString(text[start:matchStart])
			b.WriteByte('~')
			start = matchEnd
			continue
		}
		// Not a real boundary match. Keep the text up to and including
		// the first byte of this occurrence and resume the search right
		// after it, so an overlapping later match is still found.
		b.WriteString(text[start : matchStart+1])
		start = matchStart + 1
	}
}

// tooShortToRewrite reports whether home is too short, or too close to a
// filesystem root, to use as a rewrite prefix: empty, "/", or a bare
// Windows drive root such as "C:\" or "C:/". Any of those would match
// (and corrupt) every absolute path under it, which is every path there
// is.
func tooShortToRewrite(home string) bool {
	if len(home) <= 1 {
		return true
	}
	// A drive root: "C:" (filepath.Clean on a non-Windows build has no
	// "\" separator to preserve, so "C:/" cleans to this) or "C:\" /
	// "C:/" (what filepath.Clean produces on Windows itself).
	if len(home) >= 2 && len(home) <= 3 && home[1] == ':' {
		c := home[0]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
		return len(home) == 2 || home[2] == '\\' || home[2] == '/'
	}
	return false
}

// continuesPathSegment reports whether c extends the path segment before
// it. A path separator ("/" or "\\") ends a segment, and so does
// anything else not explicitly listed here (quotes, colons, whitespace,
// and the like), so a boundary check never has to special-case those
// individually.
func continuesPathSegment(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '-' || c == '+' || c == '@' || c == '~':
		return true
	case c >= 0x80:
		return true
	default:
		return false
	}
}
