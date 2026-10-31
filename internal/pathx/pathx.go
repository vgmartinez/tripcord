// Package pathx redacts a local filesystem path, typically the operator's
// home directory, out of text that otherwise shows it. It is shared by
// the scan CLI's git error messages and the Claude Code adapter's
// evidence keys and payloads, so both redact a home directory the same
// way.
package pathx

import (
	"path/filepath"
	"runtime"
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
//
// On Windows (runtime.GOOS == "windows"), matching is case-insensitive
// and treats "/" and "\\" as equivalent, since Windows paths are
// case-insensitive and both separators are valid and commonly mixed
// (an error message built with filepath.Join uses "\\", while config
// content or a user-typed path often uses "/"); on every other OS,
// matching stays byte-exact.
func TildeHome(home, text string) string {
	return tildeHome(home, text, runtime.GOOS == "windows")
}

// tildeHome is TildeHome with the Windows-matching decision passed in
// explicitly, rather than read from runtime.GOOS, so a test can exercise
// Windows-mode matching deterministically on any OS the test suite
// itself runs on (CI's "go test -race" step runs only on ubuntu-latest).
func tildeHome(home, text string, windowsMatching bool) string {
	home = filepath.Clean(home)
	if tooShortToRewrite(home) {
		return text
	}
	byteEqual := byteEqualExact
	if windowsMatching {
		byteEqual = byteEqualWindows
	}
	var b strings.Builder
	start := 0
	for {
		i := indexHome(text[start:], home, byteEqual)
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

// indexHome returns the index of the first byte range in text that
// equals home under byteEqual, or -1 if there is none. It is strings.Index
// generalized to a per-byte equality function, so Windows-mode matching
// can reuse the same boundary-scanning loop above as the exact-match case.
func indexHome(text, home string, byteEqual func(a, b byte) bool) int {
	n := len(home)
	for i := 0; i+n <= len(text); i++ {
		if regionEqual(text[i:i+n], home, byteEqual) {
			return i
		}
	}
	return -1
}

func regionEqual(a, b string, byteEqual func(x, y byte) bool) bool {
	for i := 0; i < len(a); i++ {
		if !byteEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func byteEqualExact(a, b byte) bool { return a == b }

// byteEqualWindows is byteEqual for Windows-mode matching: "/" and "\\"
// are the same separator, and ASCII letters compare case-insensitively
// (Windows paths are case-insensitive; non-ASCII bytes compare exactly,
// since case-folding them correctly would need full Unicode decoding
// this byte-at-a-time comparison does not have, and home directories
// are a narrow enough case that over-matching non-ASCII text is not
// worth that cost).
func byteEqualWindows(a, b byte) bool {
	if (a == '/' || a == '\\') && (b == '/' || b == '\\') {
		return true
	}
	return lowerASCII(a) == lowerASCII(b)
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
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
