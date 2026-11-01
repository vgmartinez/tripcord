// Package hiddenchar finds code points that change what text says
// without showing on screen: Unicode bidirectional controls, which
// reorder what a reviewer sees, tag characters, which spell ASCII text
// that renders as nothing, and zero-width characters. An agent reads all
// of them. It reports where each run of them starts and its first code
// point, never the text, so a finding cannot carry the hidden
// instruction.
package hiddenchar

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/model"
)

// MaxRuns is how many runs Scan keeps positions for. Later runs are
// counted, not located.
const MaxRuns = 5

// Classes of hidden code points.
const (
	Bidi      = "bidi control"
	Tag       = "tag character"
	ZeroWidth = "zero-width"
)

// Class returns the class of a hidden code point, or "" for any other:
// U+202A-U+202E and U+2066-U+2069 are bidi controls, U+E0000-U+E007F tag
// characters, and U+200B-U+200D, U+2060, and U+FEFF zero-width. Scan
// does not count a byte order mark at the start of the file.
func Class(r rune) string {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return Bidi
	case r >= 0xE0000 && r <= 0xE007F:
		return Tag
	case r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF:
		return ZeroWidth
	}
	return ""
}

var bom = []byte{0xEF, 0xBB, 0xBF}

// Scan returns the hidden code points of b, and whether b is valid
// UTF-8. Lines are counted from 1 and end at \n; columns are counted
// from 1 in code points, so \r is a column and an invalid byte is one.
// A leading byte order mark is neither reported nor a column.
// Consecutive hidden code points of any class are one run. An invalid
// byte ends a run and is otherwise skipped, so the rest of the file is
// still read.
func Scan(b []byte) (model.HiddenChars, bool) {
	var out model.HiddenChars
	valid := true
	b, _ = bytes.CutPrefix(b, bom)
	line, col := 1, 1
	inRun, stored := false, false
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		switch {
		case r == utf8.RuneError && size == 1:
			valid = false
			inRun = false
		case r == '\n':
			line, col = line+1, 1
			inRun = false
			continue
		case Class(r) != "":
			out.Total++
			switch {
			case inRun && stored:
				out.Runs[len(out.Runs)-1].Length++
			case !inRun:
				out.RunCount++
				stored = len(out.Runs) < MaxRuns
				if stored {
					out.Runs = append(out.Runs, model.HiddenRun{CodePoint: r, Line: line, Column: col, Length: 1})
				}
			}
			inRun = true
		default:
			inRun = false
		}
		col++
	}
	return out, valid
}

// Excerpt describes h for a finding: the number of hidden code points,
// and for each located run its first code point and class, line and
// column, and length. A tag character is named by its block, not its
// code point, because each one stands for a printable ASCII character
// and would spell out the hidden text. The result is ASCII.
func Excerpt(h model.HiddenChars) string {
	var b strings.Builder
	noun := "code points"
	if h.Total == 1 {
		noun = "code point"
	}
	fmt.Fprintf(&b, "%d hidden %s: ", h.Total, noun)
	for i, run := range h.Runs {
		if i > 0 {
			b.WriteString("; ")
		}
		if class := Class(run.CodePoint); class == Tag {
			b.WriteString("tag characters (U+E0000-U+E007F)")
		} else {
			fmt.Fprintf(&b, "U+%04X (%s)", run.CodePoint, class)
		}
		fmt.Fprintf(&b, " at line %d, column %d", run.Line, run.Column)
		if run.Length > 1 {
			fmt.Fprintf(&b, ", %d in a row", run.Length)
		}
	}
	if more := h.RunCount - len(h.Runs); more > 0 {
		fmt.Fprintf(&b, "; %d more run(s)", more)
	}
	return b.String()
}
