// Package hiddenchar finds code points that change what text says
// without showing on screen: Unicode bidirectional controls, which
// reorder what a reviewer sees, tag characters, which spell ASCII text
// that renders as nothing, and zero-width characters. An agent reads all
// of them. It reports where each run of them starts and its first code
// point, never the text, so a finding cannot carry the hidden
// instruction.
package hiddenchar

//go:generate go run ./gen -data gen/emoji-data.txt -out pictographic.go

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"unicode"
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
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			valid = false
			inRun = false
		case r == '\n':
			line, col = line+1, 1
			inRun = false
			i += size
			continue
		case countedAt(b, i):
			out.Total++
			out.Sequence = append(out.Sequence, r)
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
		i += size
	}
	return out, valid
}

// countedAt reports a hidden code point. U+200D is not counted inside an
// emoji ZWJ sequence: the code points around it, skipping U+FE0F and
// skin tones U+1F3FB-U+1F3FF, are both Extended_Pictographic.
//
// An isolated U+200B, U+200C, or U+200D is not counted only when both
// neighbors are whitespace, a line boundary, or the edge of a quote or
// a code fence. A strip literal is also not counted: a quoted string or
// bracket class made only of zero-width characters, at most 8 of them,
// with no code point repeated. A longer run or a repeated code point
// stays counted, including inside quotes or brackets. A character next
// to punctuation, after a dot, before a word, or at the end of a word
// stays counted, as do tags, bidi controls, and U+2060 or U+FEFF
// outside a strip literal.
func countedAt(b []byte, i int) bool {
	r, size := utf8.DecodeRune(b[i:])
	if Class(r) == "" {
		return false
	}
	if r == 0x200D && emojiJoiner(b, i, size) {
		return false
	}
	if Class(r) != ZeroWidth {
		return true
	}
	if stripLiteral(b, i) {
		return false
	}
	if r != 0x200B && r != 0x200C && r != 0x200D {
		return true
	}
	if zeroWidthRun(b, i, size) {
		return true
	}
	return !quietSide(b, i, false) || !quietSide(b, i+size, true)
}

func emojiJoiner(b []byte, i, size int) bool {
	before := pictographic(skipEmojiMods(b[:i], false))
	after := pictographic(skipEmojiMods(b[i+size:], true))
	return before && after
}

// stripLiteral reports a zero-width character written as a short list of
// distinct characters to strip: the quoted string or bracket class that
// holds it contains only zero-width characters, at most 8, with no code
// point repeated.
func stripLiteral(b []byte, i int) bool {
	return quotedStrip(b, i) || stripClass(b, i)
}

func quotedStrip(b []byte, i int) bool {
	start, end := zwSpan(b, i)
	prev, psize := utf8.DecodeLastRune(b[:start])
	next, nsize := utf8.DecodeRune(b[end:])
	if psize == 0 || nsize == 0 || prev != next {
		return false
	}
	if prev != '"' && prev != '\'' && prev != '`' {
		return false
	}
	return distinctStrip(b[start:end])
}

// distinctStrip reports a span of at most 8 zero-width code points with
// no repeated code point. A longer span or a repeated code point is a
// run, not a list of characters to strip.
func distinctStrip(span []byte) bool {
	var seen []rune
	for j := 0; j < len(span); {
		r, size := utf8.DecodeRune(span[j:])
		if size == 0 || Class(r) != ZeroWidth {
			return false
		}
		for _, prev := range seen {
			if prev == r {
				return false
			}
		}
		seen = append(seen, r)
		if len(seen) > 8 {
			return false
		}
		j += size
	}
	return len(seen) > 0
}

// zwSpan is the byte range of the zero-width run that contains i.
func zwSpan(b []byte, i int) (start, end int) {
	start = i
	for start > 0 {
		r, size := utf8.DecodeLastRune(b[:start])
		if size == 0 || Class(r) != ZeroWidth {
			break
		}
		start -= size
	}
	end = i
	for end < len(b) {
		r, size := utf8.DecodeRune(b[end:])
		if size == 0 || Class(r) != ZeroWidth {
			break
		}
		end += size
	}
	return start, end
}

// stripClass reports whether i sits in a [...] class on this line whose
// contents are only zero-width characters. A class that also holds
// letters is a word or a markdown link, and the character stays counted.
func stripClass(b []byte, i int) bool {
	lineStart := bytes.LastIndexByte(b[:i], '\n') + 1
	lineEnd := len(b)
	if rel := bytes.IndexByte(b[i:], '\n'); rel >= 0 {
		lineEnd = i + rel
	}
	openRel := bytes.LastIndexByte(b[lineStart:i], '[')
	if openRel < 0 {
		return false
	}
	open := lineStart + openRel
	if bytes.Contains(b[open+1:i], []byte{']'}) {
		return false
	}
	closeRel := bytes.IndexByte(b[i:lineEnd], ']')
	if closeRel < 0 {
		return false
	}
	return distinctStrip(b[open+1 : i+closeRel])
}

// zeroWidthRun reports a neighbor that is itself a zero-width character.
// A run stays counted unless the whole run is a strip literal.
func zeroWidthRun(b []byte, i, size int) bool {
	prev, psize := utf8.DecodeLastRune(b[:i])
	if psize > 0 && Class(prev) == ZeroWidth {
		return true
	}
	next, nsize := utf8.DecodeRune(b[i+size:])
	return nsize > 0 && Class(next) == ZeroWidth
}

// quietSide reports a neighbor that is whitespace, a line boundary, a
// quote, or the edge of a code fence (three or more ` or ~). forward
// reads the rune at i; otherwise it reads the rune that ends at i.
func quietSide(b []byte, i int, forward bool) bool {
	var r rune
	var size int
	if forward {
		if i >= len(b) {
			return true
		}
		r, size = utf8.DecodeRune(b[i:])
	} else {
		if i <= 0 {
			return true
		}
		r, size = utf8.DecodeLastRune(b[:i])
	}
	if r == utf8.RuneError && size == 1 {
		return false
	}
	if unicode.IsSpace(r) || r == '"' || r == '\'' {
		return true
	}
	if r != '`' && r != '~' {
		return false
	}
	return fenceRun(b, i, r, forward) >= 3
}

func fenceRun(b []byte, i int, marker rune, forward bool) int {
	n := 0
	if forward {
		for j := i; j < len(b); {
			r, size := utf8.DecodeRune(b[j:])
			if r != marker {
				break
			}
			n++
			j += size
		}
		return n
	}
	for j := i; j > 0; {
		r, size := utf8.DecodeLastRune(b[:j])
		if r != marker {
			break
		}
		n++
		j -= size
	}
	return n
}

func skipEmojiMods(b []byte, forward bool) rune {
	for len(b) > 0 {
		var r rune
		var size int
		if forward {
			r, size = utf8.DecodeRune(b)
			b = b[size:]
		} else {
			r, size = utf8.DecodeLastRune(b)
			b = b[:len(b)-size]
		}
		if r == 0xFE0F || r >= 0x1F3FB && r <= 0x1F3FF {
			continue
		}
		return r
	}
	return utf8.RuneError
}

func pictographic(r rune) bool {
	lo, hi := 0, len(extendedPictographicRanges)/2
	for lo < hi {
		mid := (lo + hi) / 2
		start, end := extendedPictographicRanges[mid*2], extendedPictographicRanges[mid*2+1]
		switch {
		case r < start:
			hi = mid
		case r > end:
			lo = mid + 1
		default:
			return true
		}
	}
	return false
}

// FingerprintKey is a safe representation of a hidden-code-point sequence
// and its ordinal within the file. It never includes the hidden text or
// presentation coordinates.
func FingerprintKey(h model.HiddenChars, ordinal int) string {
	var b strings.Builder
	for _, r := range h.Sequence {
		fmt.Fprintf(&b, "%X,", r)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("hidden_chars/%d/%s", ordinal, hex.EncodeToString(sum[:8]))
}

// InstructionPath reports whether rel is one of the files TC-CFG-011
// reads, including nested .claude/rules, .cursor/rules, and
// .windsurfrules, and a repository skill at .claude/skills/<name>/SKILL.md,
// .agents/skills/<name>/SKILL.md, or .github/skills/<name>/SKILL.md.
// <name> is at least one character. docs/SKILL.md and a plugin skills/
// directory are not included. The test is the rule's path expression:
// every alternative is matched to the end of the path.
func InstructionPath(rel string) bool {
	p := strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "./"))
	base := path.Base(p)
	switch base {
	case "agents.md", "agents.local.md", "claude.md", "claude.local.md", "gemini.md", "gemini.local.md", ".windsurfrules":
		return true
	}
	if p == ".cursorrules" || p == ".github/copilot-instructions.md" || p == ".devin/blueprint.yaml" || strings.HasSuffix(p, "/.devin/blueprint.yaml") {
		return true
	}
	if under(p, ".claude/rules/") && strings.HasSuffix(p, ".md") {
		return true
	}
	if under(p, ".cursor/rules/") && (strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".mdc")) {
		return true
	}
	if skillInstructionPath(p) {
		return true
	}
	if strings.HasPrefix(p, ".github/instructions/") && strings.HasSuffix(p, ".md") && path.Base(p) != ".md" {
		return true
	}
	return strings.HasPrefix(p, ".github/agents/") && strings.HasSuffix(p, ".agent.md") && len(path.Base(p)) > len(".agent.md")
}

// skillInstructionPath matches TC-CFG-012's three skill directories and
// no others. The name segment is the regex's `.+` before /SKILL.md.
func skillInstructionPath(p string) bool {
	const file = "/skill.md"
	for _, root := range []string{".claude/skills/", ".agents/skills/", ".github/skills/"} {
		start := 0
		for start < len(p) {
			i := strings.Index(p[start:], root)
			if i < 0 {
				break
			}
			i += start
			if i == 0 || p[i-1] == '/' {
				rest := p[i+len(root):]
				if len(rest) > len(file) && strings.HasSuffix(rest, file) {
					return true
				}
			}
			start = i + 1
		}
	}
	return false
}

// InstructionFile reports whether a markdown item of this scope and
// kind at rel is a file TC-CFG-011 reads, so an invalid UTF-8
// diagnostic follows the rule. The rule requires repository scope, so
// a user or managed file is not one, even when its path matches. A
// skill counts only when InstructionPath does.
func InstructionFile(scope model.Scope, kind model.ConfigKind, rel string) bool {
	if scope != model.ScopeRepo {
		return false
	}
	switch kind {
	case model.ConfigKindInstructions, model.ConfigKindSkill:
		return InstructionPath(rel)
	default:
		return false
	}
}

func under(path, dir string) bool {
	return strings.HasPrefix(path, dir) || strings.Contains(path, "/"+dir)
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
