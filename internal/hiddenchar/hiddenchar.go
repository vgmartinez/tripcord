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
func countedAt(b []byte, i int) bool {
	r, size := utf8.DecodeRune(b[i:])
	if Class(r) == "" {
		return false
	}
	if r != 0x200D {
		return true
	}
	before := pictographic(skipEmojiMods(b[:i], false))
	after := pictographic(skipEmojiMods(b[i+size:], true))
	return !before || !after
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
