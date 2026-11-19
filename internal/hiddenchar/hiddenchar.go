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
//
// CodeSpanJoiners counts the lines whose only hidden code point, counted
// or not, is a U+2060 that opens an inline code span (see
// codeSpanJoiner). That U+2060 is still counted in Total.
//
// LowShapes counts the counted code points that are one of these
// artifacts, each still in Total: a CodeSpanJoiners U+2060; a U+2060 that
// is the only hidden code point on its line, right after a list marker
// (see listJoiner), not counting a line-start U+2060; a single U+2060 at
// the start of a line (see lineStartJoiner); a joiner between a Latin word and a joining-script
// suffix (see latinSuffixJoiner); and a code point of an inline code
// span that holds only invisible characters (see codeSpanSample).
//
// Strong counts the counted code points that are a strong hiding signal:
// every tag character and bidi control, and every zero-width code point
// in a run of two or more counted code points, apart from a code point
// of an inline code span that holds only invisible characters. An
// isolated zero-width code point, a joiner, and a U+FEFF that are not in
// such a run are not strong, however many of them the file holds.
func Scan(b []byte) (model.HiddenChars, bool) {
	var out model.HiddenChars
	valid := true
	b, _ = bytes.CutPrefix(b, bom)
	line, col := 1, 1
	inRun, stored := false, false
	lineHidden, lineSpan, lineList, lineStarts := 0, false, false, 0
	runLen, runZW := 0, 0
	endRun := func() {
		if runLen >= 2 {
			out.Strong += runZW
		}
		runLen, runZW = 0, 0
	}
	endLine := func() {
		if lineHidden == 1 && lineSpan {
			out.CodeSpanJoiners++
			out.LowShapes++
		} else if lineHidden-lineStarts == 1 && lineList {
			out.LowShapes++
		}
		lineHidden, lineSpan, lineList, lineStarts = 0, false, false, 0
	}
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if Class(r) != "" {
			lineHidden++
		}
		switch {
		case r == utf8.RuneError && size == 1:
			valid = false
			inRun = false
			endRun()
		case r == '\n':
			endLine()
			endRun()
			line, col = line+1, 1
			inRun = false
			i += size
			continue
		case countedAt(b, i):
			low := false
			switch {
			case codeSpanJoiner(b, i, size):
				lineSpan = true
			case lineStartJoiner(b, i, size):
				lineStarts++
				out.LowShapes++
			case listJoiner(b, i, size):
				lineList = true
			case latinSuffixJoiner(b, i, size), codeSpanSample(b, i):
				out.LowShapes++
				low = true
			}
			if !inRun {
				endRun()
			}
			runLen++
			switch {
			case Class(r) != ZeroWidth:
				out.Strong++
			case !low:
				runZW++
			}
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
			endRun()
		}
		col++
		i += size
	}
	endLine()
	endRun()
	return out, valid
}

// codeSpanJoiner reports a U+2060 at i right after a single backtick
// that opens an inline code span, right before an ASCII letter or digit,
// with a closing backtick later on the same line, as some editors put
// one there to stop Markdown or MDX from autolinking the code. It is
// still counted; Scan reports it in CodeSpanJoiners so a rule can lower
// its severity. A U+2060 after a double backtick, inside or at the end
// of a span, before a space, a non-ASCII letter, or another hidden code
// point, or in prose is not this shape.
func codeSpanJoiner(b []byte, i, size int) bool {
	r, _ := utf8.DecodeRune(b[i:])
	if r != 0x2060 {
		return false
	}
	prev, psize := utf8.DecodeLastRune(b[:i])
	if psize == 0 || prev != '`' {
		return false
	}
	if pp, _ := utf8.DecodeLastRune(b[:i-psize]); pp == '`' {
		return false
	}
	rest := b[i+size:]
	if len(rest) == 0 || rest[0] >= 0x80 || !isASCIIAlnum(rest[0]) {
		return false
	}
	if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	return bytes.IndexByte(rest, '`') > 0
}

// listJoiner reports a U+2060 at i right after a list marker at the
// start of its line (optional indentation, then -, *, +, or one to nine
// digits and . or ), then spaces or tabs) and right before an ASCII
// letter or digit: the same editor artifact as codeSpanJoiner, written
// where a list item's text starts. A line-start U+2060 before the marker
// is allowed. Scan counts it as a low shape only when it is the only
// hidden code point on its line apart from that line-start U+2060. A U+2060 inside
// the item's text, before a space or another hidden code point, or
// after anything else is not this shape.
func listJoiner(b []byte, i, size int) bool {
	r, _ := utf8.DecodeRune(b[i:])
	if r != 0x2060 {
		return false
	}
	rest := b[i+size:]
	if len(rest) == 0 || !isASCIIAlnum(rest[0]) {
		return false
	}
	p := b[bytes.LastIndexByte(b[:i], '\n')+1 : i]
	p, _ = bytes.CutPrefix(p, []byte("\u2060"))
	p = bytes.TrimLeft(p, " \t")
	n := 0
	for n < len(p) && p[n] >= '0' && p[n] <= '9' {
		n++
	}
	switch {
	case n == 0 && len(p) > 0 && (p[0] == '-' || p[0] == '*' || p[0] == '+'):
		p = p[1:]
	case n > 0 && n <= 9 && n < len(p) && (p[n] == '.' || p[n] == ')'):
		p = p[n+1:]
	default:
		return false
	}
	return len(p) > 0 && len(bytes.TrimLeft(p, " \t")) == 0
}

// lineStartJoiner reports a U+2060 at i that is the first code point of
// its line and is not next to another hidden or invisible code point
// (see invisibleSample), as editors leave one at the start of a pasted
// paragraph or before a list marker. A run at the start of a line, and a
// tag character or bidi control there, are not this shape. A list item
// that starts with one may still have its list joiner (see listJoiner).
func lineStartJoiner(b []byte, i, size int) bool {
	r, _ := utf8.DecodeRune(b[i:])
	if r != 0x2060 || (i > 0 && b[i-1] != '\n') {
		return false
	}
	next, nsize := utf8.DecodeRune(b[i+size:])
	return nsize == 0 || Class(next) == "" && !invisibleSample(next)
}

// latinSuffixJoiner reports an isolated U+200C or U+200D at i between
// the end of a Latin word of at least two letters and a suffix of at
// least two letters or marks of a linguistic joining script, as
// localised text writes a native suffix on an English term (an
// Arabic-script plural or a Kannada case ending on "URL"). It splits no
// ASCII word. A one-letter Latin word, a one-letter suffix, a joiner
// inside a Latin word, a suffix of another script, and a run stay out of
// this shape.
func latinSuffixJoiner(b []byte, i, size int) bool {
	r, _ := utf8.DecodeRune(b[i:])
	if (r != 0x200C && r != 0x200D) || zeroWidthRun(b, i, size) {
		return false
	}
	latin := 0
	for j := i; j > 0 && latin < 2; {
		prev, psize := utf8.DecodeLastRune(b[:j])
		if !unicode.IsLetter(prev) || !unicode.Is(unicode.Latin, prev) {
			break
		}
		latin++
		j -= psize
	}
	if latin < 2 {
		return false
	}
	next, nsize := utf8.DecodeRune(b[i+size:])
	if nsize == 0 || !unicode.IsLetter(next) {
		return false
	}
	script := scriptOf(next, linguisticJoiningScripts)
	if script == nil {
		return false
	}
	after, asize := utf8.DecodeRune(b[i+size+nsize:])
	if asize == 0 || !unicode.Is(script, after) {
		return false
	}
	return unicode.IsLetter(after) || unicode.In(after, unicode.Mn, unicode.Mc)
}

// invisibleSample is a code point an inline code span may quote as a
// literal sample of invisible text: a zero-width code point or one of
// the invisible operators U+2061-U+2064. Bidi controls and tag
// characters are not.
func invisibleSample(r rune) bool {
	return Class(r) == ZeroWidth || r >= 0x2061 && r <= 0x2064
}

// codeSpanSample reports a hidden code point at i inside an inline code
// span that holds nothing but invisibleSample code points, at most 8 of
// them with none repeated, as documentation quotes the characters it is
// describing. The span opens with a single backtick that is an odd
// backtick on its line and closes with a single backtick. A span that
// also holds visible text, a longer or repeated span, a bidi control or
// tag character, and a double-backtick span are not this shape.
func codeSpanSample(b []byte, i int) bool {
	r, _ := utf8.DecodeRune(b[i:])
	if Class(r) != ZeroWidth {
		return false
	}
	start := i
	for start > 0 {
		prev, psize := utf8.DecodeLastRune(b[:start])
		if !invisibleSample(prev) {
			break
		}
		start -= psize
	}
	end := i
	for end < len(b) {
		next, nsize := utf8.DecodeRune(b[end:])
		if nsize == 0 || !invisibleSample(next) {
			break
		}
		end += nsize
	}
	if start == 0 || end >= len(b) || b[start-1] != '`' || b[end] != '`' {
		return false
	}
	if start >= 2 && b[start-2] == '`' || end+1 < len(b) && b[end+1] == '`' {
		return false
	}
	lineStart := bytes.LastIndexByte(b[:start], '\n') + 1
	if bytes.Count(b[lineStart:start], []byte{'`'})%2 != 1 {
		return false
	}
	var seen []rune
	for j := start; j < end; {
		c, csize := utf8.DecodeRune(b[j:])
		for _, s := range seen {
			if s == c {
				return false
			}
		}
		seen = append(seen, c)
		j += csize
	}
	return len(seen) <= 8
}

func isASCIIAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
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
// outside a strip literal, except an isolated U+FEFF between a sentence
// end and whitespace or a line end (see strayBOM).
//
// Some scripts use these characters as ordinary spelling, so an
// isolated one is also not counted inside a word of such a script (see
// scriptJoiner and scriptWordBreak): a U+200C or U+200D between two
// letters of the same joining script, or after a virama that ends a
// word, and a U+200B between two letters of the same script written
// without spaces. A character next to a letter of another script
// (apart from the virama shapes scriptJoiner describes), at a word edge
// in a script with no virama, or in any run stays counted.
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
	if zeroWidthRun(b, i, size) {
		return true
	}
	if r == 0xFEFF {
		return !strayBOM(b, i, size)
	}
	if r != 0x200B && r != 0x200C && r != 0x200D {
		return true
	}
	if quietSide(b, i, false) && quietSide(b, i+size, true) {
		return false
	}
	if r == 0x200B {
		return !scriptWordBreak(b, i, size)
	}
	return !scriptJoiner(b, i, size)
}

// sentenceEnds are the punctuation marks that end a sentence, including
// the ideographic full stop and the fullwidth exclamation and question
// marks.
var sentenceEnds = map[rune]bool{
	'.': true, '!': true, '?': true, 0x3002: true, 0xFF01: true, 0xFF1F: true,
}

// strayBOM reports a U+FEFF at i that text pasted from a word processor
// or a web page leaves behind: the code point before it ends a sentence
// and the code point after it is whitespace or the end of the file. It
// changes no word. A U+FEFF before a word, inside a word, at the start
// of a line, or next to another zero-width character stays counted.
func strayBOM(b []byte, i, size int) bool {
	prev, psize := utf8.DecodeLastRune(b[:i])
	if psize == 0 || !sentenceEnds[prev] {
		return false
	}
	next, nsize := utf8.DecodeRune(b[i+size:])
	if nsize == 0 {
		return true
	}
	if next == utf8.RuneError && nsize == 1 {
		return false
	}
	return unicode.IsSpace(next)
}

// maxMarks caps the combining marks lastLetter skips.
const maxMarks = 8

// joiningScripts write U+200C and U+200D inside words as ordinary
// spelling: Arabic-script text (Persian in particular) and Brahmic
// scripts, where the joiner after a virama selects a conjunct, half, or
// final form.
var joiningScripts = []*unicode.RangeTable{
	unicode.Arabic, unicode.Syriac, unicode.Nko, unicode.Mongolian,
	unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati,
	unicode.Oriya, unicode.Tamil, unicode.Telugu, unicode.Kannada,
	unicode.Malayalam, unicode.Sinhala, unicode.Myanmar, unicode.Khmer,
	unicode.Tibetan,
}

// noSpaceScripts are written without spaces between words; U+200B is
// the standard word separator there.
var noSpaceScripts = []*unicode.RangeTable{
	unicode.Thai, unicode.Lao, unicode.Khmer, unicode.Myanmar, unicode.Tibetan,
}

// viramas are the vowel-killing signs of the joining scripts (virama,
// halant, al-lakuna, asat, coeng, halanta).
var viramas = map[rune]bool{
	0x094D: true, 0x09CD: true, 0x0A4D: true, 0x0ACD: true, 0x0B4D: true,
	0x0BCD: true, 0x0C4D: true, 0x0CCD: true, 0x0D4D: true, 0x0DCA: true,
	0x1039: true, 0x103A: true, 0x17D2: true, 0x0F84: true,
}

// scriptJoiner reports a U+200C or U+200D at i that is spelling, not
// hidden content: the nearest letter before it (skipping at most
// maxMarks combining marks) is a letter of a joining script and the
// code point after it is a letter or combining mark of the same script
// (Marathi writes U+0905 U+200D U+0945, Bengali U+09B0 U+200D U+09CD),
// or the code point before it is a virama of a joining script on a
// letter of that script and the code point after it ends the word
// (whitespace, punctuation, or the end of the file).
//
// After a virama two more shapes are spelling. A letter of the
// virama's own script after the joiner is spelling when the virama sits
// on a letter of any joining script, as when text mixes two sibling
// Brahmic scripts in one word. And a letter of a script outside the
// joining scripts, with no Latin look-alikes (see viramaBeforeOtherScript),
// is spelling after a Brahmic or Sinhala virama on a letter of a
// linguistic joining script. A letter of another joining script, a
// Latin, Greek, Cyrillic, Armenian, or Cherokee letter, a digit, or a
// symbol after the joiner stays counted. Callers only get here for an
// isolated joiner: a run stays counted (see zeroWidthRun).
func scriptJoiner(b []byte, i, size int) bool {
	if sameScriptLetters(b, i, size, joiningScripts, true) {
		return true
	}
	v, vsize := utf8.DecodeLastRune(b[:i])
	if !viramas[v] {
		return false
	}
	script := scriptOf(v, joiningScripts)
	base, ok := lastLetter(b[:i-vsize])
	if script == nil || !ok {
		return false
	}
	next, nsize := utf8.DecodeRune(b[i+size:])
	if next == utf8.RuneError && nsize == 1 {
		return false
	}
	if unicode.Is(script, base) {
		if nsize == 0 || unicode.IsSpace(next) || unicode.IsPunct(next) {
			return true
		}
	}
	if nsize == 0 || !unicode.IsLetter(next) {
		return false
	}
	if unicode.Is(script, next) && scriptOf(base, joiningScripts) != nil {
		return true
	}
	return viramaBeforeOtherScript(v, base, next)
}

// linguisticViramas are the viramas of the Brahmic scripts of India
// and of Sinhala, where a joiner after the virama selects the form of a
// conjunct.
var linguisticViramas = map[rune]bool{
	0x094D: true, 0x09CD: true, 0x0A4D: true, 0x0ACD: true, 0x0B4D: true,
	0x0BCD: true, 0x0C4D: true, 0x0CCD: true, 0x0D4D: true, 0x0DCA: true,
}

// linguisticJoiningScripts write U+200C and U+200D as ordinary
// spelling: the Brahmic scripts of India, Arabic (including Persian),
// Syriac, Mongolian, and Sinhala.
var linguisticJoiningScripts = []*unicode.RangeTable{
	unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati,
	unicode.Oriya, unicode.Tamil, unicode.Telugu, unicode.Kannada,
	unicode.Malayalam, unicode.Arabic, unicode.Syriac, unicode.Mongolian,
	unicode.Sinhala,
}

// lookAlikeScripts have letters that pass for ASCII on screen, so a
// joiner before one of them can split a word a reviewer reads as
// ASCII.
var lookAlikeScripts = []*unicode.RangeTable{
	unicode.Latin, unicode.Greek, unicode.Cyrillic, unicode.Armenian,
	unicode.Cherokee, unicode.Common, unicode.Inherited,
}

// viramaBeforeOtherScript reports a joiner between a Brahmic or Sinhala
// virama v on a letter base of a linguistic joining script and a letter
// next of a script that is neither a joining script nor one with Latin
// look-alikes, such as Hangul or Han in a machine translation. It joins
// nothing that can hide or split ASCII text.
func viramaBeforeOtherScript(v, base, next rune) bool {
	if !linguisticViramas[v] || scriptOf(base, linguisticJoiningScripts) == nil {
		return false
	}
	return scriptOf(next, joiningScripts) == nil && scriptOf(next, lookAlikeScripts) == nil
}

// scriptWordBreak reports a U+200B at i between two letters of the same
// script written without spaces. Next to whitespace or punctuation, or
// next to a letter of another script, it stays counted.
func scriptWordBreak(b []byte, i, size int) bool {
	return sameScriptLetters(b, i, size, noSpaceScripts, false)
}

// sameScriptLetters reports that the nearest letter before i (skipping
// combining marks) and the code point right after the character at i
// are letters of one script in set. With mark, the code point after may
// also be a combining mark of that script; an Inherited mark is not.
func sameScriptLetters(b []byte, i, size int, set []*unicode.RangeTable, mark bool) bool {
	before, ok := lastLetter(b[:i])
	if !ok {
		return false
	}
	script := scriptOf(before, set)
	if script == nil {
		return false
	}
	after, asize := utf8.DecodeRune(b[i+size:])
	if asize == 0 || after == utf8.RuneError && asize == 1 {
		return false
	}
	if !unicode.Is(script, after) {
		return false
	}
	return unicode.IsLetter(after) || mark && unicode.In(after, unicode.Mn, unicode.Mc)
}

// lastLetter returns the last letter of b, skipping at most maxMarks
// combining marks (Mn, Mc) such as harakat, vowel signs, and viramas.
// Any other code point, or more marks, means there is no letter.
func lastLetter(b []byte) (rune, bool) {
	for n := 0; n <= maxMarks && len(b) > 0; n++ {
		r, size := utf8.DecodeLastRune(b)
		b = b[:len(b)-size]
		switch {
		case r == utf8.RuneError && size == 1:
			return 0, false
		case unicode.IsLetter(r):
			return r, true
		case !unicode.In(r, unicode.Mn, unicode.Mc):
			return 0, false
		}
	}
	return 0, false
}

func scriptOf(r rune, set []*unicode.RangeTable) *unicode.RangeTable {
	for _, t := range set {
		if unicode.Is(t, r) {
			return t
		}
	}
	return nil
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
