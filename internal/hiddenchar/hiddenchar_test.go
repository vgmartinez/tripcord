package hiddenchar

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/model"
)

func run(r rune, line, col, n int) model.HiddenRun {
	return model.HiddenRun{CodePoint: r, Line: line, Column: col, Length: n}
}

func TestScan(t *testing.T) {
	var alt strings.Builder
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			alt.WriteRune('\u200B')
		} else {
			alt.WriteRune('\u200C')
		}
	}
	stego := alt.String()
	cases := []struct {
		name  string
		in    string
		runs  []model.HiddenRun
		count int
		total int
		valid bool
	}{
		{"plain", "# Rules\n\nBe nice.\n", nil, 0, 0, true},
		{"leading BOM", "\uFEFF# Rules\n", nil, 0, 0, true},
		{"BOM column", "\uFEFFa\u202Eb", []model.HiddenRun{run(0x202E, 1, 2, 1)}, 1, 1, true},
		{"BOM later", "a\uFEFF", []model.HiddenRun{run(0xFEFF, 1, 2, 1)}, 1, 1, true},
		{"second BOM", "\uFEFF\uFEFF", []model.HiddenRun{run(0xFEFF, 1, 1, 1)}, 1, 1, true},
		{"bidi", "x\n  if a \u202E b\n", []model.HiddenRun{run(0x202E, 2, 8, 1)}, 1, 1, true},
		{"isolates", "\u2066\u2067\u2068\u2069", []model.HiddenRun{run(0x2066, 1, 1, 4)}, 1, 4, true},
		{"zero-width run", "a\u200B\u200C\u200D\u2060b", []model.HiddenRun{run(0x200B, 1, 2, 4)}, 1, 4, true},
		{"emoji ZWJ sequence", "👨\u200D👩", nil, 0, 0, true},
		{"emoji with FE0F", "❤\uFE0F\u200D🔥", nil, 0, 0, true},
		{"black cat", "🐈\u200D⬛", nil, 0, 0, true},
		{"ZWJ beside ASCII", "a\u200Db", []model.HiddenRun{run(0x200D, 1, 2, 1)}, 1, 1, true},
		{"lone ZWJ", "\u200D", nil, 0, 0, true},
		{"word split", "ign\u200Bore", []model.HiddenRun{run(0x200B, 1, 4, 1)}, 1, 1, true},
		{"end of word", "ok\u200B", []model.HiddenRun{run(0x200B, 1, 3, 1)}, 1, 1, true},
		{"after dot", ".\u200Benv", []model.HiddenRun{run(0x200B, 1, 2, 1)}, 1, 1, true},
		{"before dot", "evil\u200B.com", []model.HiddenRun{run(0x200B, 1, 5, 1)}, 1, 1, true},
		{"before a word", " \u200Btabs", []model.HiddenRun{run(0x200B, 1, 2, 1)}, 1, 1, true},
		{"next to punctuation", "see\u200B, note", []model.HiddenRun{run(0x200B, 1, 4, 1)}, 1, 1, true},
		{"isolated ZWSP", "a \u200B b", nil, 0, 0, true},
		{"placeholder ZWSP", "item-\u2026\u200B.yaml", []model.HiddenRun{run(0x200B, 1, 7, 1)}, 1, 1, true},
		{"fence ZWSP", "\n\u200B```\n", nil, 0, 0, true},
		{"single backtick", "\n\u200B`\n", []model.HiddenRun{run(0x200B, 2, 1, 1)}, 1, 1, true},
		{"quoted literals", "\"\u200B\" '\u200C' `\u200D` \"\uFEFF\"", nil, 0, 0, true},
		{"strip class", "[\u200B\u200C\u200D]", nil, 0, 0, true},
		{"quoted repeat", "\"\u200B\u200B\"", []model.HiddenRun{run(0x200B, 1, 2, 2)}, 1, 2, true},
		{"quoted stego", "note: \"" + stego + "\" end", []model.HiddenRun{run(0x200B, 1, 8, 200)}, 1, 200, true},
		{"bracket stego", "[" + stego + "]", []model.HiddenRun{run(0x200B, 1, 2, 200)}, 1, 200, true},
		{"strip class escape", "[\\u200b\uFEFF]", []model.HiddenRun{run(0xFEFF, 1, 8, 1)}, 1, 1, true},
		{"in-word quoted", "\"a\u200Bb\"", []model.HiddenRun{run(0x200B, 1, 3, 1)}, 1, 1, true},
		{"class with a word", "[ign\u200Bore]", []model.HiddenRun{run(0x200B, 1, 5, 1)}, 1, 1, true},
		{"zero-width run outside a word", " \u200B\u200B ", []model.HiddenRun{run(0x200B, 1, 2, 2)}, 1, 2, true},
		{"word joiner in prose", " \u2060 ", []model.HiddenRun{run(0x2060, 1, 2, 1)}, 1, 1, true},
		{"tags", "ok\U000E0069\U000E0067\U000E006E\n", []model.HiddenRun{run(0xE0069, 1, 3, 3)}, 1, 3, true},
		{"crlf", "a\r\n\u202Ab", []model.HiddenRun{run(0x202A, 2, 1, 1)}, 1, 1, true},
		{"newline exempts isolated", "\u200B\n\u200B", nil, 0, 0, true},
		{"newline keeps in-word", "a\u200Bb\na\u200Bb", []model.HiddenRun{run(0x200B, 1, 2, 1), run(0x200B, 2, 2, 1)}, 2, 2, true},
		{"multibyte columns", "é漢\u202B", []model.HiddenRun{run(0x202B, 1, 3, 1)}, 1, 1, true},
		{"not hidden", "\u200E\u200F\u061C\u00AD", nil, 0, 0, true},
		{"escape text", "\\u200b", nil, 0, 0, true},
		{"invalid", "a\xff\u202Cb", []model.HiddenRun{run(0x202C, 1, 3, 1)}, 1, 1, false},
		{"invalid ends run", "\u2060\xff\u2060", []model.HiddenRun{run(0x2060, 1, 1, 1), run(0x2060, 1, 3, 1)}, 2, 2, false},
		{"cap", strings.Repeat("a\u200Bb", MaxRuns+2), []model.HiddenRun{
			run(0x200B, 1, 2, 1), run(0x200B, 1, 5, 1), run(0x200B, 1, 8, 1), run(0x200B, 1, 11, 1), run(0x200B, 1, 14, 1),
		}, MaxRuns + 2, MaxRuns + 2, true},
	}
	for _, tc := range cases {
		got, valid := Scan([]byte(tc.in))
		if !slices.Equal(got.Runs, tc.runs) || got.RunCount != tc.count || got.Total != tc.total || valid != tc.valid {
			t.Errorf("%s: Scan = %+v, %v; want runs %+v, count %d, total %d, valid %v", tc.name, got, valid, tc.runs, tc.count, tc.total, tc.valid)
		}
	}
}

// TestScanScriptJoiners covers U+200C/U+200D as spelling in joining
// scripts and U+200B as the word separator in scripts written without
// spaces, and the cases that stay counted. counted is the number of
// counted code points; each one here is isolated.
func TestScanScriptJoiners(t *testing.T) {
	marks := strings.Repeat("\u064E", maxMarks)
	cases := []struct {
		name    string
		in      string
		counted int
	}{
		// Not counted.
		{"Persian ZWNJ in a word", "\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645", 0},
		{"Arabic ZWNJ after a haraka", "\u0628\u064E\u200C\u0647\u0627", 0},
		{"ZWNJ after the mark cap", "\u0628" + marks + "\u200C\u0647", 0},
		{"Devanagari ZWJ after virama", "\u0915\u094D\u200D\u0937", 0},
		{"Devanagari ZWNJ after virama", "\u0915\u094D\u200C\u0937", 0},
		{"Devanagari eyelash ra", "\u0930\u200D\u092F", 0},
		{"Kannada ZWNJ in a word", "\u0CB2\u0CCD\u200C\u0C97", 0},
		{"Sinhala yansaya", "\u0D9A\u0DCA\u200D\u0DBA", 0},
		{"Malayalam chillu before a space", "\u0D28\u0D4D\u200D \u0D35", 0},
		{"Malayalam chillu before punctuation", "\u0D32\u0D4D\u200D, x", 0},
		{"Malayalam chillu at the end", "\u0D28\u0D4D\u200D", 0},
		{"Malayalam chillu at a line end", "\u0D28\u0D4D\u200D\nx", 0},
		{"Khmer coeng ZWNJ", "\u179F\u17D2\u200C\u178F", 0},
		{"Marathi ZWJ before a vowel sign", "\u0905\u200D\u0945\u092A", 0},
		{"Bengali ZWJ before virama", "\u09B0\u200D\u09CD\u09AF", 0},
		{"Thai ZWSP word break", "\u0E01\u0E23\u0E38\u0E13\u0E32\u200B\u0E23\u0E31\u0E19", 0},
		{"Khmer ZWSP after a vowel sign", "\u179F\u17BC\u1798\u200B\u178A", 0},
		{"Myanmar ZWSP after asat", "\u1004\u103A\u200B\u1019", 0},
		{"Lao ZWSP", "\u0E81\u200B\u0E82", 0},
		{"Tibetan ZWSP", "\u0F40\u200B\u0F41", 0},
		{"Kannada virama on a Gujarati letter before Kannada", "\u0A9C\u0CCD\u200C\u0CB2\u0CBE", 0},
		{"Kannada virama before Hangul", "\u0CAA\u0CCD\u200C\uC2A4", 0},
		{"Devanagari virama ZWJ before Han", "\u0915\u094D\u200D\u5B57", 0},
		{"Sinhala virama before Hiragana", "\u0D9A\u0DCA\u200C\u3042", 0},

		// Counted.
		{"Latin word split", "stan\u200Cdard", 1},
		{"ZWNJ between Latin and Arabic", "a\u200C\u0628", 1},
		{"ZWNJ between Arabic and Latin", "\u0628\u200Ca", 1},
		{"ZWJ between Persian and ASCII", "\u0644\u200Da", 1},
		{"ZWNJ between two scripts", "\u0915\u094D\u200C\u0CB2", 1},
		{"Persian ZWNJ before a space", "\u0628\u200C \u0627", 1},
		{"Persian ZWNJ before punctuation", "\u0628\u200C.", 1},
		{"Persian ZWNJ before a digit", "\u0628\u200C1", 1},
		{"Persian ZWNJ after a space", "x \u200C\u0628", 1},
		{"mark-only neighbor", "\u064E\u200C\u0647", 1},
		{"ZWJ before an Inherited mark", "\u0628\u200D\u0301", 1},
		{"ZWJ before a mark of another script", "\u0915\u200D\u0CCD", 1},
		{"ZWJ between a Latin letter and a Devanagari sign", "a\u200D\u0945", 1},
		{"mark cap exceeded", "\u0628" + marks + "\u064E\u200C\u0647", 1},
		{"Persian ZWSP", "\u0645\u06CC\u200B\u062E", 1},
		{"Devanagari ZWSP", "\u0915\u200B\u0937", 1},
		{"Thai ZWSP before a space", "\u0E01\u200B \u0E23", 1},
		{"Thai ZWSP before punctuation", "\u0E01\u200B.", 1},
		{"Thai ZWSP before Latin", "\u0E01\u200Bignore", 1},
		{"Thai ZWNJ in a word", "\u0E01\u200C\u0E23", 1},
		{"Thai ZWSP before a mark", "\u0E01\u200B\u0E31", 1},
		{"virama ZWNJ before Latin", "\u0915\u094D\u200Cenv", 1},
		{"virama ZWNJ before a digit", "\u0915\u094D\u200C1", 1},
		{"virama with no base letter", " \u094D\u200C ", 1},
		{"virama on a letter of another script", "a\u094D\u200C ", 1},
		{"word joiner in Persian", "\u0628\u2060\u0647", 1},
		{"inner BOM in Persian", "\u0628\uFEFF\u0647", 1},
		{"Persian run", "\u0645\u06CC\u200C\u200C\u062E", 2},
		{"Thai ZWSP run", "\u0E01\u200B\u200B\u0E23", 2},
		{"Devanagari doubled ZWNJ", "\u0915\u094D\u200C\u200C\u0937", 2},
		{"Devanagari virama on Latin before Devanagari", "a\u094D\u200C\u0915", 1},
		{"virama on Latin before Hangul", "a\u094D\u200C\uC2A4", 1},
		{"virama ZWNJ before Greek", "\u0915\u094D\u200C\u03B1", 1},
		{"virama ZWNJ before Cyrillic", "\u0915\u094D\u200C\u0435nv", 1},
		{"virama ZWNJ before Armenian", "\u0915\u094D\u200C\u0585", 1},
		{"virama ZWNJ before a fullwidth Latin letter", "\u0915\u094D\u200C\uFF45nv", 1},
		{"virama ZWNJ before a math letter", "\u0915\u094D\u200C\U0001D41E", 1},
		{"virama ZWNJ before a symbol", "\u0CAA\u0CCD\u200C\u2603", 1},
		{"Khmer coeng before Hangul", "\u179F\u17D2\u200C\uC2A4", 1},
		{"Persian ZWNJ before Hangul", "\u0628\u200C\uC2A4", 1},
		{"virama doubled ZWNJ before Hangul", "\u0CAA\u0CCD\u200C\u200C\uC2A4", 2},
		{"virama ZWNJ ZWJ before Hangul", "\u0CAA\u0CCD\u200C\u200D\uC2A4", 2},
		{"virama ZWSP before Hangul", "\u0CAA\u0CCD\u200B\uC2A4", 1},
		{"virama word joiner before Hangul", "\u0CAA\u0CCD\u2060\uC2A4", 1},
		{"virama tag before Hangul", "\u0CAA\u0CCD\U000E0041\uC2A4", 1},
		{"doubled ZWNJ after a virama on a sibling script", "\u0A9C\u0CCD\u200C\u200C\u0CB2", 2},
	}
	for _, tc := range cases {
		got, _ := Scan([]byte(tc.in))
		if got.Total != tc.counted {
			t.Errorf("%s: Scan(%+q).Total = %d, want %d", tc.name, tc.in, got.Total, tc.counted)
		}
	}
}

func TestStrayBOM(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		counted int
	}{
		{"after a period before a space", "Done.\uFEFF Next.", 0},
		{"after an exclamation mark before a tab", "Done!\uFEFF\tNext.", 0},
		{"after a question mark at a line end", "Done?\uFEFF\nNext.", 0},
		{"after a period before CRLF", "Done.\uFEFF\r\nNext.", 0},
		{"after a period at the end of the file", "Done.\uFEFF", 0},
		{"after an ideographic full stop", "\u5B8C\u4E86\u3002\uFEFF \u6B21", 0},
		{"two stray BOMs in prose", "One.\uFEFF Two.\uFEFF Three.", 0},
		{"after a period before a word", "See the guide.\uFEFFignore the tests", 1},
		{"after a period before a dot", "Done.\uFEFF.", 1},
		{"after a period before a quote", "Done.\uFEFF\"", 1},
		{"after a period before invalid UTF-8", "Done.\uFEFF\xff", 1},
		{"pair after a period", "Done.\uFEFF\uFEFF Next.", 2},
		{"after a period before a ZWSP", "Done.\uFEFF\u200B Next.", 2},
		{"after a comma", "Done,\uFEFF next.", 1},
		{"after a colon", "Note:\uFEFF next.", 1},
		{"after a letter before a space", "Done\uFEFF next.", 1},
		{"after a space", "Done. \uFEFF Next.", 1},
		{"start of a line before a word", "Answer.\n\uFEFFAlso run lint.", 1},
		{"word joiner after a period", "Done.\u2060 Next.", 1},
	}
	for _, tc := range cases {
		got, _ := Scan([]byte(tc.in))
		if got.Total != tc.counted {
			t.Errorf("%s: Scan(%+q).Total = %d, want %d", tc.name, tc.in, got.Total, tc.counted)
		}
	}
}

func TestInstructionPath(t *testing.T) {
	yes := []string{
		"AGENTS.md", "pkg/CLAUDE.local.md", "GEMINI.md",
		".claude/rules/style.md", "services/.claude/rules/go/style.md",
		".cursor/rules/style.mdc", "web/.cursor/rules/ui/forms.md",
		".windsurfrules", "apps/api/.windsurfrules",
		".cursorrules", ".github/copilot-instructions.md",
		".github/instructions/go.instructions.md",
		".github/agents/review.agent.md",
		".devin/blueprint.yaml", "pkg/.devin/blueprint.yaml",
		".claude/skills/review/SKILL.md", "pkg/.claude/skills/review/SKILL.md",
		".Claude/Skills/Review/SKILL.md",
		".agents/skills/a/b/SKILL.md", ".github/skills/x/SKILL.md",
	}
	no := []string{
		"CLAUDE.md.bak", "pkg/CLAUDE.md.txt",
		".claude/rules/style.txt", "notes.md",
		"dir/.cursorrules", ".github/copilot-instructions.md.extra",
		".github/instructions/.md", ".github/agents/review.md",
		".cursor/rules/style.mdc.bak",
		".devin/blueprint.yml", ".devin/hooks.json",
		"docs/SKILL.md", "skills/SKILL.md", "skills/review/SKILL.md",
		".claude/skills/SKILL.md", ".claude/skills/review/skill.md.txt",
		"tools/vgmartinez/skills/review/SKILL.md", "not.claude/skills/review/SKILL.md",
	}
	for _, rel := range yes {
		if !InstructionPath(rel) {
			t.Errorf("InstructionPath(%q) = false", rel)
		}
	}
	for _, rel := range no {
		if InstructionPath(rel) {
			t.Errorf("InstructionPath(%q) = true", rel)
		}
	}
}

func TestInstructionFileRequiresRepoScope(t *testing.T) {
	if !InstructionFile(model.ScopeRepo, model.ConfigKindInstructions, "CLAUDE.md") {
		t.Error("repo CLAUDE.md")
	}
	if !InstructionFile(model.ScopeRepo, model.ConfigKindSkill, ".claude/skills/x/SKILL.md") {
		t.Error("repo skill")
	}
	if !InstructionFile(model.ScopeRepo, model.ConfigKindSkill, ".agents/skills/x/SKILL.md") {
		t.Error("repo agents skill")
	}
	quiet := []struct {
		scope model.Scope
		kind  model.ConfigKind
		path  string
	}{
		{model.ScopeUser, model.ConfigKindSkill, "~/.claude/skills/x/SKILL.md"},
		{model.ScopeUser, model.ConfigKindSkill, "~/.agents/skills/x/SKILL.md"},
		{model.ScopeUser, model.ConfigKindInstructions, "~/.claude/CLAUDE.md"},
		{model.ScopeUser, model.ConfigKindInstructions, "~/.gemini/GEMINI.md"},
		{model.ScopeUser, model.ConfigKindInstructions, "~/.codex/AGENTS.md"},
		{model.ScopeManaged, model.ConfigKindInstructions, "CLAUDE.md"},
		{model.ScopeRepo, model.ConfigKindHook, "AGENTS.md"},
		{model.ScopeRepo, model.ConfigKindSkill, "docs/SKILL.md"},
	}
	for _, tc := range quiet {
		if InstructionFile(tc.scope, tc.kind, tc.path) {
			t.Errorf("InstructionFile(%s, %s, %q) = true", tc.scope, tc.kind, tc.path)
		}
	}
}

func TestExcerpt(t *testing.T) {
	cases := map[string]string{
		"a\u202Eb":                     "1 hidden code point: U+202E (bidi control) at line 1, column 2",
		"\n\u200B\u200B\u200B":         "3 hidden code points: U+200B (zero-width) at line 2, column 1, 3 in a row",
		"x\U000E0069\U000E0067":        "2 hidden code points: tag characters (U+E0000-U+E007F) at line 1, column 2, 2 in a row",
		"\u202E\U000E0041":             "2 hidden code points: U+202E (bidi control) at line 1, column 1, 2 in a row",
		strings.Repeat("\u2060 ", 7):   "7 hidden code points: U+2060 (zero-width) at line 1, column 1; U+2060 (zero-width) at line 1, column 3; U+2060 (zero-width) at line 1, column 5; U+2060 (zero-width) at line 1, column 7; U+2060 (zero-width) at line 1, column 9; 2 more run(s)",
		"plain":                        "0 hidden code points: ",
		"\uFEFFlead\uFEFF":             "1 hidden code point: U+FEFF (zero-width) at line 1, column 5",
		"y\u2066\u2069":                "2 hidden code points: U+2066 (bidi control) at line 1, column 2, 2 in a row",
		"tag\U000E0001\U000E007F\nend": "2 hidden code points: tag characters (U+E0000-U+E007F) at line 1, column 4, 2 in a row",
	}
	for in, want := range cases {
		h, _ := Scan([]byte(in))
		if got := Excerpt(h); got != want {
			t.Errorf("Excerpt(%q) = %q, want %q", in, got, want)
		}
	}
}

// reference is a second reading of b, split into lines first: every
// hidden code point with its line and column.
type point struct {
	r         rune
	line, col int
}

func reference(b []byte) (points []point, valid bool) {
	valid = true
	b = bytes.TrimPrefix(b, bom)
	for i, line := range bytes.Split(b, []byte("\n")) {
		col := 1
		for off := 0; off < len(line); {
			r, size := utf8.DecodeRune(line[off:])
			if r == utf8.RuneError && size == 1 {
				valid = false
			}
			if countedAt(line, off) {
				points = append(points, point{r, i + 1, col})
			}
			off += size
			col++
		}
	}
	return points, valid
}

func FuzzScan(f *testing.F) {
	for _, seed := range []string{
		"# AGENTS\n\nRun tests.\n",
		"\uFEFFa\u202Eb\r\n\u2066x\u2069",
		"ignore\U000E0069\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065",
		"\u200B\u200C\u200D\u2060\uFEFF\xff\u200B",
		"\xef\xbb",
		strings.Repeat("\u200Bz\n", 20),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, valid := Scan(b)
		want, wantValid := reference(b)
		if valid != wantValid || valid != utf8.Valid(bytes.TrimPrefix(b, bom)) {
			t.Fatalf("valid = %v, reference %v", valid, wantValid)
		}
		if got.Total != len(want) || len(got.Runs) > MaxRuns || got.RunCount < len(got.Runs) || got.RunCount > got.Total {
			t.Fatalf("Scan = %+v, reference has %d points", got, len(want))
		}
		// Every located run starts at a reference point, in order, and
		// its length never runs past the points that follow it.
		next := 0
		for _, r := range got.Runs {
			for next < len(want) && (want[next].line != r.Line || want[next].col != r.Column) {
				next++
			}
			if next == len(want) || want[next].r != r.CodePoint || r.Length < 1 || next+r.Length > len(want) {
				t.Fatalf("run %+v not in reference %+v", r, want)
			}
			next += r.Length
		}
		excerpt := Excerpt(got)
		for i := 0; i < len(excerpt); i++ {
			if excerpt[i] >= utf8.RuneSelf {
				t.Fatalf("excerpt is not ASCII: %q", excerpt)
			}
		}
		if strings.Contains(strings.ReplaceAll(excerpt, "(U+E0000-U+E007F)", ""), "U+E00") {
			t.Fatalf("excerpt names a tag code point: %q", excerpt)
		}
	})
}

func TestCodeSpanJoiners(t *testing.T) {
	cases := []struct {
		name          string
		in            string
		counted, span int
	}{
		{"opening a code span", "Define `\u2060jobs.define()` first.", 1, 1},
		{"opening a code span before a digit", "Use `\u20602026` as the year.", 1, 1},
		{"one per line on two lines", "`\u2060a()`\n`\u2060b()`\n", 2, 2},
		{"after a double backtick", "``\u2060x``", 1, 0},
		{"before a space", "`\u2060 x`", 1, 0},
		{"before a non-ASCII letter", "`\u2060\u0430pi`", 1, 0},
		{"no closing backtick", "`\u2060jobs.define()", 1, 0},
		{"closing backtick on the next line", "`\u2060jobs\n`", 1, 0},
		{"run after a backtick", "`\u2060\u2060x`", 2, 0},
		{"with a ZWSP after it", "`\u2060\u200Bx`", 2, 0},
		{"inside a span", "`jobs.\u2060define()`", 1, 0},
		{"closing a span", "`x\u2060`", 1, 0},
		{"in prose", "small\u2060 commits", 1, 0},
		{"another hidden code point on the line", "`\u2060x` and ign\u200Bore", 2, 0},
		{"an uncounted emoji joiner on the line", "`\u2060x` \U0001F469\u200D\U0001F4BB", 1, 0},
		{"another hidden code point on another line", "`\u2060x`\nign\u200Bore", 2, 1},
		{"ZWSP opening a code span", "`\u200Bx`", 1, 0},
		{"BOM opening a code span", "`\uFEFFx`", 1, 0},
	}
	for _, tc := range cases {
		got, _ := Scan([]byte(tc.in))
		if got.Total != tc.counted || got.CodeSpanJoiners != tc.span {
			t.Errorf("%s: Scan(%+q) = Total %d, CodeSpanJoiners %d, want %d, %d", tc.name, tc.in, got.Total, got.CodeSpanJoiners, tc.counted, tc.span)
		}
	}
}

func TestLowShapes(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		counted, low int
	}{
		{"code span joiner", "Define `\u2060jobs.define()` first.", 1, 1},
		{"after a dash list marker", "- \u2060Keep commits small.", 1, 1},
		{"after an indented star marker", "  * \u2060Keep commits small.", 1, 1},
		{"after a plus marker and a tab", "+\t\u2060Keep commits small.", 1, 1},
		{"after a numbered marker", "12. \u2060Keep commits small.", 1, 1},
		{"after a paren numbered marker", "3) \u20602026 plan", 1, 1},
		{"list joiner on one of two lines", "- \u2060Keep\n- small\u2060 commits", 2, 1},
		{"list marker without a space", "-\u2060Keep", 1, 0},
		{"list marker then text", "- Keep\u2060 commits", 1, 0},
		{"list joiner before a space", "- \u2060 Keep", 1, 0},
		{"list joiner before a non-ASCII letter", "- \u2060\u0430pi", 1, 0},
		{"list joiner run", "- \u2060\u2060Keep", 2, 0},
		{"list joiner with another hidden code point", "- \u2060Keep ign\u200Bore", 2, 0},
		{"list joiner with an uncounted joiner on the line", "- \u2060Keep \U0001F469\u200D\U0001F4BB", 1, 0},
		{"ZWSP after a list marker", "- \u200BKeep", 1, 0},
		{"heading not a list", "# \u2060Keep", 1, 0},
		{"too many digits", "1234567890. \u2060Keep", 1, 0},
		{"Latin word and Persian suffix", "Server\u200c\u0647\u0627 \u0631\u0627", 1, 1},
		{"Latin word and Kannada suffix", "API\u200c\u0c97\u0cb3\u0cca\u0c82\u0ca6\u0cbf\u0c97\u0cc6", 1, 1},
		{"Latin word and Devanagari suffix with a mark", "API\u200d\u0915\u0947", 1, 1},
		{"one-letter Latin word", "Read a\u200c\u0628\u0627 first.", 1, 0},
		{"one-letter suffix", "Read API\u200c\u0628 first.", 1, 0},
		{"joiner inside a Latin word", "ign\u200core", 1, 0},
		{"Latin word and Cyrillic suffix", "API\u200c\u0430\u0431", 1, 0},
		{"Latin word and Hangul suffix", "API\u200c\uc2a4\uc2a4", 1, 0},
		{"joiner run before a suffix", "API\u200c\u200c\u0647\u0627", 2, 0},
		{"ZWSP before a suffix", "API\u200b\u0647\u0627", 1, 0},
		{"script joiner then Latin", "\u0c95\u0ccd\u200cenv", 1, 0},
		{"sample in a code span", "The marker is (`\u2062\u2060`).", 1, 1},
		{"two counted in a sample", "Strip `\u2060\uFEFF\u2063` first.", 2, 2},
		{"sample after a closed span", "`a` and `\u2063\u2060` here", 1, 1},
		{"between two spans", "`a`\u2063\u2060`b`", 1, 0},
		{"sample with a repeat", "`\u2063\u2060\u2060`", 2, 0},
		{"sample with a tag", "`\u2063\u2060\U000E0041`", 2, 0},
		{"sample with a bidi control", "`\u2060\u202E`", 2, 0},
		{"sample too long", "`\u2061\u2062\u2063\u2064\u200B\u2060\uFEFF\u200C\u200D`", 5, 0},
		{"double-backtick sample", "``\u2063\u2060``", 1, 0},
		{"span with visible text", "`jobs.\u2060define()`", 1, 0},
		{"span joiner run", "`\u2060\u2060x`", 2, 0},
		{"sample not closed", "`\u2063\u2060 x", 1, 0},
	}
	for _, tc := range cases {
		got, _ := Scan([]byte(tc.in))
		if got.Total != tc.counted || got.LowShapes != tc.low {
			t.Errorf("%s: Scan(%+q) = Total %d, LowShapes %d, want %d, %d", tc.name, tc.in, got.Total, got.LowShapes, tc.counted, tc.low)
		}
	}
}

func TestLineStartJoiner(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		counted, low int
	}{
		{"before plain text", "\u2060When access is denied, stop.", 1, 1},
		{"before a list marker", "\u2060- Keep commits small.", 1, 1},
		{"on a later line", "# Agents\n\u2060Keep commits small.", 1, 1},
		{"alone on its line", "a\n\u2060\nb", 1, 1},
		{"before a list marker with a list joiner", "\u2060- \u2060Keep commits small.", 2, 2},
		{"with a list joiner and another hidden code point", "\u2060- \u2060Keep ign\u200Bore", 3, 1},
		{"with hidden text later on the line", "\u2060Keep ign\u200Bore", 2, 1},
		{"run at line start", "\u2060\u2060Keep commits small.", 2, 0},
		{"next to a ZWSP", "\u2060\u200BKeep", 2, 0},
		{"next to an invisible operator", "\u2060\u2063Keep", 1, 0},
		{"after indentation", "  \u2060Keep", 1, 0},
		{"tag at line start", "\U000E0041Keep", 1, 0},
		{"bidi control at line start", "\u202EKeep", 1, 0},
		{"BOM at line start", "a\n\uFEFFKeep", 1, 0},
		{"ZWSP at line start", "a\n\u200BKeep", 1, 0},
	}
	for _, tc := range cases {
		got, _ := Scan([]byte(tc.in))
		if got.Total != tc.counted || got.LowShapes != tc.low {
			t.Errorf("%s: Scan(%+q) = Total %d, LowShapes %d, want %d, %d", tc.name, tc.in, got.Total, got.LowShapes, tc.counted, tc.low)
		}
	}
}

func TestStrong(t *testing.T) {
	cases := []struct {
		name            string
		in              string
		counted, strong int
	}{
		{"isolated ZWSP in a word", "ign\u200Bore", 1, 0},
		{"sparse ZWSPs", "a/\u200Bb and c/\u200Bd", 2, 0},
		{"BOM-only line", "a\n\uFEFF\nb", 1, 0},
		{"isolated joiner", "ign\u200core", 1, 0},
		{"word joiner", "ign\u2060ore", 1, 0},
		{"one tag character", "Keep\U000E0041", 1, 1},
		{"tag run", "Keep\U000E0041\U000E0042", 2, 2},
		{"one bidi control", "Run\u2067 tests", 1, 1},
		{"bidi pair", "\u202Eab\u202C", 2, 2},
		{"zero-width pair", "ign\u200B\u200Core", 2, 2},
		{"repeated zero-width pair", "note\u200B\u200B", 2, 2},
		{"zero-width run of three", "a\u200B\u200C\u200Db", 3, 3},
		{"runs split by a letter", "a\u200Bb\u200Bc", 2, 0},
		{"runs split by a line", "a\u200B\n\u200Bb", 2, 0},
		{"zero-width next to a bidi control", "a\u200B\u202Eb", 2, 2},
		{"line-start joiner run", "\u2060\u2060Keep", 2, 2},
		{"code span sample", "Strip `\u2060\uFEFF\u2063` first.", 2, 0},
		{"code span sample with a repeat", "`\u2063\u2060\u2060`", 2, 2},
		{"strip literal", "s.replace(\"\u200B\u200C\", \"\")", 0, 0},
		{"emoji joiner", "\U0001F469\u200D\U0001F4BB", 0, 0},
	}
	for _, tc := range cases {
		got, _ := Scan([]byte(tc.in))
		if got.Total != tc.counted || got.Strong != tc.strong {
			t.Errorf("%s: Scan(%+q) = Total %d, Strong %d, want %d, %d", tc.name, tc.in, got.Total, got.Strong, tc.counted, tc.strong)
		}
	}
}
