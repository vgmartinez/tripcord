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
