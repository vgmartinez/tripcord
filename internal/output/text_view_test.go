package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The detailed text of findings(), captured before the compact view.
// -v must reproduce it byte for byte.
const detailedTextGolden = "" +
	"MEDIUM TC-CFG-002 configs/tasks.json: Task runs on folder open | evidence: runOn: folderOpen | fix: Remove runOn: folderOpen. | fingerprint: tcf_7a4367039eb41858\n" +
	"HIGH TC-CFG-010 configs/hook.json:7: Plugin executes arbitrary code | evidence: plugin: ./plugins/unreviewed.js | fix: Remove the plugin or review and pin it. | fingerprint: tcf_47cbba354adad9a1\n" +
	"2 finding(s): 0 critical, 1 high, 1 medium, 0 low; 0 warning(s)\n"

func TestVerboseReproducesDetailedText(t *testing.T) {
	t.Parallel()
	options := testOptions()
	options.Verbose = true
	if got := renderWith(t, FormatText, sealAll(t, findings()), options); got != detailedTextGolden {
		t.Fatalf("verbose text =\n%s\nwant =\n%s", got, detailedTextGolden)
	}
}

func TestCompactTextFitsOneScreen(t *testing.T) {
	t.Parallel()
	got := render(t, FormatText, findings())
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) > 24 {
		t.Fatalf("%d lines, want at most 24:\n%s", len(lines), got)
	}
	if len(lines) != len(findings())+2 {
		t.Fatalf("lines = %d, want summary + %d findings + hint", len(lines), len(findings()))
	}
	if !strings.Contains(lines[0], "exit 1") || !strings.Contains(lines[0], "1 high") {
		t.Fatalf("summary = %q", lines[0])
	}
	if lines[len(lines)-1] != textDetailHint {
		t.Fatalf("hint = %q", lines[len(lines)-1])
	}
	for _, line := range lines {
		visible := stripTextHyperlinks(line)
		if n := utf8.RuneCountInString(visible); n > textWidth {
			t.Fatalf("visible width %d > %d: %q", n, textWidth, visible)
		}
	}
	for _, id := range []string{"TC-CFG-002", "TC-CFG-010"} {
		url := "https://github.com/vgmartinez/tripcord/blob/main/docs/rules/" + id + ".md"
		if !strings.Contains(got, url) || !strings.Contains(got, id) {
			t.Fatalf("missing link for %s:\n%s", id, got)
		}
	}
	if strings.Contains(got, "fingerprint:") || strings.Contains(got, "evidence:") {
		t.Fatalf("compact text includes the detail:\n%s", got)
	}
}

func TestMachineFormatsIgnoreVerboseAndExit(t *testing.T) {
	t.Parallel()
	code := 1
	verbose := testOptions()
	verbose.Verbose = true
	verbose.TextExit = &code
	sealed := sealAll(t, findings())
	for _, format := range []Format{FormatJSON, FormatJSONL, FormatSARIF, FormatMD, FormatGHA} {
		plain := render(t, format, findings())
		other := renderWith(t, format, sealed, verbose)
		if plain != other {
			t.Fatalf("%s changed with -v or an exit verdict", format)
		}
	}
}

func stripTextHyperlinks(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if n := textHyperlinkLen(s[i:]); n > 0 {
			i += n
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func TestShortenVisibleWordBoundary(t *testing.T) {
	t.Parallel()
	const title = "Hidden Unicode in an agent instructions file"
	longWord := strings.Repeat("x", 40)
	// "ab" plus a 4-rune escape: a mid-token cut at room 6 (budget 5)
	// would split \x1b. The escape must be dropped whole.
	escaped := "ab" + `\x1b` + "cdefghijklmnop"
	cases := []struct {
		name, in string
		room     int
		want     string
	}{
		{"room 32 backs up to agent", title, 32, "Hidden Unicode in an agent…"},
		{"room 22 trims space before ellipsis", title, 22, "Hidden Unicode in an…"},
		{"short title is unchanged", "Short title", 32, "Short title"},
		{"room 1 is only the ellipsis", title, 1, "…"},
		{"room 0 is empty", title, 0, ""},
		{"long word keeps a hard cut", longWord, 10, longWord[:9] + "…"},
		{"escape token stays whole", escaped, 6, "ab…"},
		{"trailing comma is trimmed", "Hello, world and friends", 8, "Hello…"},
		{"too little remains keeps the hard cut", "xx " + strings.Repeat("y", 40), 10, "xx " + strings.Repeat("y", 6) + "…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shortenVisible(tc.in, tc.room)
			if got != tc.want {
				t.Fatalf("shortenVisible(%q, %d) = %q, want %q", tc.in, tc.room, got, tc.want)
			}
			if tc.room > 0 && utf8.RuneCountInString(got) > tc.room {
				t.Fatalf("width %d > room %d: %q", utf8.RuneCountInString(got), tc.room, got)
			}
			if strings.Contains(tc.in, `\x1b`) && strings.Contains(got, `\`) && !strings.Contains(got, `\x1b`) {
				t.Fatalf("split escape token: %q", got)
			}
		})
	}
}

func TestFitFindingTitleWordBoundary(t *testing.T) {
	t.Parallel()
	title, loc := fitFinding("HIGH", "TC-CFG-011", "Hidden Unicode in an agent instructions file", ".cursor/rules/abcdefghijk.mdc:7")
	if strings.HasSuffix(strings.TrimSuffix(title, "…"), " ") {
		t.Fatalf("title has a space before the ellipsis: %q", title)
	}
	if strings.Contains(title, "inst…") || strings.HasSuffix(title, "an …") {
		t.Fatalf("title cut mid-word or left a space: %q", title)
	}
	visible := "HIGH TC-CFG-011"
	if title != "" {
		visible += " " + title
	}
	visible += " " + loc
	if n := utf8.RuneCountInString(visible); n > textWidth {
		t.Fatalf("visible width %d > %d: %q", n, textWidth, visible)
	}
}

func TestShortenHardKeepsMidComponentCut(t *testing.T) {
	t.Parallel()
	path := "very/long/path/without/spaces/abcdefghijk.md:7"
	got := shortenHard(path, 10)
	want := path[:9] + "…"
	if got != want {
		t.Fatalf("shortenHard(%q, 10) = %q, want %q", path, got, want)
	}
}
