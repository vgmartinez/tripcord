package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestTruncateKeepsRunesAndEscapesIntact(t *testing.T) {
	t.Parallel()
	cases := []string{
		strings.Repeat("é", 800),
		escapeControls(strings.Repeat("\u202e", 400)),
		escapeControls(strings.Repeat("\x1b", 400)),
		strings.Repeat(`\u202e`, 200),
		strings.Repeat("a\u200b", 700),
	}
	for _, value := range cases {
		got := truncateSanitized(value, MaxFieldBytes)
		if len(got) > MaxFieldBytes {
			t.Fatalf("len %d > %d", len(got), MaxFieldBytes)
		}
		if !utf8.ValidString(got) {
			t.Fatal("truncated string is not valid UTF-8")
		}
		if !strings.Contains(got, "…[truncated ") || !strings.HasSuffix(got, " bytes]") {
			t.Fatalf("marker missing: %q", got[len(got)-40:])
		}
		assertCompleteEscapes(t, got)
	}
	short := "already short"
	if truncateSanitized(short, MaxFieldBytes) != short {
		t.Fatal("short value was modified")
	}
}

func TestTruncateGHADoesNotSplitPercentEscapes(t *testing.T) {
	t.Parallel()
	value := strings.Repeat("prefix%0A", 300)
	got := truncateGHA(value, MaxFieldBytes)
	if len(got) > MaxFieldBytes {
		t.Fatalf("len %d > %d", len(got), MaxFieldBytes)
	}
	for i := 0; i < len(got); i++ {
		if got[i] != '%' {
			continue
		}
		if i+2 >= len(got) || !isHex(got[i+1]) || !isHex(got[i+2]) {
			t.Fatalf("split GHA escape at byte %d: %q", i, got[i:])
		}
		i += 2
	}
}

func assertCompleteEscapes(t *testing.T, value string) {
	t.Helper()
	for i := 0; i < len(value); {
		if value[i] != '\\' {
			i++
			continue
		}
		n := escapeTokenLen(value[i:])
		if n == 0 {
			t.Fatalf("split escape at byte %d: %q", i, value[i:min(i+12, len(value))])
		}
		i += n
	}
}

func TestHugeExcerptIsCapped(t *testing.T) {
	t.Parallel()
	payload := strings.Repeat("Q", 2<<20)
	finding := findings()[0]
	finding.Evidence[0].Excerpt = payload
	for _, format := range allFormats {
		got := render(t, format, []model.Finding{finding})
		if strings.Contains(got, strings.Repeat("Q", 1000)) {
			t.Fatalf("%s leaked the excerpt", format)
		}
		if len(got) > 256<<10 {
			t.Fatalf("%s is %d bytes", format, len(got))
		}
		switch format {
		case FormatJSON, FormatJSONL, FormatText, FormatMD:
			if !strings.Contains(got, "…[truncated ") {
				t.Fatalf("%s did not mark the truncated excerpt", format)
			}
		case FormatSARIF, FormatGHA:
		default:
			t.Fatalf("unhandled format %s", format)
		}
		if format == FormatMD && (len(got) > MaxMarkdownBytes || utf8.RuneCountInString(got) >= GitHubCommentLimit) {
			t.Fatalf("markdown comment is %d bytes, %d chars", len(got), utf8.RuneCountInString(got))
		}
	}
	if finding.Evidence[0].Excerpt != payload {
		t.Fatal("rendering changed the stored excerpt")
	}
}

func TestMarkdownOmitsFindingsPastTheCap(t *testing.T) {
	t.Parallel()
	const n = 120
	excerpt := strings.Repeat("e", 400)
	input := make([]model.Finding, n)
	for i := range input {
		finding := findings()[0]
		finding.Rule = fmt.Sprintf("TC-TST-%03d", i)
		finding.Title = fmt.Sprintf("title-%03d", i)
		finding.Evidence[0].Excerpt = excerpt
		input[i] = finding
	}
	got := render(t, FormatMD, input)
	if len(got) > MaxMarkdownBytes || utf8.RuneCountInString(got) >= GitHubCommentLimit {
		t.Fatalf("markdown comment is %d bytes, %d chars", len(got), utf8.RuneCountInString(got))
	}
	shown := 0
	for i := range input {
		if strings.Contains(got, fmt.Sprintf("title-%03d", i)) {
			shown++
		}
	}
	if shown == 0 || shown >= n {
		t.Fatalf("shown = %d of %d", shown, n)
	}
	omitted := n - shown
	want := omissionLine(omitted)
	if !strings.Contains(got, want) {
		t.Fatalf("missing %q\n%s", want, got[len(got)-80:])
	}
	if strings.Contains(got, fmt.Sprintf("title-%03d", n-1)) {
		t.Fatal("the last finding was not omitted")
	}
	text := render(t, FormatText, input)
	if !strings.Contains(text, fmt.Sprintf("title-%03d", n-1)) || strings.Contains(text, "more findings omitted") {
		t.Fatal("the text sink omitted findings")
	}
}

func TestFormatCharactersAreEscaped(t *testing.T) {
	t.Parallel()
	const tag = "\U000E0001"
	payload := "a\u200b\u200c\u200d\u2060\ufeff\u00ad" + tag + "z @org/team"
	finding := findings()[0]
	finding.Title = payload
	for _, format := range allFormats {
		got := render(t, format, []model.Finding{finding})
		assertNoRawControls(t, got)
		for _, raw := range []string{"\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", tag} {
			if strings.Contains(got, raw) {
				t.Fatalf("%s leaked %U", format, []rune(raw)[0])
			}
		}
		if format == FormatMD {
			if !strings.Contains(got, "@\u200borg/team") {
				t.Fatalf("mention breaker missing:\n%s", got)
			}
			continue
		}
		if strings.Contains(got, "\u200b") {
			t.Fatalf("%s kept a raw U+200B", format)
		}
	}
	raw := render(t, FormatJSON, []model.Finding{finding})
	var decoded model.Finding
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &decoded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decoded.Title, tag) || !strings.Contains(decoded.Title, "\u200b") {
		t.Fatalf("JSON did not preserve format characters: %q", decoded.Title)
	}
}

func TestSARIFTextEscapesBrackets(t *testing.T) {
	t.Parallel()
	finding := findings()[0]
	finding.Title = "[x](https://evil.example/phish)"
	finding.Fix = "see [docs](https://evil.example/fix)"
	got := render(t, FormatSARIF, []model.Finding{finding})
	validateSARIF(t, got)
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ShortDescription map[string]string `json:"shortDescription"`
						FullDescription  map[string]string `json:"fullDescription"`
						Help             map[string]string `json:"help"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Message map[string]string `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(got), &log); err != nil {
		t.Fatal(err)
	}
	texts := []string{
		log.Runs[0].Results[0].Message["text"],
		log.Runs[0].Tool.Driver.Rules[0].ShortDescription["text"],
		log.Runs[0].Tool.Driver.Rules[0].FullDescription["text"],
		log.Runs[0].Tool.Driver.Rules[0].Help["text"],
	}
	for _, text := range texts {
		if strings.Contains(text, "[x](https://evil.example/phish)") || strings.Contains(text, "[docs](https://evil.example/fix)") {
			t.Fatalf("SARIF text still has a link: %s", text)
		}
	}
	if !strings.Contains(texts[0], `\[x\](https://evil.example/phish)`) || !strings.Contains(texts[3], `\[docs\](https://evil.example/fix)`) {
		t.Fatalf("escaped brackets missing: %#v", texts)
	}
}

func TestMarkdownMentionBreakerStaysWithinFieldCap(t *testing.T) {
	t.Parallel()
	raw := strings.Repeat("@", MaxFieldBytes)
	got := markdownValue(raw)
	if len(got) > MaxFieldBytes {
		t.Fatalf("markdown field is %d bytes", len(got))
	}
	if !strings.Contains(got, "…[truncated ") {
		t.Fatal("mention field was not capped")
	}
	assertAtMentionsBroken(t, got)
	cell := tableCode(raw)
	if len(cell) > MaxFieldBytes+2 {
		t.Fatalf("table cell is %d bytes", len(cell))
	}
	assertAtMentionsBroken(t, cell)

	finding := findings()[0]
	finding.Title = raw
	finding.Fix = raw
	finding.Evidence[0].Excerpt = raw
	rendered := render(t, FormatMD, []model.Finding{finding})
	if len(rendered) > MaxMarkdownBytes || utf8.RuneCountInString(rendered) >= GitHubCommentLimit {
		t.Fatalf("markdown comment is %d bytes, %d chars", len(rendered), utf8.RuneCountInString(rendered))
	}
	assertAtMentionsBroken(t, rendered)
}

func assertAtMentionsBroken(t *testing.T, got string) {
	t.Helper()
	for i := 0; i < len(got); {
		r, n := utf8.DecodeRuneInString(got[i:])
		if r == '@' {
			r2, n2 := utf8.DecodeRuneInString(got[i+n:])
			if r2 != '\u200b' {
				t.Fatalf("bare @ at byte %d", i)
			}
			i += n + n2
			continue
		}
		i += n
	}
}

func TestSARIFPathFieldsAreCapped(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("b", MaxFieldBytes+80)
	finding := userFinding()
	finding.Location.Path = "~/" + longName
	for _, mode := range []SARIFNonRepoLocation{SARIFNonRepoLogical, SARIFNonRepoURIBase} {
		options := testOptions()
		options.NonRepoSARIF = mode
		got := renderWith(t, FormatSARIF, sealAll(t, []model.Finding{finding}), options)
		var log struct {
			Runs []struct {
				Results []struct {
					Locations []struct {
						Logical []struct {
							Name               string `json:"name"`
							FullyQualifiedName string `json:"fullyQualifiedName"`
						} `json:"logicalLocations"`
					} `json:"locations"`
					Properties struct {
						Tripcord struct {
							Path string `json:"path"`
						} `json:"tripcord"`
					} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(got), &log); err != nil {
			t.Fatal(err)
		}
		result := log.Runs[0].Results[0]
		fields := []string{result.Properties.Tripcord.Path}
		if mode == SARIFNonRepoLogical {
			loc := result.Locations[0].Logical[0]
			fields = append(fields, loc.Name, loc.FullyQualifiedName)
		}
		for _, field := range fields {
			if len(field) > MaxFieldBytes || !strings.Contains(field, "…[truncated ") {
				t.Fatalf("%s field %q", mode, field)
			}
		}
	}
}

func TestDriveRelativePathsAreAbsolute(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"c:x.json", "C:", "C:foo"} {
		ref := locate(model.Location{Scope: model.ScopeRepo, Path: path}, "/work/repo")
		if ref.kind != locNone || ref.path != "" {
			t.Fatalf("%s located as %+v", path, ref)
		}
	}
	finding := findings()[0]
	finding.Location.Path = "c:x.json"
	for _, format := range allFormats {
		got := render(t, format, []model.Finding{finding})
		if strings.Contains(got, "c:x.json") || strings.Contains(got, "file=") {
			t.Fatalf("%s kept a drive-relative path:\n%s", format, got)
		}
	}
}
