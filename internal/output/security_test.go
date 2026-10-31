package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/model"
)

var allFormats = []Format{FormatJSON, FormatJSONL, FormatSARIF, FormatText, FormatGHA, FormatMD}

// injectionPayloads are attacker-controlled strings a repository can put in
// a title, fix, excerpt, or path. Rule IDs are a closed model vocabulary.
var injectionPayloads = map[string]string{
	"stop-commands":   "\n::stop-commands::tok",
	"add-mask":        "x\n::add-mask::secret\n::error::forged",
	"indented-cmd":    "\n   \t::warning::forged",
	"ansi-erase":      "\x1b[2K\rforged",
	"csi-c1":          "\u009b2Kforged\u0085next",
	"link":            "[x](https://evil)",
	"image":           "![i](https://evil/i.png)",
	"autolink":        "<https://evil>",
	"html":            "<img src=x onerror=alert(1)>",
	"entity":          "&lt;b&gt;&amp;",
	"mention-team":    "@org/team",
	"mention-user":    "ping @user",
	"issue-ref":       "fixes #1",
	"heading":         "\n\n## Pwned",
	"emphasis":        "**bold** _it_ ~~s~~",
	"backticks":       "`` ` ``` x",
	"fence-line":      "\n```\n[x](https://evil)\n```",
	"pipe":            "a|b\\|c",
	"bidi":            "safe\u202eevil\u2066x\u2069",
	"line-separator":  "a\u2028b\u2029c",
	"c0":              "\x00\x07\x08\x7f",
	"invalid-utf8":    "\xff\xfe",
	"windows-path":    "C:/Users/alice/secret.txt",
	"escape-sequence": "\\n::error::literal",
}

var placements = map[string]func(*model.Finding, string){
	"title":   func(f *model.Finding, v string) { f.Title = v },
	"fix":     func(f *model.Finding, v string) { f.Fix = v },
	"excerpt": func(f *model.Finding, v string) { f.Evidence[0].Excerpt = v },
	"path":    func(f *model.Finding, v string) { f.Location.Path = "configs/" + v },
}

func TestInjectionPayloadsAreInert(t *testing.T) {
	t.Parallel()
	for payloadName, payload := range injectionPayloads {
		for placementName, place := range placements {
			finding := findings()[0]
			place(&finding, payload)
			input := []model.Finding{finding, findings()[1]}
			for _, format := range allFormats {
				t.Run(payloadName+"/"+placementName+"/"+string(format), func(t *testing.T) {
					t.Parallel()
					if err := writable(finding); err != nil {
						if placementName != "path" {
							t.Fatal(err)
						}
						assertRejected(t, format, finding)
						return
					}
					got := render(t, format, input)
					assertNoRawControls(t, got)
					assertLineStructure(t, format, got, len(input))
					switch format {
					case FormatJSON, FormatJSONL:
						assertJSONFaithful(t, got, finding, placementName)
						validateFindingLines(t, got)
					case FormatMD:
						assertMarkdownInert(t, got)
					case FormatSARIF:
						validateSARIF(t, got)
					case FormatText, FormatGHA:
					default:
						t.Fatalf("unhandled format %s", format)
					}
				})
			}
		}
	}
}

// writable reports whether finding can be stored: its path and evidence
// satisfy the model, and a fingerprint can be stamped.
func writable(finding model.Finding) error {
	fp, err := model.Fingerprint(finding.Rule, finding.Location, finding.Evidence)
	if err != nil {
		return err
	}
	finding.Fingerprint = fp
	return finding.Validate()
}

// assertRejected checks that a finding the model rejects is not written
// and produces no bytes.
func assertRejected(t *testing.T, format Format, finding model.Finding) {
	t.Helper()
	var buffer bytes.Buffer
	sink, err := NewStdoutSink(format, &buffer, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(finding); err == nil {
		t.Fatal("invalid finding was written")
	}
	if buffer.Len() != 0 {
		t.Fatalf("rejected finding produced %q", buffer.String())
	}
}

func TestInjectionGoldens(t *testing.T) {
	t.Parallel()
	for _, format := range []Format{FormatText, FormatGHA, FormatMD} {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			got := render(t, format, []model.Finding{injectionFinding()})
			assertGolden(t, string(format)+"-injection.golden", got)
		})
	}
}

func injectionFinding() model.Finding {
	finding := findings()[0]
	finding.Title = "Run \x1b[2K\rforged [x](https://evil) @org/team"
	finding.Fix = "See\n\n## Pwned <img src=x> `tick` a|b \u202eevil"
	finding.Evidence[0].Excerpt = "\n::stop-commands::tok\n``` [x](https://evil) @org/team \\d"
	finding.Location.Path = "configs/a:b,c.json"
	return finding
}

func assertNoRawControls(t *testing.T, got string) {
	t.Helper()
	for i := 0; i < len(got); {
		r, size := utf8.DecodeRuneInString(got[i:])
		if r == '\u200b' {
			// The markdown sink inserts U+200B after sanitization: after "@"
			// to break a mention, and before a leading "::" in a fence.
			afterAt := i > 0 && got[i-1] == '@'
			beforeCmd := strings.HasPrefix(got[i+size:], "::")
			if !afterAt && !beforeCmd {
				t.Fatalf("raw U+200B at byte %d:\n%q", i, got)
			}
			i += size
			continue
		}
		if (r < 0x20 && r != '\n') || isUnsafeRune(r) {
			t.Fatalf("raw control %U at byte %d:\n%q", r, i, got)
		}
		i += size
	}
}

var ghaLine = regexp.MustCompile(`^::(error|warning|notice)( [^:]*)?::`)

func assertLineStructure(t *testing.T, format Format, got string, findings int) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	switch format {
	case FormatGHA:
		if len(lines) != findings {
			t.Fatalf("gha lines = %d, want %d:\n%s", len(lines), findings, got)
		}
		for _, line := range lines {
			if !ghaLine.MatchString(line) {
				t.Fatalf("gha line is not one annotation: %q", line)
			}
		}
		return
	case FormatText:
		if len(lines) != findings+1 {
			t.Fatalf("text lines = %d, want %d:\n%s", len(lines), findings+1, got)
		}
	case FormatJSON, FormatJSONL:
		if len(lines) != findings {
			t.Fatalf("jsonl lines = %d, want %d:\n%s", len(lines), findings, got)
		}
	case FormatSARIF, FormatMD:
	default:
		t.Fatalf("unhandled format %s", format)
	}
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), "::") {
			t.Fatalf("%s line starts a workflow command: %q", format, line)
		}
	}
}

// assertJSONFaithful checks that JSONL escapes without changing values.
func assertJSONFaithful(t *testing.T, got string, want model.Finding, placement string) {
	t.Helper()
	want = redactFinding(seal(t, want), DefaultRedactor)
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		var decoded model.Finding
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("invalid JSONL line %q: %v", line, err)
		}
		if decoded.Fingerprint != want.Fingerprint {
			continue
		}
		var gotValue, wantValue string
		switch placement {
		case "rule":
			gotValue, wantValue = decoded.Rule, want.Rule
		case "title":
			gotValue, wantValue = decoded.Title, want.Title
		case "fix":
			gotValue, wantValue = decoded.Fix, want.Fix
		case "excerpt":
			gotValue, wantValue = decoded.Evidence[0].Excerpt, want.Evidence[0].Excerpt
		case "path":
			return
		default:
			t.Fatalf("unhandled placement %s", placement)
		}
		if gotValue != jsonCoerced(wantValue) {
			t.Fatalf("%s = %q, want %q", placement, gotValue, wantValue)
		}
		return
	}
	t.Fatal("finding missing from JSONL")
}

// jsonCoerced is value as encoding/json round-trips it: each invalid UTF-8
// byte becomes U+FFFD.
func jsonCoerced(value string) string {
	var b strings.Builder
	for _, r := range value {
		b.WriteRune(r)
	}
	return b.String()
}

// assertMarkdownInert checks that markdown syntax only appears inside code
// spans and fences, apart from the sink's own headings and table.
func assertMarkdownInert(t *testing.T, got string) {
	t.Helper()
	for i := strings.Index(got, "@"); i >= 0; i = nextIndex(got, "@", i) {
		if !strings.HasPrefix(got[i+1:], "\u200b") {
			t.Fatalf("unbroken mention at byte %d:\n%s", i, got)
		}
	}
	for _, line := range strings.Split(markdownOutsideCode(t, got), "\n") {
		if strings.HasPrefix(line, "#") && line != "## Tripcord findings" && !strings.HasPrefix(line, "### ") {
			t.Fatalf("injected heading %q:\n%s", line, got)
		}
		trimmed := strings.TrimLeft(line, "#")
		if i := strings.IndexAny(trimmed, "[]()<>&*_!~\\#@`"); i >= 0 {
			t.Fatalf("markdown syntax %q outside code in %q:\n%s", trimmed[i], line, got)
		}
	}
}

func nextIndex(s, sub string, after int) int {
	i := strings.Index(s[after+1:], sub)
	if i < 0 {
		return -1
	}
	return after + 1 + i
}

// markdownOutsideCode removes fenced blocks and code spans, failing on an
// unterminated one. Inside GFM tables, "\|" counts as part of the span.
func markdownOutsideCode(t *testing.T, doc string) string {
	t.Helper()
	var out []string
	fence := ""
	for _, line := range strings.Split(doc, "\n") {
		if fence != "" {
			if strings.TrimRight(line, "`") == "" && len(line) >= len(fence) {
				fence = ""
			}
			continue
		}
		if strings.HasPrefix(line, "```") && strings.TrimLeft(line, "`") == "" {
			fence = line
			continue
		}
		out = append(out, stripCodeSpans(t, line))
	}
	if fence != "" {
		t.Fatalf("unterminated fence:\n%s", doc)
	}
	return strings.Join(out, "\n")
}

func stripCodeSpans(t *testing.T, line string) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			b.WriteByte(line[i])
			i++
			continue
		}
		n := runLength(line, i)
		end := -1
		for j := i + n; j < len(line); {
			if line[j] != '`' {
				j++
				continue
			}
			m := runLength(line, j)
			if m == n {
				end = j
				break
			}
			j += m
		}
		if end < 0 {
			t.Fatalf("unterminated code span in %q", line)
		}
		i = end + n
	}
	return b.String()
}

func runLength(s string, i int) int {
	n := 0
	for i+n < len(s) && s[i+n] == '`' {
		n++
	}
	return n
}

func TestUnredactedSecretsNeverReachOutput(t *testing.T) {
	t.Parallel()
	awsID := "AKIA" + "Z7Q4" + "TRIPCORDTEST"
	awsSecret := "wJalr" + strings.Repeat("XUtnFEMI", 4) + "K7MDE"
	githubToken := "ghp_" + strings.Repeat("aB3", 12)
	secrets := []string{awsID, awsSecret, githubToken, "Z7Q4TRIPCORDTEST", strings.Repeat("aB3", 12)}
	carrier := "token " + githubToken + " key " + awsID + " aws_secret_access_key=" + awsSecret

	finding := findings()[0]
	finding.Title = carrier
	finding.Fix = carrier
	finding.Location.Session = carrier
	finding.Location.Path = "configs/" + awsID + ".json"
	finding.Evidence = []model.Evidence{
		{Config: &model.ConfigRef{ID: "cursor:repo:" + githubToken, Key: githubToken}, Excerpt: carrier},
		{Event: "evt_" + awsID, Excerpt: "`" + githubToken + "`"},
	}
	finding.Refs = []string{"https://example.invalid/?t=" + githubToken}
	user := userFinding()
	user.Location.Path = "~/" + githubToken + "/settings.json"

	for _, format := range allFormats {
		for _, mode := range []SARIFNonRepoLocation{SARIFNonRepoLogical, SARIFNonRepoURIBase} {
			options := testOptions()
			options.NonRepoSARIF = mode
			got := renderWith(t, format, sealAll(t, []model.Finding{finding, user}), options)
			for _, secret := range secrets {
				if strings.Contains(got, secret) {
					t.Fatalf("%s/%s leaked %q:\n%s", format, mode, secret, got)
				}
			}
			if !strings.Contains(got, "REDACTED") {
				t.Fatalf("%s/%s shows no redaction marker:\n%s", format, mode, got)
			}
		}
	}
}

func TestRedactorRunsInEverySink(t *testing.T) {
	t.Parallel()
	const canary = "canary-7f3a"
	finding := findings()[0]
	finding.Title = "title " + canary
	finding.Fix = "fix " + canary
	finding.Evidence[0].Excerpt = canary
	finding.Location.Path = "configs/" + canary + ".json"
	options := testOptions()
	options.Redactor = func(value string) string { return strings.ReplaceAll(value, canary, "gone") }
	for _, format := range allFormats {
		got := renderWith(t, format, sealAll(t, []model.Finding{finding}), options)
		if strings.Contains(got, canary) || !strings.Contains(got, "gone") {
			t.Fatalf("%s did not apply the redactor:\n%s", format, got)
		}
	}
}

func TestSinksRequireRedactor(t *testing.T) {
	t.Parallel()
	options := testOptions()
	options.Redactor = nil
	var buffer bytes.Buffer
	for _, format := range allFormats {
		if _, err := NewStdoutSink(format, &buffer, options); err == nil {
			t.Fatalf("%s sink accepted a nil redactor", format)
		}
		if _, err := NewFileSink(format, &buffer, options); err == nil {
			t.Fatalf("%s file sink accepted a nil redactor", format)
		}
	}
	path := t.TempDir() + "/out.json"
	if _, err := SelectSink("json", path, &buffer, options); err == nil {
		t.Fatal("SelectSink accepted a nil redactor")
	}
}

func TestDefaultRedactorKeepsRedactedText(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"sk-***REDACTED***abcd", "plugin: ./plugins/unreviewed.js", "[REDACTED]"} {
		if got := DefaultRedactor(value); got != value {
			t.Fatalf("DefaultRedactor(%q) = %q", value, got)
		}
	}
}

func TestDefaultRedactorCredentialPatterns(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"npm", "npm_abcdefghijklmnopqrstuvwxyz123456", "[REDACTED]"},
		{"hugging-face", "hf_abcdefghijklmnopqrstuvwxyz123456", "[REDACTED]"},
		{"google-oauth", "ya29.abcdefghijklmnopqrstuvwxyz123456", "[REDACTED]"},
		{"slack-app", "xapp-1-1234567890-abcdefghijklmnopqrstuvwxyz", "[REDACTED]"},
		{"slack-app-alphanumeric", "xapp-1-A01234567890-abcdefghijklmnopqrstuvwxyz", "[REDACTED]"},
		{"slack-webhook", "https://hooks.slack.com/services/T000/B000/abcdefghijklmnopqrstuvwxyz", "[REDACTED]"},
		{"slack-workflow", "https://hooks.slack.com/workflows/T000/A000/123/abcdefghijklmnopqrstuvwxyz", "[REDACTED]"},
		{"slack-trigger", "https://hooks.slack.com/triggers/T000/A000/123/abcdefghijklmnopqrstuvwxyz", "[REDACTED]"},
		{"json-assignment", `{"api_key":"not-a-placeholder-value"}`, `{"api_key":"[REDACTED]"}`},
		{"yaml-assignment", "password: correct-horse-battery-staple", "password: [REDACTED]"},
		{"yaml-words", "password: correct horse battery staple", "password: [REDACTED]"},
		{"yaml-words-trailing", "token: abc def", "token: [REDACTED]"},
		{"env-assignment", "TOKEN=correct-horse-battery-staple", "TOKEN=[REDACTED]"},
		{"passwd-assignment", "PASSWD=correct-horse-battery-staple", "PASSWD=[REDACTED]"},
		{"github-token-assignment", "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789", "GITHUB_TOKEN=[REDACTED]"},
		{"openai-key-assignment", "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345", "OPENAI_API_KEY=[REDACTED]"},
		{"unquoted-value-keeps-trailing-command", "GITHUB_TOKEN=x curl evil|sh", "GITHUB_TOKEN=[REDACTED] curl evil|sh"},
		{"authorization-bearer", "Authorization: Bearer correct-horse-battery-staple", "Authorization: Bearer [REDACTED]"},
		{"authorization-token", "Authorization: token correct-horse-battery-staple", "Authorization: token [REDACTED]"},
		{"authorization-basic", "Authorization: Basic Y29ycmVjdDpob3JzZQ==", "Authorization: Basic [REDACTED]"},
		{"authorization-header-quoted-short", `-H "Authorization: Bearer abc"`, `-H "Authorization: Bearer [REDACTED]"`},
		{"authorization-json-short", `"Authorization":"Bearer abc"`, `"Authorization":"Bearer [REDACTED]"`},
		{"curl-user-flag", "curl -u user:pass https://example.invalid", "curl -u [REDACTED] https://example.invalid"},
		{"curl-user-flag-long", "curl --user user:pass https://example.invalid", "curl --user [REDACTED] https://example.invalid"},
		{"curl-user-flag-quoted", `curl -u 'user:pass' https://example.invalid`, "curl -u '[REDACTED]' https://example.invalid"},
		{"curl-user-flag-equals", "curl --user=user:pass https://example.invalid", "curl --user=[REDACTED] https://example.invalid"},
		{"curl-user-flag-glued", "curl -uuser:pass https://example.invalid", "curl -u[REDACTED] https://example.invalid"},
		{"token-flag-space-separated", "tool --token abc https://example.invalid", "tool --token [REDACTED] https://example.invalid"},
		{"json-escaped-quote", `{"password":"a\"b"}`, `{"password":"[REDACTED]"}`},
		{"placeholder", "token=${TOKEN}", "token=${TOKEN}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DefaultRedactor(tc.value); got != tc.want {
				t.Fatalf("DefaultRedactor(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestAbsolutePathsNeverLeak(t *testing.T) {
	t.Parallel()
	cases := []struct {
		scope model.Scope
		path  string
	}{
		{model.ScopeRepo, "C:/Users/alice/proj/x.json"},
		{model.ScopeRepo, `C:\Users\alice\proj\x.json`},
		{model.ScopeRepo, "c:relative-drive"},
		{model.ScopeRepo, "/home/alice/work/x.json"},
		{model.ScopeRepo, `\\alice-server\share\x.json`},
		{model.ScopeRepo, "../../alice/passwd"},
		{model.ScopeRepo, "a/../../alice/shadow"},
		{model.ScopeRepo, "~/alice/x.json"},
		{model.ScopeRepo, "/work/repo/../alice/x.json"},
		{model.ScopeRepo, "/work/repository-alice/x.json"},
		{model.ScopeUser, "/home/alice/.claude/settings.json"},
		{model.ScopeUser, `C:\Users\alice\.claude\settings.json`},
		{model.ScopeUser, "~/../alice/.ssh/config"},
		{model.ScopeUser, "~alice/.claude/settings.json"},
	}
	for _, tc := range cases {
		finding := findings()[0]
		finding.Location.Scope = tc.scope
		finding.Location.Path = tc.path
		ref := locate(finding.Location, "/work/repo")
		if strings.Contains(strings.ToLower(ref.path), "alice") {
			t.Fatalf("locate kept %s path %q as %q", tc.scope, tc.path, ref.path)
		}
		if err := writable(finding); err != nil {
			assertRejected(t, FormatText, finding)
			continue
		}
		for _, format := range allFormats {
			got := render(t, format, []model.Finding{finding})
			if strings.Contains(strings.ToLower(got), "alice") {
				t.Fatalf("%s leaked %s path %q:\n%s", format, tc.scope, tc.path, got)
			}
		}
	}
}

func TestManagedHomePathsDisplayAsTilde(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "macOS", path: "/Users/alice/.cursor/hooks.json", want: "~/.cursor/hooks.json"},
		{name: "linux", path: "/home/alice/.cursor/hooks.json", want: "~/.cursor/hooks.json"},
		{name: "windows", path: "C:/users/alice/.cursor/hooks.json", want: "~/.cursor/hooks.json"},
	}
	for _, tc := range cases {
		finding := managedFinding()
		finding.Location.Path = tc.path
		finding = seal(t, finding)
		storedPath := finding.Location.Path
		storedFP := finding.Fingerprint
		for _, format := range allFormats {
			for _, mode := range []SARIFNonRepoLocation{SARIFNonRepoLogical, SARIFNonRepoURIBase} {
				options := testOptions()
				options.NonRepoSARIF = mode
				got := renderWith(t, format, []model.Finding{finding}, options)
				if finding.Location.Path != storedPath || finding.Fingerprint != storedFP {
					t.Fatalf("render mutated the finding")
				}
				if !strings.Contains(got, tc.want) || strings.Contains(strings.ToLower(got), "alice") {
					t.Fatalf("%s/%s/%s path = %q\n%s", tc.name, format, mode, tc.path, got)
				}
				if !strings.Contains(got, finding.Fingerprint) {
					t.Fatalf("%s/%s dropped the fingerprint\n%s", format, mode, got)
				}
			}
		}
	}
}

func TestManagedHomeDisplayLeavesFingerprint(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/Users/alice/.cursor/hooks.json",
		"/home/alice/.cursor/hooks.json",
		"C:/users/alice/.cursor/hooks.json",
	} {
		finding := managedFinding()
		finding.Location.Path = path
		want, err := model.Fingerprint(finding.Rule, finding.Location, finding.Evidence)
		if err != nil {
			t.Fatal(err)
		}
		finding.Fingerprint = want
		display := managedDisplayPath(normalizeDisplayPath(path))
		rewritten := finding.Location
		rewritten.Path = display
		if _, err := model.Fingerprint(finding.Rule, rewritten, finding.Evidence); err == nil {
			t.Fatalf("display path %q was accepted as a managed path", display)
		}
		for _, format := range allFormats {
			got := render(t, format, []model.Finding{finding})
			if finding.Location.Path != path || finding.Fingerprint != want {
				t.Fatal("render mutated the finding")
			}
			again, err := model.Fingerprint(finding.Rule, finding.Location, finding.Evidence)
			if err != nil {
				t.Fatal(err)
			}
			if again != want || !strings.Contains(got, want) {
				t.Fatalf("%s fingerprint changed for %s\n%s", format, path, got)
			}
		}
	}
}

func TestConfigIDHomePathIsPresentationOnly(t *testing.T) {
	t.Parallel()
	if got := presentConfigID(`cursor:managed:C:\Users\victorg\.cursor\hooks.json`); got != "cursor:managed:~/.cursor/hooks.json" {
		t.Fatalf("windows spelling = %s", got)
	}
	if got := presentConfigID("cursor:managed:/Users/victor/.cursor/hooks.json"); got != "cursor:managed:~/.cursor/hooks.json" {
		t.Fatalf("mac spelling = %s", got)
	}
	for _, id := range []string{
		"cursor:managed:~/.cursor/hooks.json",
		"cursor:managed:/etc/cursor/hooks.json",
		"cursor:repo:configs/hook.json",
		"claude:user:~/.claude/settings.json",
	} {
		if presentConfigID(id) != id {
			t.Fatalf("rewrote %s", id)
		}
	}

	cases := []struct {
		name string
		id   string
	}{
		{name: "linux", id: "cursor:managed:/home/victor/.cursor/hooks.json"},
		{name: "windows", id: "cursor:managed:C:/users/victorg/.cursor/hooks.json"},
	}
	const want = "cursor:managed:~/.cursor/hooks.json"
	for _, tc := range cases {
		finding := managedFinding()
		finding.Location.Path = "/etc/cursor/hooks.json"
		finding.Evidence[0].Config = &model.ConfigRef{ID: tc.id}
		finding = seal(t, finding)
		storedID := finding.Evidence[0].Config.ID
		storedFP := finding.Fingerprint
		for _, format := range allFormats {
			for _, mode := range []SARIFNonRepoLocation{SARIFNonRepoLogical, SARIFNonRepoURIBase} {
				options := testOptions()
				options.NonRepoSARIF = mode
				got := renderWith(t, format, []model.Finding{finding}, options)
				if finding.Evidence[0].Config.ID != storedID || finding.Fingerprint != storedFP {
					t.Fatal("render mutated the finding")
				}
				again, err := model.Fingerprint(finding.Rule, finding.Location, finding.Evidence)
				if err != nil {
					t.Fatal(err)
				}
				if again != storedFP || !strings.Contains(got, storedFP) {
					t.Fatalf("%s/%s/%s fingerprint changed\n%s", tc.name, format, mode, got)
				}
				if strings.Contains(strings.ToLower(got), "victor") {
					t.Fatalf("%s/%s/%s leaked a username\n%s", tc.name, format, mode, got)
				}
				if format == FormatJSON || format == FormatJSONL {
					if !strings.Contains(got, want) {
						t.Fatalf("%s/%s missing %s\n%s", tc.name, format, want, got)
					}
					validateFindingLines(t, got)
				}
			}
		}
	}
}

func TestManagedHomeSARIFUsesUserHomeBase(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/home/victor/.cursor/hooks.json", "C:/users/victorg/.cursor/hooks.json"} {
		finding := managedFinding()
		finding.Location.Path = path
		options := testOptions()
		options.NonRepoSARIF = SARIFNonRepoURIBase
		got := renderWith(t, FormatSARIF, sealAll(t, []model.Finding{finding}), options)
		validateSARIF(t, got)
		if strings.Contains(strings.ToLower(got), "victor") || strings.Contains(got, `"uriBaseId":"MANAGED"`) || strings.Contains(got, `"MANAGED"`) {
			t.Fatalf("managed home %s\n%s", path, got)
		}
		var log struct {
			Runs []struct {
				OriginalURIBaseIDs map[string]map[string]any `json:"originalUriBaseIds"`
				Results            []struct {
					Locations []struct {
						Physical *struct {
							Artifact struct {
								URI       string `json:"uri"`
								URIBaseID string `json:"uriBaseId"`
							} `json:"artifactLocation"`
						} `json:"physicalLocation"`
					} `json:"locations"`
					Properties struct {
						Tripcord struct {
							Scope string `json:"scope"`
							Path  string `json:"path"`
						} `json:"tripcord"`
					} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(got), &log); err != nil {
			t.Fatal(err)
		}
		run := log.Runs[0]
		if _, ok := run.OriginalURIBaseIDs[URIBaseUserHome]; !ok {
			t.Fatalf("bases = %+v", run.OriginalURIBaseIDs)
		}
		if _, ok := run.OriginalURIBaseIDs[URIBaseManaged]; ok {
			t.Fatalf("declared MANAGED for %s", path)
		}
		result := run.Results[0]
		if result.Properties.Tripcord.Scope != string(model.ScopeManaged) || result.Properties.Tripcord.Path != "~/.cursor/hooks.json" {
			t.Fatalf("properties = %+v", result.Properties.Tripcord)
		}
		artifact := result.Locations[0].Physical.Artifact
		if artifact.URI != ".cursor/hooks.json" || artifact.URIBaseID != URIBaseUserHome {
			t.Fatalf("artifact = %+v", artifact)
		}
	}
}

func TestSARIFRuleTextFallsBackToFinding(t *testing.T) {
	t.Parallel()
	options := testOptions()
	options.Rules = map[string]RuleText{
		"TC-CFG-010": {
			FullDescription: "Catalog description",
			Help:            "Catalog help",
			HelpURI:         "https://example.invalid/catalog/TC-CFG-010",
		},
		"TC-CFG-002": {HelpURI: "javascript:alert(1)"},
	}
	got := renderWith(t, FormatSARIF, sealAll(t, findings()), options)
	validateSARIF(t, got)
	for _, want := range []string{"Catalog description", "Catalog help", "https://example.invalid/catalog/TC-CFG-010"} {
		if !strings.Contains(got, want) {
			t.Fatalf("SARIF missing catalog text %q\n%s", want, got)
		}
	}
	for _, want := range []string{"Task runs on folder open", "Remove runOn: folderOpen.", "https://example.invalid/rules/TC-CFG-002"} {
		if !strings.Contains(got, want) {
			t.Fatalf("SARIF missing finding fallback %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "javascript:") {
		t.Fatalf("SARIF kept an unsafe catalog URI\n%s", got)
	}
}

func TestWindowsRootRelativizes(t *testing.T) {
	t.Parallel()
	ref := locate(model.Location{Scope: model.ScopeRepo, Path: "c:/users/alice/proj/src/a.json"}, `C:\Users\alice\proj`)
	if ref.kind != locRepo || ref.path != "src/a.json" || strings.Contains(strings.ToLower(ref.path), "alice") {
		t.Fatalf("located = %+v", ref)
	}
	for _, path := range []string{`C:\Users\alice\.cursor\hooks.json`, "c:/USERS/alice/.cursor/hooks.json", "/USERS/Alice/Library/Cursor/hooks.json"} {
		home := locate(model.Location{Scope: model.ScopeManaged, Path: path}, "")
		if !strings.HasPrefix(home.path, "~/") || strings.Contains(strings.ToLower(home.path+home.uri), "alice") {
			t.Fatalf("located %q = %+v", path, home)
		}
	}
	finding := findings()[0]
	finding.Location.Path = "c:/users/alice/proj/src/a.json"
	assertRejected(t, FormatText, finding)
}

func TestSortIsTotalOrder(t *testing.T) {
	t.Parallel()
	base := findings()[0]
	scope := base
	scope.Location.Scope = model.ScopeUser
	scope.Location.Path = "~/.cursor/hook.json"
	severity := base
	severity.Severity = model.SeverityCritical
	decision := base
	decision.Decision = model.DecisionAudit
	excerpt := base
	excerpt.Evidence = []model.Evidence{{Config: base.Evidence[0].Config, Excerpt: "other excerpt"}}
	input := []model.Finding{base, scope, severity, decision, excerpt}

	for _, format := range allFormats {
		want := ""
		permute(input, func(order []model.Finding) {
			got := render(t, format, order)
			if want == "" {
				want = got
				return
			}
			if got != want {
				t.Fatalf("%s output depends on input order:\n%s\n---\n%s", format, got, want)
			}
		})
	}
}

func permute(items []model.Finding, visit func([]model.Finding)) {
	items = append([]model.Finding(nil), items...)
	var walk func(int)
	walk = func(k int) {
		if k == len(items) {
			visit(append([]model.Finding(nil), items...))
			return
		}
		for i := k; i < len(items); i++ {
			items[k], items[i] = items[i], items[k]
			walk(k + 1)
			items[k], items[i] = items[i], items[k]
		}
	}
	walk(0)
}

func TestSARIFRuleMetadata(t *testing.T) {
	t.Parallel()
	var input []model.Finding
	for i, severity := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		finding := findings()[1]
		finding.Rule = fmt.Sprintf("TC-SEV-%03d", i+1)
		finding.Severity = severity
		finding.Fingerprint = "tcf_000000000000000" + string(rune('0'+i))
		finding.Refs = []string{"javascript:alert(1)", "file:///etc/passwd", "https://example.invalid/rules/" + string(severity)}
		input = append(input, finding)
	}
	low := findings()[1]
	low.Severity = model.SeverityLow
	low.Refs = nil
	critical := low
	critical.Severity = model.SeverityCritical
	critical.Fingerprint = "tcf_00000000000000ff"
	critical.Refs = []string{"https://example.invalid/rules/TC-CFG-002"}
	input = append(input, low, critical)

	got := render(t, FormatSARIF, input)
	validateSARIF(t, got)
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Version         string `json:"version"`
					SemanticVersion string `json:"semanticVersion"`
					Rules           []struct {
						ID              string            `json:"id"`
						FullDescription map[string]string `json:"fullDescription"`
						Help            map[string]string `json:"help"`
						HelpURI         string            `json:"helpUri"`
						Default         map[string]string `json:"defaultConfiguration"`
						Properties      map[string]any    `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(got), &log); err != nil {
		t.Fatal(err)
	}
	driver := log.Runs[0].Tool.Driver
	if driver.Version != "1.2.3" || driver.SemanticVersion != "1.2.3" {
		t.Fatalf("driver version = %q %q", driver.Version, driver.SemanticVersion)
	}
	want := map[string][3]string{
		"TC-SEV-001": {"9.5", "error", "https://example.invalid/rules/critical"},
		"TC-SEV-002": {"8.0", "error", "https://example.invalid/rules/high"},
		"TC-SEV-003": {"5.5", "warning", "https://example.invalid/rules/medium"},
		"TC-SEV-004": {"3.0", "note", "https://example.invalid/rules/low"},
		"TC-CFG-002": {"9.5", "error", "https://example.invalid/rules/TC-CFG-002"},
	}
	if len(driver.Rules) != len(want) {
		t.Fatalf("rules = %d", len(driver.Rules))
	}
	for _, rule := range driver.Rules {
		expect, ok := want[rule.ID]
		if !ok {
			t.Fatalf("unexpected rule %s", rule.ID)
		}
		if rule.Properties["security-severity"] != expect[0] || rule.Default["level"] != expect[1] || rule.HelpURI != expect[2] {
			t.Fatalf("rule %s metadata = %+v", rule.ID, rule)
		}
		tags, _ := rule.Properties["tags"].([]any)
		if len(tags) != 1 || tags[0] != "security" {
			t.Fatalf("rule %s tags = %v", rule.ID, rule.Properties["tags"])
		}
		if rule.FullDescription["text"] == "" || rule.Help["text"] == "" {
			t.Fatalf("rule %s lacks descriptions: %+v", rule.ID, rule)
		}
	}
}

func TestToolVersions(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, version, semantic string }{
		{"", "dev", "0.0.0-dev"},
		{"dev", "dev", "0.0.0-dev"},
		{"v0.4.0", "v0.4.0", "0.4.0"},
		{"1.2.3", "1.2.3", "1.2.3"},
		{"1.2.3-rc.1+abc", "1.2.3-rc.1+abc", "1.2.3-rc.1+abc"},
		{"01.2.3", "01.2.3", "0.0.0-dev"},
		{"1.2.3\n::error::x", `1.2.3\n::error::x`, "0.0.0-dev"},
	}
	for _, tc := range cases {
		version, semantic := toolVersions(tc.in)
		if version != tc.version || semantic != tc.semantic {
			t.Fatalf("toolVersions(%q) = %q, %q", tc.in, version, semantic)
		}
	}
}

func TestEscapeControls(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"\n::stop-commands::":  `\n::stop-commands::`,
		"\x1b[2K\r":            `\x1b[2K\r`,
		"a\\b":                 `a\\b`,
		"\u009b\u0085":         `\u009b\u0085`,
		"\u202ex\u2066\u2069":  `\u202ex\u2066\u2069`,
		"\u2028\u2029\u200e":   `\u2028\u2029\u200e`,
		"\xff":                 `\xff`,
		"plain [x](y) @o/t #1": "plain [x](y) @o/t #1",
	}
	for in, want := range cases {
		if got := escapeControls(in); got != want {
			t.Fatalf("escapeControls(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEscapeControlsKeepBackslashDisambiguatesHexEscapes checks that a
// literal backslash in text that keeps backslashes is only doubled when
// leaving it alone would read exactly like this package's own \xNN,
// \uXXXX, or \UXXXXXXXX escape for a real control character. The two
// must stay visually distinct: a literal "\x1b" (backslash, x, 1, b) is
// not the same as an actual ESC byte (\x1b produced by escaping 0x1b).
func TestEscapeControlsKeepBackslashDisambiguatesHexEscapes(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		`\x1b`:       `\\x1b`,
		"\x1b":       `\x1b`,
		`\u2028`:     `\\u2028`,
		"\u2028":     `\u2028`,
		`\U0001F600`: `\\U0001F600`,
		`C:\dir`:     `C:\dir`,
		`\new`:       `\new`,
		`\temp\x`:    `\temp\x`,
		`\xampp`:     `\xampp`,
		`\\`:         `\\`,
		`a\\b`:       `a\\b`,
	}
	for in, want := range cases {
		if got := escapeControlsKeepBackslash(in); got != want {
			t.Fatalf("escapeControlsKeepBackslash(%q) = %q, want %q", in, got, want)
		}
	}
}
