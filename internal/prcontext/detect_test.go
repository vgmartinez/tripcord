package prcontext

import (
	"fmt"
	"strings"
	"testing"
)

func aiNote(tool string) string {
	return "src/a.txt\n  s_aaaaaaaaaaaaaa::t_bbbbbbbbbbbbbb 1-2\n---\n" +
		`{"schema_version":"authorship/3.0.0","base_commit_sha":"abc","prompts":{},"sessions":{"s_aaaaaaaaaaaaaa":{"agent_id":{"tool":"` + tool + `","id":"1","model":"m"}}}}` + "\n"
}

func TestDetectEverySignal(t *testing.T) {
	t.Parallel()
	sha := "0123456789abcdef0123456789abcdef01234567"
	got := Detect(Input{
		PRLogin: "claude[bot]",
		Branch:  "cursor/add-thing",
		Commits: []Commit{{
			SHA:            sha,
			AuthorName:     "Copilot",
			AuthorEmail:    "198982749+copilot-swe-agent[bot]@users.noreply.github.com",
			CommitterName:  "devin-ai-integration[bot]",
			CommitterEmail: "human@example.com",
			Message:        "subject\n\nCo-authored-by: Ada Lovelace <ada@example.com>\nCo-authored-by: Claude <noreply@anthropic.com>\n",
			Note:           aiNote("codex"),
		}},
	})
	if !got.Agent {
		t.Fatal("agent = false")
	}
	if strings.Join(got.Agents, ",") != "claude,codex,copilot,cursor,devin" {
		t.Fatalf("agents = %v", got.Agents)
	}
	wantTypes := []string{TypeBotLogin, TypeBranchPrefix, TypeBotLogin, TypeBotLogin, TypeCoAuthoredBy, TypeGitAI}
	if len(got.Signals) != len(wantTypes) {
		t.Fatalf("signals = %+v", got.Signals)
	}
	for i, kind := range wantTypes {
		if got.Signals[i].Type != kind {
			t.Errorf("signal %d type = %s, want %s (%+v)", i, got.Signals[i].Type, kind, got.Signals)
		}
	}
	if got.Signals[0].Source != "pull_request.user.login" || got.Signals[0].Value != "claude[bot]" {
		t.Errorf("pr login signal = %+v", got.Signals[0])
	}
	if got.Signals[1].Source != "pull_request.head.ref" || got.Signals[1].Value != "cursor/add-thing" {
		t.Errorf("branch signal = %+v", got.Signals[1])
	}
	if got.Signals[2].Source != "commit "+sha+" author" || !strings.Contains(got.Signals[2].Value, "copilot-swe-agent[bot]") {
		t.Errorf("author signal = %+v", got.Signals[2])
	}
	if got.Signals[3].Source != "commit "+sha+" committer" || got.Signals[3].Agent != "devin" {
		t.Errorf("committer signal = %+v", got.Signals[3])
	}
	if got.Signals[4].Value != "noreply@anthropic.com" || got.Signals[4].Source != "commit "+sha+" trailer" {
		t.Errorf("trailer signal = %+v", got.Signals[4])
	}
	if got.Signals[5].Value != "codex" || got.Signals[5].Source != "commit "+sha+" refs/notes/ai" {
		t.Errorf("note signal = %+v", got.Signals[5])
	}
}

func TestDetectNegatives(t *testing.T) {
	t.Parallel()
	sha := "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	for _, tc := range []struct {
		name string
		in   Input
	}{
		{name: "human pr", in: Input{PRLogin: "octocat", Branch: "feature/docs"}},
		{name: "forged login without bot suffix", in: Input{PRLogin: "claude-bot", Branch: "feature/docs"}},
		{name: "login that only contains a bot login", in: Input{PRLogin: "not-copilot-swe-agent[bot]"}},
		{name: "bare claude login", in: Input{PRLogin: "claude"}},
		{name: "branch contains claude but is not a prefix", in: Input{Branch: "feature/claude-fix"}},
		{name: "branch word without slash", in: Input{Branch: "claude-fix"}},
		{name: "prefix lookalike", in: Input{Branch: "notclaude/foo"}},
		{name: "prefix is case sensitive", in: Input{Branch: "Claude/foo"}},
		{name: "human co-author", in: Input{Commits: []Commit{{SHA: sha, Message: "subject\n\nCo-authored-by: Ada Lovelace <ada@example.com>\n"}}}},
		{name: "claude display name with a human address", in: Input{Commits: []Commit{{SHA: sha, Message: "subject\n\nCo-authored-by: Claude <ada@example.com>\n"}}}},
		{name: "human named claude shannon", in: Input{Commits: []Commit{{SHA: sha, Message: "subject\n\nCo-authored-by: Claude Shannon <shannon@example.com>\n"}}}},
		{name: "co-authored-by mentioned before the trailer block", in: Input{Commits: []Commit{{SHA: sha, Message: "Co-authored-by: Claude <noreply@anthropic.com>\n\ndid the work\n"}}}},
		{name: "spoofed noreply plus-prefix", in: Input{Commits: []Commit{{SHA: sha, AuthorEmail: "notreally+copilot-swe-agent[bot]@users.noreply.github.com"}}}},
		{name: "noreply login that is not a known bot", in: Input{Commits: []Commit{{SHA: sha, AuthorEmail: "123+claude-bot@users.noreply.github.com"}}}},
		{name: "human only authorship note", in: Input{Commits: []Commit{{SHA: sha, Note: "src/a.txt\n  h_aaaaaaaaaaaaaa 1-2\n---\n" + `{"schema_version":"authorship/3.0.0","base_commit_sha":"abc","prompts":{},"humans":{"h_aaaaaaaaaaaaaa":{"author":"Ada <ada@example.com>"}}}` + "\n"}}}},
		{name: "empty", in: Input{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Detect(tc.in)
			if got.Agent || len(got.Signals) != 0 || len(got.Agents) != 0 {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestDetectTrailerAndNoteVariants(t *testing.T) {
	t.Parallel()
	sha := "0123456789abcdef0123456789abcdef01234567"
	got := Detect(Input{Commits: []Commit{{
		SHA:         sha,
		AuthorName:  "Copilot-Swe-Agent[bot]",
		AuthorEmail: "someone@example.com",
		Message: strings.Join([]string{
			"subject",
			"",
			"Signed-off-by: Ada Lovelace <ada@example.com>",
			"Co-Authored-By: Cursor <cursoragent@cursor.com>",
			"co-authored-by: windsurf <windsurf@codeium.com>",
		}, "\n"),
		Note: `{"schema_version":"authorship/3.0.0","base_commit_sha":"abc","prompts":{"0123456789abcdef":{"agent_id":{"tool":"copilot","id":"1","model":"x"}}},"sessions":{"s_bbbbbbbbbbbbbb":{"agent_id":{"tool":"opencode","id":"2","model":"y"}}}}`,
	}}})
	if strings.Join(got.Agents, ",") != "copilot,cursor,opencode,windsurf" {
		t.Fatalf("agents = %v", got.Agents)
	}
	var kinds []string
	for _, s := range got.Signals {
		kinds = append(kinds, s.Type+" "+s.Agent)
	}
	if strings.Join(kinds, ", ") != "bot-login copilot, co-authored-by cursor, co-authored-by windsurf, git-ai copilot, git-ai opencode" {
		t.Fatalf("signals = %v", kinds)
	}
}

func TestDetectUnreadableNoteWarns(t *testing.T) {
	t.Parallel()
	sha := "0123456789abcdef0123456789abcdef01234567"
	got := Detect(Input{
		Branch:   "refs/heads/devin/fix",
		Warnings: []string{"commit range old..new is not in this clone; commit and note signals were skipped"},
		Commits:  []Commit{{SHA: sha, Note: "this is not a log"}},
	})
	if !got.Agent || len(got.Signals) != 1 || got.Signals[0].Agent != "devin" || got.Signals[0].Value != "devin/fix" {
		t.Fatalf("signals = %+v", got.Signals)
	}
	if len(got.Warnings) != 2 || !strings.Contains(got.Warnings[1], sha) {
		t.Fatalf("warnings = %v", got.Warnings)
	}
}

func TestDetectRejectsUnsafeToolName(t *testing.T) {
	t.Parallel()
	sha := "0123456789abcdef0123456789abcdef01234567"
	got := Detect(Input{Commits: []Commit{{SHA: sha, Note: aiNote("../bin/sh")}}})
	if got.Agent || len(got.Warnings) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestCanonicalGitAI(t *testing.T) {
	t.Parallel()
	sha := "0123456789abcdef0123456789abcdef01234567"
	for _, tc := range []struct {
		tool  string
		agent string
		value string
	}{
		{tool: "claude-code", agent: "claude", value: "claude-code"},
		{tool: "Claude-Code", agent: "claude", value: "Claude-Code"},
		{tool: "amp", agent: "amp", value: "amp"},
		{tool: "AMP", agent: "amp", value: "AMP"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			t.Parallel()
			got := Detect(Input{Commits: []Commit{{SHA: sha, Note: aiNote(tc.tool)}}})
			if !got.Agent || len(got.Agents) != 1 || got.Agents[0] != tc.agent {
				t.Fatalf("agents = %v, want %s", got.Agents, tc.agent)
			}
			if len(got.Signals) != 1 || got.Signals[0].Agent != tc.agent || got.Signals[0].Value != tc.value {
				t.Fatalf("signal = %+v", got.Signals)
			}
		})
	}
}

func TestDetectCapsManyGitAITools(t *testing.T) {
	var commits []Commit
	for i := range 100 {
		var note strings.Builder
		note.WriteString(`{"sessions":{`)
		for j := range maxToolsPerNote + 4 {
			if j > 0 {
				note.WriteByte(',')
			}
			fmt.Fprintf(&note, `%q:{"agent_id":{"tool":%q}}`, fmt.Sprintf("s-%d-%d", i, j), fmt.Sprintf("agent%d-%d", i, j))
		}
		note.WriteString(`}}`)
		tools, limited, err := toolsFromNoteReader(strings.NewReader(note.String()))
		if err != nil {
			t.Fatal(err)
		}
		if !limited || len(tools) != maxToolsPerNote {
			t.Fatalf("note %d: limited %v tools %d", i, limited, len(tools))
		}
		commits = append(commits, Commit{
			SHA:       fmt.Sprintf("%040x", i+1),
			NoteTools: tools,
		})
	}
	got := Detect(Input{Commits: commits})
	if len(got.Signals) != maxGitAISignals {
		t.Fatalf("signals = %d, want %d", len(got.Signals), maxGitAISignals)
	}
	if len(got.Agents) != maxAgents {
		t.Fatalf("agents = %d, want %d", len(got.Agents), maxAgents)
	}
	if output := FormatOutput(got); len(output) > 4096 {
		t.Fatalf("GITHUB_OUTPUT fragment is %d bytes", len(output))
	}
	if strings.Join(got.Warnings, "\n") !=
		"git-ai signals kept at most 1000; later signals were skipped\n"+
			"agent output kept at most 32 distinct agents; later agents were skipped" {
		t.Fatalf("warnings = %v", got.Warnings)
	}
}

func TestPRAuthorType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		typ  string
		want bool
	}{
		{name: "type User", typ: "User", want: false},
		{name: "type Bot", typ: "Bot", want: true},
		{name: "no type field", typ: "", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Detect(Input{PRLogin: "claude[bot]", PRAuthorType: tc.typ})
			if got.Agent != tc.want || (tc.want && (len(got.Signals) != 1 || got.Signals[0].Agent != "claude")) {
				t.Fatalf("Detect(type %q) = %+v, want agent %v", tc.typ, got, tc.want)
			}
			if !tc.want && len(got.Signals) != 0 {
				t.Fatalf("type %q matched: %+v", tc.typ, got.Signals)
			}
		})
	}
	// A commit author has no user.type. The [bot] login still matches.
	sha := "0123456789abcdef0123456789abcdef01234567"
	got := Detect(Input{Commits: []Commit{{SHA: sha, AuthorName: "claude[bot]"}}})
	if !got.Agent || got.Signals[0].Source != "commit "+sha+" author" {
		t.Fatalf("commit author = %+v", got)
	}
}

// TestCopilotPRLogin covers GitHub's Copilot coding agent, whose pull
// request login is the literal "Copilot" with no [bot] suffix (gh-aw
// project issue #1972). It must match only alongside user.type "Bot":
// an absent or "User" type could just as well be a human so named.
func TestCopilotPRLogin(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		login string
		typ   string
		want  bool
	}{
		{name: "Copilot with type Bot", login: "Copilot", typ: "Bot", want: true},
		{name: "copilot lowercase with type Bot", login: "copilot", typ: "Bot", want: true},
		{name: "Copilot with no type", login: "Copilot", typ: "", want: false},
		{name: "Copilot with type User", login: "Copilot", typ: "User", want: false},
		{name: "login merely contains copilot", login: "copilot-fan", typ: "Bot", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Detect(Input{PRLogin: tc.login, PRAuthorType: tc.typ})
			if got.Agent != tc.want {
				t.Fatalf("Detect(login %q, type %q) = %+v, want agent %v", tc.login, tc.typ, got, tc.want)
			}
			if tc.want && (len(got.Signals) != 1 || got.Signals[0].Agent != "copilot" || got.Signals[0].Source != "pull_request.user.login") {
				t.Fatalf("signals = %+v", got.Signals)
			}
			if !tc.want && len(got.Signals) != 0 {
				t.Fatalf("login %q type %q matched: %+v", tc.login, tc.typ, got.Signals)
			}
		})
	}
	// Copilot's login has no [bot] suffix, so a commit author (which has
	// no user.type) must never match it.
	sha := "0123456789abcdef0123456789abcdef01234567"
	got := Detect(Input{Commits: []Commit{{SHA: sha, AuthorName: "Copilot"}}})
	if got.Agent {
		t.Fatalf("commit author %q matched copilot: %+v", "Copilot", got)
	}
}

func TestParseEvent(t *testing.T) {
	t.Parallel()
	ev, err := ParseEvent([]byte(`{"action":"opened","pull_request":{"user":{"login":"octocat"},"head":{"ref":"cursor/x","sha":"abc"},"base":{"sha":"def"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Login != "octocat" || ev.Branch != "cursor/x" || ev.Head != "abc" || ev.Base != "def" {
		t.Fatalf("event = %+v", ev)
	}
	ev, err = ParseEvent([]byte(`{"user":{"login":"claude[bot]"},"head":{"ref":"claude/y","sha":"abc"},"base":{"sha":"def"}}`))
	if err != nil || ev.Login != "claude[bot]" || ev.AuthorType != "" {
		t.Fatalf("bare pull_request = %+v, %v", ev, err)
	}
	ev, err = ParseEvent([]byte(`{"pull_request":{"user":{"login":"claude[bot]","type":"User"},"head":{"ref":"a","sha":"abc"},"base":{"sha":"def"}}}`))
	if err != nil || ev.AuthorType != "User" {
		t.Fatalf("type User = %+v, %v", ev, err)
	}
	ev, err = ParseEvent([]byte(`{"pull_request":{"user":{"login":"claude[bot]","type":"Bot"},"head":{"ref":"a","sha":"abc"},"base":{"sha":"def"}}}`))
	if err != nil || ev.AuthorType != "Bot" {
		t.Fatalf("type Bot = %+v, %v", ev, err)
	}
	for _, raw := range []string{``, `[]`, `{"zen":"x"}`, "{\"pull_request\":{\"user\":{\"login\":\"a\\nb\"}}}"} {
		if _, err := ParseEvent([]byte(raw)); err == nil {
			t.Errorf("ParseEvent(%q) succeeded", raw)
		}
	}
}

func TestValidateRev(t *testing.T) {
	t.Parallel()
	if err := ValidateRev("base", "refs/heads/main"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "-upload-pack", "a..b", "a\nb", "HEAD@{1}", "a^b", "a:b", "a~1", "a\\b", "a?b", "a*b", "a[b", "a{b"} {
		if err := ValidateRev("head", bad); err == nil {
			t.Errorf("ValidateRev(%q) succeeded", bad)
		}
	}
}

func TestFormat(t *testing.T) {
	t.Parallel()
	r := Detect(Input{PRLogin: "cursor[bot]"})
	text := FormatText(r)
	if !strings.Contains(text, "agent: true\n") || !strings.Contains(text, "agents: cursor\n") || !strings.Contains(text, "type: bot-login\n") {
		t.Fatalf("text = %q", text)
	}
	js, err := FormatJSON(r)
	if err != nil || !strings.Contains(string(js), "\"agent\": true") || !strings.HasSuffix(string(js), "\n") {
		t.Fatalf("json = %q, %v", js, err)
	}
	if got := FormatOutput(r); got != "is_agent=true\nagents=cursor\n" {
		t.Fatalf("output = %q", got)
	}
	empty := Detect(Input{})
	js, err = FormatJSON(empty)
	if err != nil || !strings.Contains(string(js), "\"agents\": []") || !strings.Contains(string(js), "\"signals\": []") || strings.Contains(string(js), "warnings") {
		t.Fatalf("empty json = %q, %v", js, err)
	}
	if got := FormatOutput(empty); got != "is_agent=false\nagents=\n" {
		t.Fatalf("empty output = %q", got)
	}
}
