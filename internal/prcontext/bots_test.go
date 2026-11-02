package prcontext

import "testing"

func TestBotInvolvedDoesNotChangeDetection(t *testing.T) {
	in := Input{
		PRLogin:      "dependabot[bot]",
		PRAuthorType: "Bot",
		Commits: []Commit{{
			SHA:            "abc",
			AuthorName:     "Ada Lovelace",
			AuthorEmail:    "ada@example.com",
			CommitterName:  "github-actions[bot]",
			CommitterEmail: "41898282+github-actions[bot]@users.noreply.github.com",
			Message:        "subject\n\nCo-authored-by: dependabot[bot] <dependabot[bot]@users.noreply.github.com>\n",
		}},
	}
	if !BotInvolved(in) {
		t.Fatal("dependabot author was not in scope")
	}
	got := Detect(in)
	if got.Agent || len(got.Agents) != 0 {
		t.Fatalf("bot scope changed detection: %+v", got)
	}

	if !BotInvolved(Input{PRAuthorType: "Bot", PRLogin: "octocat"}) {
		t.Fatal("user.type Bot was not in scope")
	}
	if !BotInvolved(Input{PRLogin: "Some[Bot]", PRAuthorType: "User"}) {
		t.Fatal("[bot] login was not in scope")
	}
	if BotInvolved(Input{PRLogin: "dependabot-bot", PRAuthorType: "User"}) {
		t.Fatal("a login without the [bot] suffix matched")
	}
	if BotInvolved(Input{Commits: []Commit{{
		Message: "Co-authored-by: dependabot[bot] <dependabot[bot]@users.noreply.github.com>\n\nnot a trailer\n",
	}}}) {
		t.Fatal("a co-author mention outside the trailer block matched")
	}
	if !BotInvolved(Input{Commits: []Commit{{
		AuthorName:  "Ada",
		AuthorEmail: "ada@example.com",
		Message:     "subject\n\nCo-authored-by: github-actions[bot] <github-actions[bot]@users.noreply.github.com>\n",
	}}}) {
		t.Fatal("trailer bot was not in scope")
	}
}
