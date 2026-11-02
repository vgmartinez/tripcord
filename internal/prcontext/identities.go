package prcontext

import "strings"

// agentID is one unverified way an agent signs its work. match is
// compared exactly (logins and emails case-insensitively, branch
// prefixes case-sensitively). A value that only resembles match, such
// as the login claude-bot, does not match.
type agentID struct {
	match string
	agent string
}

// The three tables below are hints, not a trust decision, and they are
// not confirmed against vendor documentation. A login, trailer, or
// branch that is absent here is reported as not an agent even when a
// human would recognize it.

// botLogins are GitHub accounts treated as coding-agent authors. The
// match is the whole login, case-insensitive, including the [bot]
// suffix. A display name such as "Claude" is not a login and is not in
// this table. Review bots such as gemini-code-assist[bot] are not
// listed: they comment on pull requests but do not author the changes.
//
// TODO(#34): Verify the unverified agent identity tables (botLogins, trailerEmails, branchPrefixes) and replace 0 with the tracking issue.
var botLogins = []agentID{
	{match: "copilot-swe-agent[bot]", agent: "copilot"},
	{match: "copilot[bot]", agent: "copilot"},
	{match: "chatgpt-codex-connector[bot]", agent: "codex"},
	{match: "claude[bot]", agent: "claude"},
	{match: "cursor[bot]", agent: "cursor"},
	{match: "devin-ai-integration[bot]", agent: "devin"},
	{match: "google-labs-jules[bot]", agent: "jules"},
}

// trailerEmails are Co-authored-by addresses treated as coding-agent
// attribution. The match is the whole address, case-insensitive.
// Display names are not matched: "Claude Shannon <shannon@example.com>"
// is a human, and "Claude Opus <noreply@anthropic.com>" matches because
// of the address. Codex CLI has no address here. Codex is recognized
// only as chatgpt-codex-connector[bot] and the codex/ branch prefix.
//
// TODO(#34): Verify the unverified agent identity tables (botLogins, trailerEmails, branchPrefixes) and replace 0 with the tracking issue.
var trailerEmails = []agentID{
	{match: "noreply@anthropic.com", agent: "claude"},
	{match: "cursoragent@cursor.com", agent: "cursor"},
	{match: "copilot@github.com", agent: "copilot"},
	{match: "noreply@opencode.ai", agent: "opencode"},
	{match: "windsurf@codeium.com", agent: "windsurf"},
}

// branchPrefixes are the start of a head branch name, including the
// slash. The comparison is case-sensitive, so Claude/foo does not match
// claude/. A name that merely contains the word, such as
// feature/claude-fix or notclaude/foo, does not match.
//
// TODO(#34): Verify the unverified agent identity tables (botLogins, trailerEmails, branchPrefixes) and replace 0 with the tracking issue.
var branchPrefixes = []agentID{
	{match: "claude/", agent: "claude"},
	{match: "cursor/", agent: "cursor"},
	{match: "copilot/", agent: "copilot"},
	{match: "codex/", agent: "codex"},
	{match: "devin/", agent: "devin"},
}

// canonicalAliases map a lowercased git-ai tool name onto a canonical
// agent id. The raw tool string stays in the signal value. A tool that
// is already a canonical id, or that is not listed, passes through
// lowercased.
var canonicalAliases = []agentID{
	{match: "claude-code", agent: "claude"},
}

// canonicalAgent maps a git-ai tool name to the id stored on
// signals[].agent and in agents[].
func canonicalAgent(tool string) string {
	tool = strings.ToLower(strings.TrimSpace(tool))
	for _, id := range canonicalAliases {
		if tool == id.match {
			return id.agent
		}
	}
	return tool
}

func agentForLogin(login string) (agent string, ok bool) {
	login = strings.ToLower(strings.TrimSpace(login))
	// A login counts only with the [bot] suffix. Bare names such as
	// "claude" are not bot accounts.
	if login == "" || !strings.HasSuffix(login, "[bot]") {
		return "", false
	}
	for _, id := range botLogins {
		if login == strings.ToLower(id.match) {
			return id.agent, true
		}
	}
	return "", false
}

// copilotPRLogin is the exact login GitHub's Copilot coding agent uses
// to open a pull request. Unlike the accounts in botLogins, it carries
// no [bot] suffix, so a bare "Copilot" cannot be told apart from a human
// by login alone; it is matched only alongside user.type "Bot" (see
// gh-aw project issue #1972).
const copilotPRLogin = "copilot"

// agentForPRLogin matches the pull request author. When authorType is
// set, it is GitHub's user.type and must be "Bot". A [bot] login whose
// type is present and not "Bot" does not match. An empty authorType
// means the event omitted user.type, and the login table decides alone.
// Commit authors have no user.type and use agentForLogin directly.
func agentForPRLogin(login, authorType string) (agent string, ok bool) {
	if authorType != "" && authorType != "Bot" {
		return "", false
	}
	if agent, ok := agentForLogin(login); ok {
		return agent, true
	}
	// copilotPRLogin requires authorType == "Bot" exactly: an empty
	// authorType (the event omitted user.type) must not match, since a
	// human account can also be named "Copilot".
	if authorType == "Bot" && strings.EqualFold(strings.TrimSpace(login), copilotPRLogin) {
		return "copilot", true
	}
	return "", false
}

func agentForEmail(email string) (agent string, ok bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", false
	}
	for _, id := range trailerEmails {
		if email == strings.ToLower(id.match) {
			return id.agent, true
		}
	}
	return "", false
}

// gitHubNoReplyLogin returns the login embedded in a GitHub noreply
// address: "<id>+<login>@users.noreply.github.com" or
// "<login>@users.noreply.github.com". The id must be all digits. A
// non-numeric prefix is refused, so "notreally+copilot-swe-agent[bot]@..."
// cannot borrow the login after the plus.
func gitHubNoReplyLogin(email string) (string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	const host = "@users.noreply.github.com"
	if !strings.HasSuffix(email, host) {
		return "", false
	}
	local := email[:len(email)-len(host)]
	if local == "" || strings.Contains(local, "@") {
		return "", false
	}
	if plus := strings.LastIndex(local, "+"); plus >= 0 {
		id := local[:plus]
		if id == "" || strings.Trim(id, "0123456789") != "" {
			return "", false
		}
		local = local[plus+1:]
	}
	if local == "" {
		return "", false
	}
	return local, true
}

func agentForNoReply(email string) (agent, login string, ok bool) {
	login, ok = gitHubNoReplyLogin(email)
	if !ok {
		return "", "", false
	}
	agent, ok = agentForLogin(login)
	if !ok {
		return "", "", false
	}
	return agent, login, true
}

// branchAgent reports the agent whose prefix starts branch. A leading
// refs/heads/ is ignored. The comparison is case-sensitive.
func branchAgent(branch string) (agent string, ok bool) {
	branch = strings.TrimPrefix(branch, "refs/heads/")
	if branch == "" {
		return "", false
	}
	for _, id := range branchPrefixes {
		if strings.HasPrefix(branch, id.match) {
			return id.agent, true
		}
	}
	return "", false
}
