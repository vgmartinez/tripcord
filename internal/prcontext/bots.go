package prcontext

import "strings"

// BotInvolved reports whether in names a bot, including bots that are
// not in the agent identity tables. It does not affect Detect: is_agent
// and agents stay limited to those tables. TC-CFG-014 uses this to
// widen its scope to every bot the spec names.
//
// A pull request author matches when user.type is Bot or the login ends
// in [bot]. A commit author, committer, or Co-authored-by trailer matches
// when the name or the GitHub noreply login ends in [bot]. The comparison
// is case-insensitive. A login that only resembles a bot, such as
// dependabot-bot, does not match.
func BotInvolved(in Input) bool {
	if in.PRAuthorType == "Bot" || botSuffix(in.PRLogin) {
		return true
	}
	for _, c := range in.Commits {
		if botIdentity(c.AuthorName, c.AuthorEmail) || botIdentity(c.CommitterName, c.CommitterEmail) {
			return true
		}
		for _, trailer := range coAuthors(c.Message) {
			name, email := splitIdentity(trailer)
			if botIdentity(name, email) {
				return true
			}
		}
	}
	return false
}

func botIdentity(name, email string) bool {
	if botSuffix(name) {
		return true
	}
	login, ok := gitHubNoReplyLogin(email)
	return ok && botSuffix(login)
}

func botSuffix(login string) bool {
	login = strings.TrimSpace(login)
	return login != "" && strings.HasSuffix(strings.ToLower(login), "[bot]")
}
