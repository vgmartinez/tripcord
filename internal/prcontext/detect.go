package prcontext

import (
	"fmt"
	"slices"
	"strings"
)

// Signal types. Each signal records which kind of evidence matched.
const (
	TypeBotLogin     = "bot-login"
	TypeCoAuthoredBy = "co-authored-by"
	TypeBranchPrefix = "branch-prefix"
	TypeGitAI        = "git-ai"
)

const (
	maxGitAISignals = 1000
	maxAgents       = 32
)

// Signal is one piece of evidence that an agent was involved.
type Signal struct {
	// Type is bot-login, co-authored-by, branch-prefix, or git-ai.
	Type string `json:"type"`
	// Agent is the normalized agent id the evidence mapped to.
	Agent string `json:"agent"`
	// Value is the login, trailer address, branch name, or git-ai tool
	// that matched.
	Value string `json:"value"`
	// Source is the pull request field or commit the evidence came from.
	Source string `json:"source"`
}

// Result is the normalized pr-context decision. Agent is true when
// Signals is non-empty. Warnings describe evidence that could not be
// read (a shallow clone, an unreadable authorship note); they do not
// make the result a failure.
type Result struct {
	Agent    bool     `json:"agent"`
	Agents   []string `json:"agents"`
	Signals  []Signal `json:"signals"`
	Warnings []string `json:"warnings,omitempty"`
}

// Commit is one commit in base..head.
type Commit struct {
	SHA            string
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	Message        string
	// NoteTools are the validated tool ids extracted while refs/notes/ai was
	// streamed. ReadCommits never retains the original note text.
	NoteTools []string
	// Note is accepted only for callers that construct Commit directly. It is
	// parsed by Detect for compatibility; ReadCommits leaves it empty.
	Note string
}

// Input is everything Detect needs. BranchSource names where Branch came
// from, either "pull_request.head.ref" or "--head". Warnings from reading
// git are copied onto the result.
type Input struct {
	PRLogin string
	// PRAuthorType is GitHub's user.type for the pull request author.
	// Empty means the event did not include it.
	PRAuthorType string
	Branch       string
	BranchSource string
	Commits      []Commit
	Warnings     []string
}

// Detect applies the four signals to in. It does not run git and it does
// not fail when a note cannot be parsed: that becomes a warning.
func Detect(in Input) Result {
	b := &builder{seen: map[string]bool{}, agents: map[string]bool{}}
	warnings := append([]string{}, in.Warnings...)
	if agent, ok := agentForPRLogin(in.PRLogin, in.PRAuthorType); ok {
		b.add(TypeBotLogin, agent, in.PRLogin, "pull_request.user.login")
	}
	branch := strings.TrimPrefix(in.Branch, "refs/heads/")
	if agent, ok := branchAgent(branch); ok {
		source := in.BranchSource
		if source == "" {
			source = "pull_request.head.ref"
		}
		b.add(TypeBranchPrefix, agent, branch, source)
	}
	for _, c := range in.Commits {
		from := "commit " + c.SHA
		b.identity(TypeBotLogin, c.AuthorName, c.AuthorEmail, from+" author")
		b.identity(TypeBotLogin, c.CommitterName, c.CommitterEmail, from+" committer")
		for _, trailer := range coAuthors(c.Message) {
			b.trailer(trailer, from+" trailer")
		}
		tools := c.NoteTools
		if tools == nil && c.Note != "" {
			var err error
			tools, err = toolsFromNote(c.Note)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("commit %s: %s", c.SHA, err.Error()))
				continue
			}
		}
		for _, tool := range tools {
			if b.gitAISignals == maxGitAISignals {
				b.gitAISignalsLimited = true
				break
			}
			b.gitAISignals++
			b.add(TypeGitAI, canonicalAgent(tool), tool, from+" refs/notes/ai")
		}
	}
	agents := make([]string, 0, len(b.agents))
	for agent := range b.agents {
		agents = append(agents, agent)
	}
	slices.Sort(agents)
	if b.signals == nil {
		b.signals = []Signal{}
	}
	if b.gitAISignalsLimited {
		warnings = append(warnings, fmt.Sprintf("git-ai signals kept at most %d; later signals were skipped", maxGitAISignals))
	}
	if b.agentsLimited {
		warnings = append(warnings, fmt.Sprintf("agent output kept at most %d distinct agents; later agents were skipped", maxAgents))
	}
	return Result{
		Agent:    len(b.signals) > 0,
		Agents:   agents,
		Signals:  b.signals,
		Warnings: warnings,
	}
}

type builder struct {
	signals             []Signal
	seen                map[string]bool
	agents              map[string]bool
	gitAISignals        int
	gitAISignalsLimited bool
	agentsLimited       bool
}

func (b *builder) add(kind, agent, value, source string) {
	switch kind {
	case TypeBotLogin, TypeCoAuthoredBy, TypeBranchPrefix, TypeGitAI:
	default:
		panic("prcontext: unhandled signal type " + kind)
	}
	value = oneLine(value)
	if agent == "" || value == "" || source == "" {
		return
	}
	key := kind + "\x00" + agent + "\x00" + value + "\x00" + source
	if b.seen[key] {
		return
	}
	if !b.agents[agent] && len(b.agents) == maxAgents {
		b.agentsLimited = true
	} else {
		b.agents[agent] = true
	}
	b.seen[key] = true
	b.signals = append(b.signals, Signal{Type: kind, Agent: agent, Value: value, Source: source})
}

// identity matches a commit author or committer. The name is tried as a
// bot login first; the address is tried as a GitHub noreply login. A
// trailer email on an author address is not a bot-login signal.
func (b *builder) identity(kind, name, email, source string) {
	if agent, ok := agentForLogin(name); ok {
		b.add(kind, agent, name, source)
		return
	}
	if agent, _, ok := agentForNoReply(email); ok {
		b.add(kind, agent, email, source)
	}
}

func (b *builder) trailer(value, source string) {
	name, email := splitIdentity(value)
	if agent, ok := agentForLogin(name); ok {
		b.add(TypeCoAuthoredBy, agent, name, source)
		return
	}
	if agent, ok := agentForEmail(email); ok {
		b.add(TypeCoAuthoredBy, agent, email, source)
		return
	}
	if agent, _, ok := agentForNoReply(email); ok {
		b.add(TypeCoAuthoredBy, agent, email, source)
	}
}
