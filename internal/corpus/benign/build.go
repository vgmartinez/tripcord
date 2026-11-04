package benign

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MinStars is the star count a repository must reach to be kept.
const MinStars = 50

// Options controls one index build.
type Options struct {
	// Target is how many repositories to keep. The default is 1000.
	Target int
	// Now is the generation date stored on every row.
	Now time.Time
	// PerHarness is the most root matches collected for one harness.
	// The default is 2000, which covers both index orders of the
	// 1,000-result search cap.
	PerHarness int
}

// Result is the stratified index and any reason it is short of Target.
type Result struct {
	Repos []Repo
	Notes []string
	When  time.Time
}

// Build searches GitHub for root agent configs, drops archived repos,
// forks, and repos under MinStars, and stratifies what remains.
// It does not download file contents.
func Build(ctx context.Context, c *Client, opt Options, log func(string)) (Result, error) {
	if opt.Target <= 0 {
		opt.Target = 1000
	}
	if opt.PerHarness <= 0 {
		opt.PerHarness = 2000
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now().UTC()
	}
	if log == nil {
		log = func(string) {}
	}
	date := opt.Now.UTC().Format(time.DateOnly)
	cands := map[string]*candidate{}
	var notes []string
	if err := collect(ctx, c, opt.PerHarness, cands, log); err != nil {
		notes = append(notes, "GitHub code search stopped the crawl: "+err.Error())
		log(notes[len(notes)-1])
		if len(cands) == 0 {
			return Result{}, err
		}
	}
	names := make([]string, 0, len(cands))
	for name, cand := range cands {
		if cand.fork {
			continue
		}
		names = append(names, name)
	}
	log(fmt.Sprintf("hydrating %d repositories", len(names)))
	metas, err := c.Hydrate(ctx, names)
	if err != nil {
		notes = append(notes, "repository metadata stopped early: "+err.Error())
		log(notes[len(notes)-1])
	}
	var kept []Repo
	for _, m := range metas {
		if m.Missing || m.Fork || m.Archived || m.Stars < MinStars || m.SHA == "" {
			continue
		}
		cand := cands[m.Name]
		if cand == nil {
			// The API may canonicalize owner/repo capitalization.
			for name, cnd := range cands {
				if strings.EqualFold(name, m.Name) {
					cand = cnd
					break
				}
			}
		}
		if cand == nil {
			continue
		}
		var hs []string
		for h := range cand.harnesses {
			hs = append(hs, h)
		}
		license := m.License
		if license == "" {
			license = "NOASSERTION"
		}
		kept = append(kept, Repo{
			Name:      m.Name,
			SHA:       strings.ToLower(m.SHA),
			License:   license,
			Harnesses: hs,
			Date:      date,
			Stars:     m.Stars,
			SizeKB:    m.SizeKB,
		})
	}
	selected := Select(kept, opt.Target)
	if c.slow && len(selected) < opt.Target {
		notes = append(notes, "GitHub code search asked for a wait this run could not absorb, so later pages were skipped")
	}
	if len(selected) < opt.Target && len(notes) == 0 {
		notes = append(notes, fmt.Sprintf("code search was exhausted with %d repositories after the star, archive, and fork filters", len(kept)))
	}
	if len(selected) < opt.Target && len(notes) == 0 {
		notes = append(notes, fmt.Sprintf("kept %d repositories, short of %d", len(selected), opt.Target))
	}
	log(fmt.Sprintf("kept %d repositories (target %d)", len(selected), opt.Target))
	return Result{Repos: selected, Notes: notes, When: opt.Now.UTC()}, nil
}

type candidate struct {
	harnesses map[string]struct{}
	fork      bool
}

type codeQuery struct {
	harness string
	tries   []string
	accept  func(path string) bool
}

type searchState struct {
	q       codeQuery
	try     int
	order   string
	page    int
	total   int
	matched int
	done    bool
	logged  bool
}

// collect reads one page from each harness in turn, then the next page.
// A rate limit therefore leaves every harness represented instead of
// filling the list from whichever query ran first.
func collect(ctx context.Context, c *Client, cap int, cands map[string]*candidate, log func(string)) error {
	states := make([]searchState, len(codeQueries))
	for i, q := range codeQueries {
		states[i] = searchState{q: q, order: "desc", page: 1}
	}
	for {
		allDone := true
		var stepErr error
		for i := range states {
			st := &states[i]
			if st.done {
				continue
			}
			if st.matched >= cap {
				finish(st, log)
				continue
			}
			allDone = false
			if err := step(ctx, c, st, cap, cands, log); err != nil {
				stepErr = err
				break
			}
		}
		if stepErr != nil {
			for i := range states {
				finish(&states[i], log)
			}
			return stepErr
		}
		if allDone {
			break
		}
	}
	for i := range states {
		finish(&states[i], log)
	}
	return nil
}

func finish(st *searchState, log func(string)) {
	if st.logged {
		return
	}
	st.done = true
	st.logged = true
	log(fmt.Sprintf("%s: %d root matches", st.q.harness, st.matched))
}

func step(ctx context.Context, c *Client, st *searchState, cap int, cands map[string]*candidate, log func(string)) error {
	if st.try >= len(st.q.tries) {
		finish(st, log)
		return nil
	}
	query := strings.TrimSpace(st.q.tries[st.try])
	if query == "" {
		st.try++
		return nil
	}
	if c.slow && (st.order == "asc" || st.page > 1) {
		log("code search rate limit; one page per harness")
		finish(st, log)
		return nil
	}
	hits, n, err := c.SearchCode(ctx, query, st.page, 100, st.order)
	if errors.Is(err, ErrBadQuery) {
		log(fmt.Sprintf("code search rejected %q", query))
		st.try++
		st.page = 1
		st.order = "desc"
		st.total = 0
		return nil
	}
	if errors.Is(err, ErrRateLimited) {
		log(fmt.Sprintf("code search rate limit; skipping the rest of %s", st.q.harness))
		finish(st, log)
		return nil
	}
	if err != nil {
		return err
	}
	st.total = n
	pageMatches := 0
	for _, hit := range hits {
		if !st.q.accept(hit.Path) || hit.Repo == "" {
			continue
		}
		cand := cands[hit.Repo]
		if cand == nil {
			cand = &candidate{harnesses: map[string]struct{}{}}
			cands[hit.Repo] = cand
		}
		if _, ok := cand.harnesses[st.q.harness]; !ok {
			st.matched++
			pageMatches++
		}
		cand.harnesses[st.q.harness] = struct{}{}
		if hit.Fork {
			cand.fork = true
		}
	}
	log(fmt.Sprintf("search %s %s page %d: %d hits, %d new root matches, %d indexed", st.q.harness, st.order, st.page, len(hits), pageMatches, st.total))
	if st.matched >= cap || len(hits) < 100 || st.page >= 10 {
		if st.order == "desc" && st.total > 1000 && !c.slow && st.matched < cap {
			st.order = "asc"
			st.page = 1
			return nil
		}
		finish(st, log)
		return nil
	}
	st.page++
	return nil
}

func rootFile(path, want string) bool {
	return path == want
}

func rootTree(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// codeQueries are the root agent configs. Stars are not a code-search
// qualifier; a repository under 50 stars is dropped after hydration.
// Each try is attempted until one is accepted. When the index holds
// more than 1,000 hits, both index orders are read, because each order
// returns a different window of at most 1,000.
var codeQueries = []codeQuery{
	{harness: "claude", accept: func(p string) bool { return rootFile(p, ".claude/settings.json") }, tries: []string{
		`filename:settings.json path:.claude`,
	}},
	{harness: "mcp", accept: func(p string) bool { return rootFile(p, ".mcp.json") }, tries: []string{
		`filename:.mcp.json`,
	}},
	{harness: "cursor", accept: func(p string) bool { return rootTree(p, ".cursor") }, tries: []string{
		`path:.cursor`,
		`filename:mcp.json path:.cursor`,
		`filename:hooks.json path:.cursor`,
	}},
	{harness: "agents", accept: func(p string) bool { return rootFile(p, "AGENTS.md") }, tries: []string{
		`filename:AGENTS.md`,
	}},
	{harness: "vscode", accept: func(p string) bool { return rootFile(p, ".vscode/tasks.json") }, tries: []string{
		`filename:tasks.json path:.vscode`,
	}},
	{harness: "copilot", accept: func(p string) bool { return rootFile(p, ".github/workflows/copilot-setup-steps.yml") }, tries: []string{
		`filename:copilot-setup-steps.yml`,
	}},
	{harness: "devcontainer", accept: func(p string) bool { return rootTree(p, ".devcontainer") }, tries: []string{
		`path:.devcontainer`,
		`filename:devcontainer.json path:.devcontainer`,
	}},
	{harness: "codex", accept: func(p string) bool { return rootTree(p, ".codex") }, tries: []string{
		`path:.codex`,
	}},
	{harness: "gemini", accept: func(p string) bool { return rootTree(p, ".gemini") }, tries: []string{
		`path:.gemini`,
	}},
}
