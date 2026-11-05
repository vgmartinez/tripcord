package benign

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// MinStars is the star count a repository must reach to be kept.
const MinStars = 50

// Options controls one index build.
type Options struct {
	// Target is how many repositories to keep. The default is 1000.
	Target int
	// Now is the generation date stored on a new row.
	Now time.Time
	// PerHarness is the most root matches collected for one harness.
	// The default is 2000, which covers both index orders of the
	// 1,000-result search cap.
	PerHarness int
	// MinPerHarness gives search priority to harnesses under this
	// count. Zero keeps the plain round-robin order.
	MinPerHarness int
	// Batch is the most code-search requests in this run. Zero means
	// no limit. A run that stops at the limit is Incomplete.
	Batch int
	// Existing rows are merged in and are never dropped or re-pinned
	// unless Repin is set.
	Existing []Repo
	// Repin replaces the commit SHA of a row that is already in Existing.
	Repin bool
	// State is the crawl cursor from the previous run.
	State []Cursor
	// Only limits this run to the named harnesses. Empty searches all.
	Only []string
	// Save is called after each code-search page with the merged rows
	// and the cursor to resume from. It may be nil.
	Save func(repos []Repo, cursors []Cursor) error
}

// Result is the merged index and any reason it is short of Target.
type Result struct {
	Repos       []Repo
	Notes       []string
	When        time.Time
	Cursors     []Cursor
	Incomplete  bool
	RateLimited bool
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
	existing, bandErr := fillMissingBands(ctx, c, opt.Existing, log)
	if bandErr != nil {
		return Result{}, bandErr
	}
	opt.Existing = existing
	cands := map[string]*candidate{}
	known := map[string]Meta{}
	var notes []string
	states := newStates(opt.State)
	stopped, err := collect(ctx, c, opt, states, cands, known, date, log)
	if err != nil {
		notes = append(notes, "GitHub code search stopped the crawl: "+err.Error())
		log(notes[len(notes)-1])
		if len(cands) == 0 && len(opt.Existing) == 0 {
			return Result{}, err
		}
	}
	selected, ferr := integrateKnown(ctx, c, opt, cands, known, date, log)
	if ferr != nil {
		notes = append(notes, "repository metadata stopped early: "+ferr.Error())
		log(notes[len(notes)-1])
	}
	if c.slow {
		notes = append(notes, "GitHub code search asked for a wait this run could not absorb, so later pages were skipped")
	}
	if stopped == stopRate {
		notes = append(notes, "GitHub code search rate limit stopped the crawl")
	}
	if opt.Batch > 0 && stopped == stopBatch && len(selected) < opt.Target {
		notes = append(notes, fmt.Sprintf("batch stopped after %d code-search requests", opt.Batch))
	}
	if len(selected) < opt.Target && len(notes) == 0 {
		notes = append(notes, fmt.Sprintf("code search was exhausted with %d repositories after the star, archive, and fork filters", len(selected)))
	}
	log(fmt.Sprintf("kept %d repositories (target %d)", len(selected), opt.Target))
	return Result{
		Repos:       selected,
		Notes:       notes,
		When:        opt.Now.UTC(),
		Cursors:     cursorsFrom(states),
		Incomplete:  len(selected) < opt.Target,
		RateLimited: c.slow || stopped == stopRate,
	}, nil
}

type stopKind int

const (
	stopNone stopKind = iota
	stopBatch
	stopRate
)

func fillMissingBands(ctx context.Context, c *Client, existing []Repo, log func(string)) ([]Repo, error) {
	var need []string
	for _, r := range existing {
		if r.Band == "" {
			need = append(need, r.Name)
		}
	}
	if len(need) == 0 {
		return existing, nil
	}
	log(fmt.Sprintf("hydrating size bands for %d pinned repositories", len(need)))
	metas, err := c.Hydrate(ctx, need)
	if err != nil {
		return nil, err
	}
	by := map[string]Meta{}
	for _, m := range metas {
		by[m.Name] = m
		for _, asked := range need {
			if strings.EqualFold(asked, m.Name) {
				by[asked] = m
			}
		}
	}
	out := slices.Clone(existing)
	for i, r := range out {
		if r.Band != "" {
			continue
		}
		m, ok := by[r.Name]
		if !ok || m.Missing {
			return nil, fmt.Errorf("%s: no metadata for the size band", r.Name)
		}
		out[i].Band = SizeBand(m.SizeKB)
		out[i].SizeKB = m.SizeKB
		if out[i].Stars == 0 {
			out[i].Stars = m.Stars
		}
	}
	return out, nil
}

func integrateKnown(ctx context.Context, c *Client, opt Options, cands map[string]*candidate, known map[string]Meta, date string, log func(string)) ([]Repo, error) {
	fresh, err := materialize(ctx, c, opt.Existing, cands, known, date, opt.Repin, log)
	if err != nil && len(fresh) == 0 && len(cands) > 0 {
		return Integrate(opt.Existing, nil, opt.Target, opt.Repin), err
	}
	return Integrate(opt.Existing, fresh, opt.Target, opt.Repin), err
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

func newStates(saved []Cursor) []searchState {
	states := make([]searchState, len(codeQueries))
	for i, q := range codeQueries {
		states[i] = searchState{q: q, order: "desc", page: 1}
	}
	by := map[string]Cursor{}
	for _, c := range saved {
		by[c.Harness] = c
	}
	for i := range states {
		c, ok := by[states[i].q.harness]
		if !ok {
			continue
		}
		states[i].try = c.Try
		if c.Order == "asc" || c.Order == "desc" {
			states[i].order = c.Order
		}
		if c.Page > 0 {
			states[i].page = c.Page
		}
		states[i].done = c.Done
	}
	return states
}

func cursorsFrom(states []searchState) []Cursor {
	out := make([]Cursor, len(states))
	for i, st := range states {
		out[i] = Cursor{Harness: st.q.harness, Try: st.try, Order: st.order, Page: st.page, Done: st.done}
	}
	return out
}

// collect reads pages until every harness is done, the batch limit is
// hit, or code search rate-limits the run. Harnesses under
// MinPerHarness are searched first. With no minimum, it reads one page
// from each harness in turn.
func collect(ctx context.Context, c *Client, opt Options, states []searchState, cands map[string]*candidate, known map[string]Meta, date string, log func(string)) (stopKind, error) {
	requests := 0
	rr := 0
	for {
		if allDone(states) {
			return stopNone, nil
		}
		if opt.Batch > 0 && requests >= opt.Batch {
			return stopBatch, nil
		}
		idx := pickState(states, opt, cands, rr)
		if idx < 0 {
			return stopNone, nil
		}
		st := &states[idx]
		if st.matched >= opt.PerHarness {
			finish(st, log)
			continue
		}
		searched, err := step(ctx, c, st, opt.PerHarness, cands, log)
		if searched {
			requests++
			rr = idx + 1
		}
		if errors.Is(err, ErrRateLimited) {
			return stopRate, nil
		}
		if err != nil {
			return stopNone, err
		}
		if searched && opt.Save != nil {
			repos, ferr := integrateKnown(ctx, c, opt, cands, known, date, log)
			if saveErr := opt.Save(repos, cursorsFrom(states)); saveErr != nil {
				return stopNone, saveErr
			}
			if ferr != nil {
				return stopNone, ferr
			}
		}
	}
}

func allDone(states []searchState) bool {
	for i := range states {
		if !states[i].done {
			return false
		}
	}
	return true
}

func pickState(states []searchState, opt Options, cands map[string]*candidate, rr int) int {
	skip := func(i int) bool {
		return states[i].done || (len(opt.Only) > 0 && !slices.Contains(opt.Only, states[i].q.harness))
	}
	if opt.MinPerHarness > 0 {
		counts := coverage(opt.Existing, cands)
		lowest := -1
		for i := range states {
			if skip(i) {
				continue
			}
			n := counts[states[i].q.harness]
			if n >= opt.MinPerHarness {
				continue
			}
			if lowest < 0 || n < lowest {
				lowest = n
			}
		}
		if lowest >= 0 {
			for k := 0; k < len(states); k++ {
				i := (rr + k) % len(states)
				if skip(i) {
					continue
				}
				n := counts[states[i].q.harness]
				if n == lowest {
					return i
				}
			}
		}
	}
	for k := 0; k < len(states); k++ {
		i := (rr + k) % len(states)
		if !skip(i) {
			return i
		}
	}
	return -1
}

func coverage(existing []Repo, cands map[string]*candidate) map[string]int {
	seen := map[string]map[string]bool{}
	add := func(h, name string) {
		if seen[h] == nil {
			seen[h] = map[string]bool{}
		}
		seen[h][name] = true
	}
	for _, r := range existing {
		for _, h := range r.Harnesses {
			add(h, r.Name)
		}
	}
	for name, cand := range cands {
		for h := range cand.harnesses {
			add(h, name)
		}
	}
	out := map[string]int{}
	for h, names := range seen {
		out[h] = len(names)
	}
	return out
}

func finish(st *searchState, log func(string)) {
	if st.logged {
		return
	}
	st.done = true
	st.logged = true
	log(fmt.Sprintf("%s: %d root matches", st.q.harness, st.matched))
}

// step runs at most one code search. searched reports whether that
// request was sent.
func step(ctx context.Context, c *Client, st *searchState, cap int, cands map[string]*candidate, log func(string)) (bool, error) {
	if st.try >= len(st.q.tries) {
		finish(st, log)
		return false, nil
	}
	query := strings.TrimSpace(st.q.tries[st.try])
	if query == "" {
		st.try++
		return false, nil
	}
	if c.slow && (st.order == "asc" || st.page > 1) {
		log("code search rate limit; one page per harness")
		finish(st, log)
		return false, nil
	}
	hits, n, err := c.SearchCode(ctx, query, st.page, 100, st.order)
	if errors.Is(err, ErrBadQuery) {
		log(fmt.Sprintf("code search rejected %q", query))
		st.try++
		st.page = 1
		st.order = "desc"
		st.total = 0
		return true, nil
	}
	if errors.Is(err, ErrRateLimited) {
		log(fmt.Sprintf("code search rate limit at %s page %d", st.q.harness, st.page))
		return true, err
	}
	if err != nil {
		return true, err
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
	// Another shape names a different file the adapter reads. Two pages
	// of this shape are enough before that file is searched. The last
	// shape still walks both index orders.
	if st.try+1 < len(st.q.tries) && st.page >= 2 && st.matched < cap {
		st.try++
		st.page = 1
		st.order = "desc"
		st.total = 0
		return true, nil
	}
	if st.matched >= cap || len(hits) < 100 || st.page >= 10 {
		if st.order == "desc" && st.total > 1000 && !c.slow && st.matched < cap {
			st.order = "asc"
			st.page = 1
			return true, nil
		}
		// A query the API accepts can still match nothing the adapter
		// reads. The next shape is tried before the harness is done.
		if st.try+1 < len(st.q.tries) && st.matched < cap {
			st.try++
			st.page = 1
			st.order = "desc"
			st.total = 0
			return true, nil
		}
		finish(st, log)
		return true, nil
	}
	st.page++
	return true, nil
}

func materialize(ctx context.Context, c *Client, existing []Repo, cands map[string]*candidate, known map[string]Meta, date string, repin bool, log func(string)) ([]Repo, error) {
	have := map[string]Repo{}
	for _, r := range existing {
		have[r.Name] = r
	}
	var need []string
	for name, cand := range cands {
		if cand.fork {
			continue
		}
		if _, ok := known[name]; ok {
			continue
		}
		old, ok := have[name]
		if ok && !repin && old.Band != "" {
			continue
		}
		need = append(need, name)
	}
	slices.Sort(need)
	var err error
	if len(need) > 0 {
		log(fmt.Sprintf("hydrating %d repositories", len(need)))
		var metas []Meta
		metas, err = c.Hydrate(ctx, need)
		for _, m := range metas {
			known[m.Name] = m
			for _, asked := range need {
				if strings.EqualFold(asked, m.Name) {
					known[asked] = m
				}
			}
		}
	}
	var fresh []Repo
	for name, cand := range cands {
		if cand.fork {
			continue
		}
		m, ok := known[name]
		if !ok {
			for k, meta := range known {
				if strings.EqualFold(k, name) {
					m = meta
					ok = true
					break
				}
			}
		}
		var hs []string
		for h := range cand.harnesses {
			hs = append(hs, h)
		}
		if !ok {
			if old, exists := have[name]; exists {
				fresh = append(fresh, Repo{Name: old.Name, SHA: old.SHA, License: old.License, Harnesses: hs, Date: old.Date, Band: old.Band, Stars: old.Stars, SizeKB: old.SizeKB})
			}
			continue
		}
		if m.Missing || m.Fork || m.Archived || m.Stars < MinStars || m.SHA == "" {
			continue
		}
		license := m.License
		if !knownLicense(license) {
			license = "NOASSERTION"
		}
		fresh = append(fresh, Repo{
			Name:      m.Name,
			SHA:       strings.ToLower(m.SHA),
			License:   license,
			Harnesses: hs,
			Date:      date,
			Band:      SizeBand(m.SizeKB),
			Stars:     m.Stars,
			SizeKB:    m.SizeKB,
		})
	}
	return fresh, err
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
	{harness: "claude", accept: acceptClaude, tries: []string{
		`filename:settings.json path:.claude`,
		`filename:CLAUDE.md`,
		`filename:settings.local.json path:.claude`,
	}},
	{harness: "mcp", accept: acceptMCP, tries: []string{
		`filename:.mcp.json`,
		`filename:.mcp.json path:/`,
		`filename:.mcp.json size:>1500`,
	}},
	{harness: "cursor", accept: func(p string) bool { return rootTree(p, ".cursor") }, tries: []string{
		`path:.cursor`,
		`filename:mcp.json path:.cursor`,
		`filename:hooks.json path:.cursor`,
	}},
	{harness: "agents", accept: func(p string) bool { return rootFile(p, "AGENTS.md") }, tries: []string{
		`filename:AGENTS.md`,
	}},
	{harness: "vscode", accept: acceptVSCode, tries: []string{
		`filename:tasks.json path:.vscode`,
		`filename:mcp.json path:.vscode`,
	}},
	{harness: "copilot", accept: acceptCopilot, tries: []string{
		`filename:copilot-instructions.md path:.github`,
		`filename:copilot-setup-steps.yml path:.github/workflows`,
	}},
	{harness: "devcontainer", accept: acceptDevcontainer, tries: []string{
		`filename:devcontainer.json path:.devcontainer`,
		`filename:.devcontainer.json`,
		`filename:devcontainer.json path:.devcontainer size:>2000`,
	}},
	{harness: "codex", accept: acceptCodex, tries: []string{
		`filename:config.toml path:.codex`,
	}},
	{harness: "gemini", accept: acceptGemini, tries: []string{
		`filename:GEMINI.md`,
		`filename:settings.json path:.gemini`,
	}},
}

func acceptClaude(p string) bool {
	switch p {
	case ".claude/settings.json", ".claude/settings.local.json", "CLAUDE.md":
		return true
	default:
		return false
	}
}

func acceptVSCode(p string) bool {
	return p == ".vscode/tasks.json" || p == ".vscode/mcp.json"
}

func acceptMCP(p string) bool {
	return strings.EqualFold(baseName(p), ".mcp.json")
}

func acceptCopilot(p string) bool {
	switch strings.ToLower(p) {
	case ".github/copilot-instructions.md", ".github/workflows/copilot-setup-steps.yml":
		return true
	default:
		return false
	}
}

func acceptDevcontainer(p string) bool {
	parts := strings.Split(strings.ToLower(p), "/")
	switch len(parts) {
	case 1:
		return parts[0] == ".devcontainer.json"
	case 2, 3:
		return parts[0] == ".devcontainer" && parts[len(parts)-1] == "devcontainer.json"
	default:
		return false
	}
}

func acceptCodex(p string) bool {
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return false
	}
	return strings.EqualFold(parts[len(parts)-1], "config.toml") && strings.EqualFold(parts[len(parts)-2], ".codex")
}

func acceptGemini(p string) bool {
	if strings.EqualFold(baseName(p), "GEMINI.md") {
		return true
	}
	parts := strings.Split(p, "/")
	return len(parts) >= 2 && strings.EqualFold(parts[len(parts)-1], "settings.json") && strings.EqualFold(parts[len(parts)-2], ".gemini")
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
