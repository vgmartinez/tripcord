package benign

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
)

func TestMergeKeepsThePin(t *testing.T) {
	oldSHA := strings.Repeat("ab", 20)
	newSHA := strings.Repeat("cd", 20)
	existing := []Repo{{
		Name: "keep/me", SHA: oldSHA, License: "MIT", Harnesses: []string{"agents"},
		Date: "2026-11-01", Band: "small", Stars: 80,
	}}
	fresh := []Repo{
		{Name: "keep/me", SHA: newSHA, License: "Apache-2.0", Harnesses: []string{"mcp"}, Date: "2026-11-04", Band: "large", Stars: 90},
		{Name: "add/me", SHA: newSHA, License: "MIT", Harnesses: []string{"codex"}, Date: "2026-11-04", Band: "medium", Stars: 70},
	}
	got := Merge(existing, fresh, false)
	if len(got) != 2 || got[0].Name != "add/me" || got[1].Name != "keep/me" {
		t.Fatalf("%#v", names(got))
	}
	if got[1].SHA != oldSHA || got[1].License != "MIT" || got[1].Date != "2026-11-01" || got[1].Band != "small" {
		t.Fatalf("pinned row changed: %#v", got[1])
	}
	if len(got[1].Harnesses) != 2 || got[1].Harnesses[0] != "agents" || got[1].Harnesses[1] != "mcp" {
		t.Fatalf("harnesses %#v", got[1].Harnesses)
	}
	pinned := Merge(existing, fresh, true)
	if pinned[1].SHA != newSHA || pinned[1].License != "Apache-2.0" || pinned[1].Date != "2026-11-04" {
		t.Fatalf("repin: %#v", pinned[1])
	}
}

func TestIntegrateDoesNotShrink(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	existing := []Repo{
		{Name: "a/a", SHA: sha, License: "MIT", Harnesses: []string{"agents"}, Date: "2026-11-04", Band: "small"},
		{Name: "b/b", SHA: sha, License: "MIT", Harnesses: []string{"claude"}, Date: "2026-11-04", Band: "large"},
	}
	fresh := []Repo{{Name: "c/c", SHA: sha, License: "MIT", Harnesses: []string{"cursor"}, Date: "2026-11-04", Band: "medium", Stars: 100}}
	got := Integrate(existing, fresh, 1, false)
	if len(got) != 2 || got[0].Name != "a/a" || got[1].Name != "b/b" {
		t.Fatalf("shrunk to %#v", names(got))
	}
	grown := Integrate(existing, fresh, 3, false)
	if len(grown) != 3 || grown[2].Name != "c/c" {
		t.Fatalf("did not add the new row: %#v", names(grown))
	}
}

func TestExitCode(t *testing.T) {
	full := Result{Repos: []Repo{{Name: "a/a"}}}
	if ExitCode(full, false) != 0 {
		t.Fatal("a finished run should exit 0")
	}
	short := Result{Repos: []Repo{{Name: "a/a"}}, Incomplete: true}
	if ExitCode(short, false) != 1 || ExitCode(short, true) != 0 {
		t.Fatal("a short run needs -partial to exit 0")
	}
	limited := Result{Repos: []Repo{{Name: "a/a"}}, Incomplete: true, RateLimited: true}
	if ExitCode(limited, true) != 1 {
		t.Fatal("a rate limit exited 0")
	}
	if ExitCode(Result{}, true) != 1 {
		t.Fatal("an empty result exited 0")
	}
}

func TestWriteLockRefusesAShorterList(t *testing.T) {
	when := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	sha := strings.Repeat("ab", 20)
	dir := t.TempDir()
	path := filepath.Join(dir, "repos.lock")
	first, err := FormatLock([]Repo{
		{Name: "a/a", SHA: sha, License: "MIT", Harnesses: []string{"agents"}, Band: "small", Date: "2026-11-04"},
		{Name: "b/b", SHA: sha, License: "MIT", Harnesses: []string{"claude"}, Band: "large", Date: "2026-11-04"},
	}, when)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteLock(path, first); err != nil {
		t.Fatal(err)
	}
	shorter, err := FormatLock([]Repo{
		{Name: "a/a", SHA: sha, License: "MIT", Harnesses: []string{"agents"}, Band: "small", Date: "2026-11-04"},
	}, when)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteLock(path, shorter); err == nil {
		t.Fatal("a shorter lock was written")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(first) {
		t.Fatal("the existing lock was replaced")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %d", len(entries))
	}
}

func TestResumeStartsAtTheSavedPage(t *testing.T) {
	var pages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search/code") {
			pages = append(pages, r.URL.Query().Get("page")+" "+r.URL.Query().Get("q"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	state, err := ParseState(mustState(t, []Cursor{{
		Harness: "mcp", Try: 0, Order: "desc", Page: 4, Done: false,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	// Mark every harness done except mcp, which resumes at page 4.
	for i := range state {
		if state[i].Harness != "mcp" {
			state[i].Done = true
		}
	}
	res, err := Build(context.Background(), c, Options{
		Target: 10, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), Batch: 1, State: state,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 1 || !strings.HasPrefix(pages[0], "4 ") || !strings.Contains(pages[0], "filename:.mcp.json") {
		t.Fatalf("pages %v", pages)
	}
	var mcp Cursor
	for _, cur := range res.Cursors {
		if cur.Harness == "mcp" {
			mcp = cur
		}
	}
	if mcp.Done || mcp.Try != 1 || mcp.Page != 1 {
		t.Fatalf("cursor after an empty page: %#v", mcp)
	}
}

func TestEmptyQueryAdvancesToTheNextShape(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search/code") {
			queries = append(queries, r.URL.Query().Get("q"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	state, err := ParseState(mustState(t, []Cursor{{
		Harness: "copilot", Try: 0, Order: "desc", Page: 1, Done: false,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range state {
		if state[i].Harness != "copilot" {
			state[i].Done = true
		}
	}
	res, err := Build(context.Background(), c, Options{
		Target: 10, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), Batch: 2, State: state,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "copilot-instructions.md") || !strings.Contains(queries[1], "copilot-setup-steps.yml") {
		t.Fatalf("queries %v", queries)
	}
	for _, cur := range res.Cursors {
		if cur.Harness == "copilot" && (!cur.Done || cur.Try != 1) {
			t.Fatalf("cursor %#v", cur)
		}
	}
}

func TestSecondShapeStartsAfterTwoPages(t *testing.T) {
	var queries []string
	var pages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/search/code") {
			http.NotFound(w, r)
			return
		}
		queries = append(queries, r.URL.Query().Get("q"))
		pages = append(pages, r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		var b strings.Builder
		b.WriteString(`{"total_count":5000,"items":[`)
		for i := 0; i < 100; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"path":"notes/page.md","repository":{"full_name":"org/r%d","fork":false}}`, i)
		}
		b.WriteString(`]}`)
		_, _ = w.Write([]byte(b.String()))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	state, err := ParseState(mustState(t, []Cursor{{
		Harness: "copilot", Try: 0, Order: "desc", Page: 1, Done: false,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	for i := range state {
		if state[i].Harness != "copilot" {
			state[i].Done = true
		}
	}
	_, err = Build(context.Background(), c, Options{
		Target: 10, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), Batch: 3, State: state,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 3 || pages[0] != "1" || pages[1] != "2" || pages[2] != "1" {
		t.Fatalf("queries %v pages %v", queries, pages)
	}
	if !strings.Contains(queries[0], "copilot-instructions.md") || !strings.Contains(queries[1], "copilot-instructions.md") || !strings.Contains(queries[2], "copilot-setup-steps.yml") {
		t.Fatalf("queries %v", queries)
	}
}

func TestPrioritySearchesTheShortHarnessFirst(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search/code") {
			queries = append(queries, r.URL.Query().Get("q"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	sha := strings.Repeat("ab", 20)
	var existing []Repo
	for _, h := range Harnesses {
		if h == "mcp" {
			continue
		}
		existing = append(existing, Repo{
			Name: "org/" + h, SHA: sha, License: "MIT", Harnesses: []string{h}, Band: "small", Date: "2026-11-04",
		})
	}
	_, err := Build(context.Background(), c, Options{
		Target: 100, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC),
		MinPerHarness: 1, Batch: 1, Existing: existing,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || !strings.Contains(queries[0], ".mcp.json") {
		t.Fatalf("first query %v", queries)
	}
}

func TestPriorityPrefersTheEmptiestHarness(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search/code") {
			queries = append(queries, r.URL.Query().Get("q"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	sha := strings.Repeat("ab", 20)
	existing := []Repo{{
		Name: "org/claude", SHA: sha, License: "MIT", Harnesses: []string{"claude"}, Band: "small", Date: "2026-11-04",
	}}
	_, err := Build(context.Background(), c, Options{
		Target: 100, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC),
		MinPerHarness: 40, Batch: 1, Existing: existing,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || !strings.Contains(queries[0], ".mcp.json") {
		t.Fatalf("first query %v", queries)
	}
}

func TestOnlySearchesTheNamedHarness(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search/code") {
			queries = append(queries, r.URL.Query().Get("q"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	state, err := ParseState(mustState(t, []Cursor{{
		Harness: "devcontainer", Try: 1, Order: "desc", Page: 1, Done: false,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Build(context.Background(), c, Options{
		Target: 10, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC),
		MinPerHarness: 40, Batch: 1, State: state, Only: []string{"devcontainer"},
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 1 || queries[0] != "filename:.devcontainer.json" {
		t.Fatalf("queries %v", queries)
	}
}

func TestRateLimitKeepsTheExistingLock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1200")
		http.Error(w, `{"message":"try again in 1200s"}`, http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	sha := strings.Repeat("ab", 20)
	existing := []Repo{
		{Name: "a/a", SHA: sha, License: "MIT", Harnesses: []string{"agents"}, Band: "small", Date: "2026-11-04"},
		{Name: "b/b", SHA: sha, License: "MIT", Harnesses: []string{"claude"}, Band: "large", Date: "2026-11-04"},
	}
	res, err := Build(context.Background(), c, Options{
		Target: 10, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), Existing: existing,
	}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if !res.RateLimited || len(res.Repos) != 2 || res.Repos[0].SHA != sha || res.Repos[1].SHA != sha {
		t.Fatalf("%#v notes %v", names(res.Repos), res.Notes)
	}
	if ExitCode(res, true) != 1 {
		t.Fatal("rate limit with -partial exited 0")
	}
}

func TestAcceptPathsMatchAdapters(t *testing.T) {
	cases := []struct {
		path    string
		accept  func(string) bool
		adapter func(string) bool
		want    bool
	}{
		{".mcp.json", acceptMCP, claude.RepoCandidate, true},
		{"pkg/.mcp.json", acceptMCP, claude.RepoCandidate, true},
		{"mcp.json", acceptMCP, claude.RepoCandidate, false},
		{".github/copilot-instructions.md", acceptCopilot, copilot.RepoCandidate, true},
		{".github/workflows/copilot-setup-steps.yml", acceptCopilot, copilot.RepoCandidate, true},
		{"sub/.github/copilot-instructions.md", acceptCopilot, copilot.RepoCandidate, false},
		{".devcontainer/devcontainer.json", acceptDevcontainer, devcontainer.RepoCandidate, true},
		{".devcontainer/gpu/devcontainer.json", acceptDevcontainer, devcontainer.RepoCandidate, true},
		{".devcontainer.json", acceptDevcontainer, devcontainer.RepoCandidate, true},
		{"sub/.devcontainer/devcontainer.json", acceptDevcontainer, devcontainer.RepoCandidate, false},
		{".codex/config.toml", acceptCodex, codex.RepoCandidate, true},
		{"lib/.codex/config.toml", acceptCodex, codex.RepoCandidate, true},
		{"AGENTS.md", acceptCodex, codex.RepoCandidate, false},
		{"GEMINI.md", acceptGemini, gemini.RepoCandidate, true},
		{"a/GEMINI.md", acceptGemini, gemini.RepoCandidate, true},
		{".gemini/settings.json", acceptGemini, gemini.RepoCandidate, true},
		{".gemini/other.json", acceptGemini, gemini.RepoCandidate, false},
		{".claude/settings.json", acceptClaude, claude.RepoCandidate, true},
		{".claude/settings.local.json", acceptClaude, claude.RepoCandidate, true},
		{"CLAUDE.md", acceptClaude, claude.RepoCandidate, true},
		{"docs/CLAUDE.md", acceptClaude, claude.RepoCandidate, false},
		{".vscode/tasks.json", acceptVSCode, generic.RepoCandidate, true},
		{".vscode/mcp.json", acceptVSCode, generic.RepoCandidate, true},
		{".vscode/settings.json", acceptVSCode, generic.RepoCandidate, false},
	}
	for _, tc := range cases {
		if tc.accept(tc.path) != tc.want {
			t.Errorf("accept %s = %v", tc.path, !tc.want)
		}
		if tc.want && !tc.adapter(tc.path) {
			t.Errorf("adapter does not read %s", tc.path)
		}
	}
}

func mustState(t *testing.T, cursors []Cursor) []byte {
	t.Helper()
	// Start from a complete cursor file and overlay.
	base, err := FormatState(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseState(base)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Cursor{}
	for _, c := range cursors {
		by[c.Harness] = c
	}
	for i, c := range parsed {
		if repl, ok := by[c.Harness]; ok {
			parsed[i] = repl
		}
	}
	out, err := FormatState(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
