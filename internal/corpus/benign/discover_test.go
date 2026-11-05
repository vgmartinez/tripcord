package benign

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

var probeCall = regexp.MustCompile(`(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\)`)

// fakeDiscover serves one search page of names and answers probes from
// roots, which maps owner/repo to the root paths present on HEAD.
func fakeDiscover(t *testing.T, names []string, meta map[string]map[string]any, roots map[string][]string) (*httptest.Server, *[]string) {
	t.Helper()
	var probed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/search/repositories":
			if r.URL.Query().Get("sort") != "stars" {
				t.Errorf("sort %q", r.URL.Query().Get("sort"))
			}
			var b strings.Builder
			fmt.Fprintf(&b, `{"total_count":%d,"items":[`, len(names))
			for i, n := range names {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"full_name":%q}`, n)
			}
			b.WriteString(`]}`)
			_, _ = io.WriteString(w, b.String())
		case "/graphql":
			var req struct {
				Query string `json:"query"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			data := map[string]any{}
			for _, m := range probeCall.FindAllStringSubmatch(req.Query, -1) {
				name := m[2] + "/" + m[3]
				probed = append(probed, name)
				base, ok := meta[name]
				if !ok {
					data[m[1]] = nil
					continue
				}
				node := map[string]any{}
				for k, v := range base {
					node[k] = v
				}
				for k, p := range rootProbes {
					node[fmt.Sprintf("p%d", k)] = nil
					for _, have := range roots[name] {
						if have == p.path {
							node[fmt.Sprintf("p%d", k)] = map[string]any{"__typename": "Blob"}
						}
					}
				}
				data[m[1]] = node
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, &probed
}

func repoMeta(name string, stars int, fork, archived bool, sha string) map[string]any {
	var ref any
	if sha != "" {
		ref = map[string]any{"target": map[string]any{"oid": sha}}
	}
	return map[string]any{
		"nameWithOwner": name, "isFork": fork, "isArchived": archived,
		"stargazerCount": stars, "diskUsage": 2048,
		"licenseInfo": map[string]any{"spdxId": "MIT"}, "defaultBranchRef": ref,
	}
}

func TestDiscoverKeepsRootConfigsOnly(t *testing.T) {
	sha := strings.Repeat("c", 40)
	names := []string{"keep/both", "keep/agents", "drop/none", "drop/fork", "drop/archived", "drop/stars", "drop/nosha", "old/pinned", "gone/missing"}
	meta := map[string]map[string]any{
		"keep/both":     repoMeta("keep/both", 70, false, false, sha),
		"keep/agents":   repoMeta("keep/agents", 55, false, false, sha),
		"drop/none":     repoMeta("drop/none", 90, false, false, sha),
		"drop/fork":     repoMeta("drop/fork", 90, true, false, sha),
		"drop/archived": repoMeta("drop/archived", 90, false, true, sha),
		"drop/stars":    repoMeta("drop/stars", 49, false, false, sha),
		"drop/nosha":    repoMeta("drop/nosha", 90, false, false, ""),
		"old/pinned":    repoMeta("old/pinned", 90, false, false, sha),
	}
	cfg := []string{"AGENTS.md"}
	roots := map[string][]string{
		"keep/both":     {".mcp.json", ".claude/settings.json", "CLAUDE.md"},
		"keep/agents":   cfg,
		"drop/fork":     cfg,
		"drop/archived": cfg,
		"drop/stars":    cfg,
		"drop/nosha":    cfg,
		"old/pinned":    {".codex/config.toml"},
	}
	srv, probed := fakeDiscover(t, names, meta, roots)
	defer srv.Close()
	existing := []Repo{{Name: "old/pinned", SHA: strings.Repeat("a", 40), License: "MIT", Harnesses: []string{"agents"}, Band: "small", Date: "2026-11-04"}}
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	got, err := Discover(context.Background(), c, DiscoverOptions{Window: 0, Pages: 1, Target: 1000, Now: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), Existing: existing}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range *probed {
		if n == "old/pinned" {
			t.Fatal("a repository already in the lock was probed")
		}
	}
	byName := map[string]Repo{}
	for _, r := range got {
		byName[r.Name] = r
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows: %#v", len(got), got)
	}
	if old := byName["old/pinned"]; old.SHA != strings.Repeat("a", 40) || strings.Join(old.Harnesses, ",") != "agents" {
		t.Fatalf("existing row changed: %#v", old)
	}
	if both := byName["keep/both"]; strings.Join(both.Harnesses, ",") != "claude,mcp" || both.SHA != sha || both.Date != "2026-11-05" || both.Band != "medium" {
		t.Fatalf("keep/both %#v", both)
	}
	if _, ok := byName["keep/agents"]; !ok {
		t.Fatal("keep/agents was dropped")
	}
}

func TestDiscoverRespectsTarget(t *testing.T) {
	sha := strings.Repeat("d", 40)
	names := []string{"a/one", "b/two", "c/three"}
	meta := map[string]map[string]any{}
	roots := map[string][]string{}
	for _, n := range names {
		meta[n] = repoMeta(n, 60, false, false, sha)
		roots[n] = []string{"AGENTS.md"}
	}
	srv, _ := fakeDiscover(t, names, meta, roots)
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	got, err := Discover(context.Background(), c, DiscoverOptions{Window: 1, Pages: 1, Target: 2, Now: time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("target 2 kept %d", len(got))
	}
}

func TestDiscoverWindowBounds(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1", Token: "t"}
	for _, w := range []int{-1, len(DiscoverWindows)} {
		if _, err := Discover(context.Background(), c, DiscoverOptions{Window: w}, nil); err == nil {
			t.Fatalf("window %d accepted", w)
		}
	}
	seen := map[string]bool{}
	for _, q := range DiscoverWindows {
		if seen[q] || !strings.Contains(q, "fork:false") || !strings.Contains(q, "archived:false") || !strings.Contains(q, "stars:") {
			t.Fatalf("bad window %q", q)
		}
		seen[q] = true
	}
}

func TestProbeRetriesBadGateway(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		node := repoMeta("o/r", 60, false, false, strings.Repeat("e", 40))
		node["p5"] = map[string]any{"__typename": "Blob"}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"r0": node}})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	got, err := c.ProbeRoots(context.Background(), []string{"o/r"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(got) != 1 || strings.Join(got[0].Harnesses, ",") != rootProbes[5].harness {
		t.Fatalf("calls %d probes %#v", calls, got)
	}
}

func TestSearchReposRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "600")
		http.Error(w, `{"message":"secondary rate limit"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	start := time.Now()
	if _, _, err := c.SearchRepos(context.Background(), "stars:>50", 1); err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("waited out a long penalty")
	}
}
