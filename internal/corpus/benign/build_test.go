package benign

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestBuildFiltersAndStratifies(t *testing.T) {
	var searches int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/search/code"):
			searches++
			q := r.URL.Query().Get("q")
			if strings.Contains(q, "stars:>=") && strings.Contains(q, "filename:AGENTS.md") {
				http.Error(w, `{"message":"Validation Failed","errors":[{"message":"stars is unsupported"}]}`, http.StatusUnprocessableEntity)
				return
			}
			if searches == 2 {
				w.Header().Set("Retry-After", "0")
				http.Error(w, `{"message":"try again"}`, http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(q, "filename:AGENTS.md"):
				_, _ = w.Write([]byte(`{"total_count":3,"items":[
					{"path":"AGENTS.md","repository":{"full_name":"good/agents","fork":false}},
					{"path":"nested/AGENTS.md","repository":{"full_name":"good/nested","fork":false}},
					{"path":"AGENTS.md","repository":{"full_name":"good/forked","fork":true}}
				]}`))
			case strings.Contains(q, "filename:settings.json"):
				_, _ = w.Write([]byte(`{"total_count":1,"items":[
					{"path":".claude/settings.json","repository":{"full_name":"good/claude","fork":false}}
				]}`))
			default:
				_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
			}
		case strings.HasSuffix(r.URL.Path, "/graphql"):
			raw, _ := io.ReadAll(r.Body)
			var req struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(raw, &req)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": fakeRepos(req.Query)})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "test-token", HTTP: srv.Client()}
	res, err := Build(context.Background(), c, Options{Target: 10, Now: time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC), PerHarness: 10}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Repos) != 1 || res.Repos[0].Name != "good/agents" {
		t.Fatalf("repos %#v notes %v", res.Repos, res.Notes)
	}
	if res.Repos[0].License != "MIT" || res.Repos[0].SHA != strings.Repeat("a", 40) || res.Repos[0].Date != "2026-11-04" {
		t.Fatalf("row %#v", res.Repos[0])
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "exhausted") {
		t.Fatalf("notes %v", res.Notes)
	}
}

func TestSearchCodeDoesNotSleepOutALongRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1200")
		http.Error(w, `{"message":"try again in 1200s"}`, http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	start := time.Now()
	_, _, err := c.SearchCode(context.Background(), "filename:AGENTS.md", 2, 100, "desc")
	if time.Since(start) > 2*time.Second {
		t.Fatalf("slept %s on a 1200s rate limit", time.Since(start))
	}
	if !errors.Is(err, ErrRateLimited) || !c.slow {
		t.Fatalf("err %v slow %v", err, c.slow)
	}
}

func TestSearchCodeSkipsASecondLongRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "240")
		http.Error(w, `{"message":"try again in 240s"}`, http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client(), longSleep: true}
	start := time.Now()
	_, _, err := c.SearchCode(context.Background(), "filename:AGENTS.md", 1, 100, "desc")
	if time.Since(start) > 2*time.Second {
		t.Fatalf("slept %s on a second long rate limit", time.Since(start))
	}
	if !errors.Is(err, ErrRateLimited) || !c.slow {
		t.Fatalf("err %v slow %v", err, c.slow)
	}
}

func TestBuildKeepsEarlierPageWhenSearchAsksForALongWait(t *testing.T) {
	var searches int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/search/code"):
			searches++
			page := r.URL.Query().Get("page")
			q := r.URL.Query().Get("q")
			if strings.Contains(q, "filename:settings.json") && page == "2" {
				w.Header().Set("Retry-After", "1200")
				http.Error(w, `{"message":"try again in 1200s"}`, http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(q, "filename:settings.json") {
				var b strings.Builder
				b.WriteString(`{"total_count":200,"items":[`)
				for i := 0; i < 100; i++ {
					if i > 0 {
						b.WriteByte(',')
					}
					if i == 0 {
						b.WriteString(`{"path":".claude/settings.json","repository":{"full_name":"good/claude","fork":false}}`)
						continue
					}
					b.WriteString(`{"path":".claude/other/settings.json","repository":{"full_name":"skip/nested","fork":false}}`)
				}
				b.WriteString(`]}`)
				_, _ = io.WriteString(w, b.String())
				return
			}
			_, _ = w.Write([]byte(`{"total_count":0,"items":[]}`))
		case strings.HasSuffix(r.URL.Path, "/graphql"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"r0":{"nameWithOwner":"good/claude","isFork":false,"isArchived":false,"stargazerCount":80,"diskUsage":100,"licenseInfo":{"spdxId":"MIT"},"defaultBranchRef":{"target":{"oid":"` + strings.Repeat("a", 40) + `"}}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	start := time.Now()
	res, err := Build(context.Background(), c, Options{Target: 10, Now: time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), PerHarness: 10}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("slept %s", time.Since(start))
	}
	if len(res.Repos) != 1 || res.Repos[0].Name != "good/claude" {
		t.Fatalf("repos %#v notes %v searches %d", res.Repos, res.Notes, searches)
	}
	if len(res.Notes) == 0 || !c.slow {
		t.Fatalf("notes %v slow %v", res.Notes, c.slow)
	}
	if searches < 3 {
		t.Fatalf("later harnesses were not searched: %d requests", searches)
	}
}

func TestHydrateMissingLicense(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"r0":{"nameWithOwner":"o/r","isFork":false,"isArchived":true,"stargazerCount":3,"diskUsage":null,"licenseInfo":null,"defaultBranchRef":null}}}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Token: "t", HTTP: srv.Client()}
	got, err := c.Hydrate(context.Background(), []string{"o/r"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Archived || got[0].License != "" || got[0].SHA != "" || got[0].SizeKB != 0 {
		t.Fatalf("%#v", got)
	}
}

var repoCall = regexp.MustCompile(`(r\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\)`)

func fakeRepos(query string) map[string]any {
	known := map[string]map[string]any{
		"good/agents": {
			"nameWithOwner": "good/agents", "isFork": false, "isArchived": false,
			"stargazerCount": 80, "diskUsage": 100,
			"licenseInfo":      map[string]any{"spdxId": "MIT"},
			"defaultBranchRef": map[string]any{"target": map[string]any{"oid": strings.Repeat("a", 40)}},
		},
		"good/claude": {
			"nameWithOwner": "good/claude", "isFork": false, "isArchived": false,
			"stargazerCount": 40, "diskUsage": 9000,
			"licenseInfo":      nil,
			"defaultBranchRef": map[string]any{"target": map[string]any{"oid": strings.Repeat("b", 40)}},
		},
	}
	out := map[string]any{}
	for _, m := range repoCall.FindAllStringSubmatch(query, -1) {
		out[m[1]] = known[m[2]+"/"+m[3]]
	}
	return out
}
