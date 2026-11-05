package benign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrRateLimited means GitHub code search kept refusing requests, so the
// crawl should keep the candidates it already has.
var ErrRateLimited = errors.New("github code search rate limit")

// ErrBadQuery means GitHub rejected the code search query.
var ErrBadQuery = errors.New("github code search rejected the query")

// Client is a read-only GitHub API client. CodeGap is the minimum pause
// between code-search requests. Zero disables it, for tests.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	CodeGap time.Duration

	nextCode time.Time
	// slow is set when code search asks for a wait longer than the
	// crawl can absorb. Later pages of the same query are skipped.
	slow bool
	// longSleep is set after this run has already waited out one
	// penalty longer than three minutes.
	longSleep bool
	// Log, when set, receives rate-limit waits. It may be nil.
	Log func(string)
}

// NewClient returns a client for api.github.com that spaces code-search
// requests far enough apart for the authenticated limit of 10 per minute.
func NewClient(token string) *Client {
	return &Client{
		BaseURL: "https://api.github.com",
		Token:   token,
		HTTP:    &http.Client{Timeout: 45 * time.Second},
		CodeGap: 8 * time.Second,
	}
}

// CodeHit is one code-search result.
type CodeHit struct {
	Path string
	Repo string
	Fork bool
}

// SearchCode runs one page of code search. perPage is clamped to 100.
// order is "asc" or "desc" on the indexed sort; an empty order uses the
// API default.
func (c *Client) SearchCode(ctx context.Context, query string, page, perPage int, order string) ([]CodeHit, int, error) {
	if perPage <= 0 || perPage > 100 {
		perPage = 100
	}
	if page <= 0 {
		page = 1
	}
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + "/search/code")
	if err != nil {
		return nil, 0, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", strconv.Itoa(perPage))
	if order != "" {
		q.Set("sort", "indexed")
		q.Set("order", order)
	}
	u.RawQuery = q.Encode()
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if err := c.paceCode(ctx); err != nil {
			return nil, 0, err
		}
		body, resp, err := c.do(ctx, http.MethodGet, u.String(), nil, "application/vnd.github+json")
		if err != nil {
			return nil, 0, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			c.markCode()
			var parsed struct {
				Total int `json:"total_count"`
				Items []struct {
					Path       string `json:"path"`
					Repository struct {
						FullName string `json:"full_name"`
						Fork     bool   `json:"fork"`
					} `json:"repository"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				return nil, 0, err
			}
			hits := make([]CodeHit, 0, len(parsed.Items))
			for _, item := range parsed.Items {
				hits = append(hits, CodeHit{Path: item.Path, Repo: item.Repository.FullName, Fork: item.Repository.Fork})
			}
			return hits, parsed.Total, nil
		case http.StatusUnprocessableEntity:
			return nil, 0, fmt.Errorf("%w: %s", ErrBadQuery, clip(body))
		case http.StatusForbidden, http.StatusTooManyRequests:
			delay := retryDelay(resp, body)
			last = fmt.Errorf("%w: %s", ErrRateLimited, clip(body))
			// Wait out one multi-minute penalty. A second one, or a
			// single wait longer than fifteen minutes, will not fit
			// in this run.
			if delay > 15*time.Minute || (c.longSleep && delay > 3*time.Minute) {
				c.slow = true
				if c.Log != nil {
					c.Log(fmt.Sprintf("code search rate limit asked for %s", delay.Round(time.Second)))
				}
				return nil, 0, last
			}
			if delay > 3*time.Minute {
				c.longSleep = true
			}
			// Honour Retry-After, but never retry faster than CodeGap.
			// A 3s hint is under the authenticated code-search limit
			// and just draws another 429.
			wait := delay
			if c.CodeGap > wait {
				wait = c.CodeGap
			}
			if c.Log != nil && wait >= time.Second {
				c.Log(fmt.Sprintf("code search rate limit, waiting %s", wait.Round(time.Second)))
			}
			c.nextCode = time.Now().Add(wait)
			continue
		default:
			return nil, 0, fmt.Errorf("code search: %s: %s", resp.Status, clip(body))
		}
	}
	if last == nil {
		last = ErrRateLimited
	}
	return nil, 0, last
}

// Meta is repository metadata from the API.
type Meta struct {
	Name     string
	Fork     bool
	Archived bool
	Stars    int
	SizeKB   int
	SHA      string
	License  string
	Missing  bool
}

// Hydrate loads metadata for names. Unknown repositories are Missing.
func (c *Client) Hydrate(ctx context.Context, names []string) ([]Meta, error) {
	const batch = 30
	var out []Meta
	for i := 0; i < len(names); i += batch {
		end := i + batch
		if end > len(names) {
			end = len(names)
		}
		part, err := c.hydrateBatch(ctx, names[i:end])
		if err != nil {
			return out, err
		}
		out = append(out, part...)
	}
	return out, nil
}

func (c *Client) hydrateBatch(ctx context.Context, names []string) ([]Meta, error) {
	var b strings.Builder
	b.WriteString("query {")
	aliases := make([]string, len(names))
	for i, name := range names {
		owner, repo, _ := strings.Cut(name, "/")
		aliases[i] = fmt.Sprintf("r%d", i)
		fmt.Fprintf(&b, " %s: repository(owner: %s, name: %s) { nameWithOwner isFork isArchived stargazerCount diskUsage licenseInfo { spdxId } defaultBranchRef { target { oid } } }", aliases[i], gqlString(owner), gqlString(repo))
	}
	b.WriteString(" }")
	payload, err := json.Marshal(map[string]string{"query": b.String()})
	if err != nil {
		return nil, err
	}
	var last error
	for attempt := 0; attempt < 6; attempt++ {
		body, resp, err := c.do(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/graphql", payload, "application/json")
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			delay := retryDelay(resp, body)
			last = fmt.Errorf("graphql: %s", clip(body))
			if delay > 30*time.Minute {
				return nil, last
			}
			if err := sleep(ctx, delay); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("graphql: %s: %s", resp.Status, clip(body))
		}
		var parsed struct {
			Data   map[string]*gqlRepo `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, err
		}
		if parsed.Data == nil && len(parsed.Errors) > 0 {
			return nil, fmt.Errorf("graphql: %s", parsed.Errors[0].Message)
		}
		out := make([]Meta, 0, len(names))
		for i, name := range names {
			node := parsed.Data[aliases[i]]
			if node == nil || node.NameWithOwner == "" {
				out = append(out, Meta{Name: name, Missing: true})
				continue
			}
			out = append(out, metaFrom(*node))
		}
		return out, nil
	}
	if last == nil {
		last = errors.New("graphql: rate limit")
	}
	return nil, last
}

type gqlRepo struct {
	NameWithOwner  string `json:"nameWithOwner"`
	IsFork         bool   `json:"isFork"`
	IsArchived     bool   `json:"isArchived"`
	StargazerCount int    `json:"stargazerCount"`
	DiskUsage      *int   `json:"diskUsage"`
	LicenseInfo    *struct {
		SPDX string `json:"spdxId"`
	} `json:"licenseInfo"`
	DefaultBranchRef *struct {
		Target struct {
			OID string `json:"oid"`
		} `json:"target"`
	} `json:"defaultBranchRef"`
}

func (c *Client) do(ctx context.Context, method, rawURL string, payload []byte, accept string) ([]byte, *http.Response, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "tripcord-benign-repos")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	ht := c.HTTP
	if ht == nil {
		ht = http.DefaultClient
	}
	resp, err := ht.Do(req)
	if err != nil {
		return nil, nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, resp, readErr
	}
	if closeErr != nil {
		return nil, resp, closeErr
	}
	return data, resp, nil
}

func (c *Client) paceCode(ctx context.Context) error {
	wait := time.Until(c.nextCode)
	if wait <= 0 {
		return nil
	}
	return sleep(ctx, wait)
}

func (c *Client) markCode() {
	if c.CodeGap > 0 {
		c.nextCode = time.Now().Add(c.CodeGap)
	}
}

func retryDelay(resp *http.Response, body []byte) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	const marker = "try again in "
	if i := strings.Index(string(body), marker); i >= 0 {
		rest := string(body)[i+len(marker):]
		if j := strings.IndexByte(rest, 's'); j > 0 {
			if f, err := strconv.ParseFloat(rest[:j], 64); err == nil && f >= 0 {
				return time.Duration(f*float64(time.Second)) + time.Second
			}
		}
	}
	return 8 * time.Second
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func gqlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

func clip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}
