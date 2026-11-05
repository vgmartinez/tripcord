package benign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// rootProbes are the root paths discovery checks on a default branch,
// by harness. They are the root forms of the paths code search accepts,
// so a repository found this way would also be accepted there. A nested
// .mcp.json, .codex/config.toml, or GEMINI.md, and a named
// .devcontainer/<name>/devcontainer.json, are not probed.
var rootProbes = []struct{ harness, path string }{
	{"claude", ".claude/settings.json"},
	{"claude", ".claude/settings.local.json"},
	{"claude", "CLAUDE.md"},
	{"mcp", ".mcp.json"},
	{"cursor", ".cursor"},
	{"agents", "AGENTS.md"},
	{"vscode", ".vscode/tasks.json"},
	{"vscode", ".vscode/mcp.json"},
	{"copilot", ".github/copilot-instructions.md"},
	{"copilot", ".github/workflows/copilot-setup-steps.yml"},
	{"devcontainer", ".devcontainer.json"},
	{"devcontainer", ".devcontainer/devcontainer.json"},
	{"codex", ".codex/config.toml"},
	{"gemini", "GEMINI.md"},
	{"gemini", ".gemini/settings.json"},
}

// DiscoverWindows are the repository-search queries discovery reads, in
// order. Each returns at most 1,000 repositories, so the star ranges are
// narrow where repositories are dense. The list is fixed so a window
// index names the same query in every run.
var DiscoverWindows = []string{
	"stars:50..60 pushed:>=2026-10-01 fork:false archived:false",
	"stars:61..80 pushed:>=2026-10-01 fork:false archived:false",
	"stars:81..110 pushed:>=2026-10-01 fork:false archived:false",
	"stars:111..160 pushed:>=2026-10-01 fork:false archived:false",
	"stars:161..250 pushed:>=2026-10-01 fork:false archived:false",
	"stars:251..450 pushed:>=2026-10-01 fork:false archived:false",
	"stars:451..1000 pushed:>=2026-10-01 fork:false archived:false",
	"stars:1001..3000 pushed:>=2026-10-01 fork:false archived:false",
	"stars:>3000 pushed:>=2026-10-01 fork:false archived:false",
	"stars:50..80 pushed:2026-07-01..2026-09-30 fork:false archived:false",
	"stars:81..200 pushed:2026-07-01..2026-09-30 fork:false archived:false",
	"stars:>200 pushed:2026-07-01..2026-09-30 fork:false archived:false",
}

// ErrSearchRateLimited means repository search kept refusing requests.
var ErrSearchRateLimited = errors.New("github repository search rate limit")

// SearchRepos runs one page of repository search, sorted by stars.
func (c *Client) SearchRepos(ctx context.Context, query string, page int) ([]string, int, error) {
	if page <= 0 {
		page = 1
	}
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + "/search/repositories")
	if err != nil {
		return nil, 0, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("sort", "stars")
	q.Set("order", "desc")
	q.Set("page", strconv.Itoa(page))
	q.Set("per_page", "100")
	u.RawQuery = q.Encode()
	for attempt := 0; attempt < 4; attempt++ {
		body, resp, err := c.do(ctx, http.MethodGet, u.String(), nil, "application/vnd.github+json")
		if err != nil {
			return nil, 0, err
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var parsed struct {
				Total int `json:"total_count"`
				Items []struct {
					FullName string `json:"full_name"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &parsed); err != nil {
				return nil, 0, err
			}
			names := make([]string, 0, len(parsed.Items))
			for _, item := range parsed.Items {
				names = append(names, item.FullName)
			}
			return names, parsed.Total, nil
		case http.StatusUnprocessableEntity:
			return nil, 0, fmt.Errorf("%w: %s", ErrBadQuery, clip(body))
		case http.StatusForbidden, http.StatusTooManyRequests:
			delay := retryDelay(resp, body)
			if delay > 3*time.Minute {
				return nil, 0, fmt.Errorf("%w: %s", ErrSearchRateLimited, clip(body))
			}
			if c.Log != nil {
				c.Log(fmt.Sprintf("repository search rate limit, waiting %s", delay.Round(time.Second)))
			}
			if err := sleep(ctx, delay); err != nil {
				return nil, 0, err
			}
		default:
			return nil, 0, fmt.Errorf("repository search: %s: %s", resp.Status, clip(body))
		}
	}
	return nil, 0, ErrSearchRateLimited
}

// Probe is repository metadata plus the harnesses whose root config is
// on the default branch.
type Probe struct {
	Meta
	Harnesses []string
}

// ProbeRoots loads metadata for names and checks rootProbes on each
// default branch, in one GraphQL query per 10 repositories. A larger
// query of 15 object lookups per repository draws 502s.
func (c *Client) ProbeRoots(ctx context.Context, names []string) ([]Probe, error) {
	const batch = 10
	var out []Probe
	for i := 0; i < len(names); i += batch {
		end := min(i+batch, len(names))
		part, err := c.probeBatch(ctx, names[i:end])
		if err != nil {
			return out, err
		}
		out = append(out, part...)
	}
	return out, nil
}

func (c *Client) probeBatch(ctx context.Context, names []string) ([]Probe, error) {
	var objs strings.Builder
	for k, p := range rootProbes {
		fmt.Fprintf(&objs, " p%d: object(expression: %s) { __typename }", k, gqlString("HEAD:"+p.path))
	}
	var b strings.Builder
	b.WriteString("query {")
	for i, name := range names {
		owner, repo, _ := strings.Cut(name, "/")
		fmt.Fprintf(&b, " r%d: repository(owner: %s, name: %s) { nameWithOwner isFork isArchived stargazerCount diskUsage licenseInfo { spdxId } defaultBranchRef { target { oid } }%s }", i, gqlString(owner), gqlString(repo), objs.String())
	}
	b.WriteString(" }")
	payload, err := json.Marshal(map[string]string{"query": b.String()})
	if err != nil {
		return nil, err
	}
	last := errors.New("graphql: rate limit")
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
		if resp.StatusCode >= 500 {
			last = fmt.Errorf("graphql: %s", resp.Status)
			if err := sleep(ctx, c.retryGap(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("graphql: %s: %s", resp.Status, clip(body))
		}
		var parsed struct {
			Data   map[string]json.RawMessage `json:"data"`
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
		out := make([]Probe, 0, len(names))
		for i, name := range names {
			raw := parsed.Data[fmt.Sprintf("r%d", i)]
			var node gqlRepo
			var fields map[string]json.RawMessage
			if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &node) != nil || json.Unmarshal(raw, &fields) != nil || node.NameWithOwner == "" {
				out = append(out, Probe{Meta: Meta{Name: name, Missing: true}})
				continue
			}
			p := Probe{Meta: metaFrom(node)}
			seen := map[string]bool{}
			for k, probe := range rootProbes {
				v, ok := fields[fmt.Sprintf("p%d", k)]
				if !ok || string(v) == "null" || seen[probe.harness] {
					continue
				}
				seen[probe.harness] = true
				p.Harnesses = append(p.Harnesses, probe.harness)
			}
			slices.Sort(p.Harnesses)
			out = append(out, p)
		}
		return out, nil
	}
	return nil, last
}

// retryGap is the pause before retrying a GraphQL 5xx: 2s, 4s, 8s, and
// so on. A client with no CodeGap, as in tests, does not wait.
func (c *Client) retryGap(attempt int) time.Duration {
	if c.CodeGap == 0 {
		return 0
	}
	return time.Duration(2<<attempt) * time.Second
}

func metaFrom(node gqlRepo) Meta {
	m := Meta{
		Name:     node.NameWithOwner,
		Fork:     node.IsFork,
		Archived: node.IsArchived,
		Stars:    node.StargazerCount,
	}
	if node.DiskUsage != nil {
		m.SizeKB = *node.DiskUsage
	}
	if node.LicenseInfo != nil {
		m.License = node.LicenseInfo.SPDX
	}
	if node.DefaultBranchRef != nil {
		m.SHA = node.DefaultBranchRef.Target.OID
	}
	return m
}

// DiscoverOptions controls one discovery run over one window.
type DiscoverOptions struct {
	// Window is an index into DiscoverWindows.
	Window int
	// Pages is how many search pages of the window to read. The search
	// API returns at most ten.
	Pages int
	// Target is how many repositories the lock may hold.
	Target int
	Now    time.Time
	// Existing rows are kept unchanged.
	Existing []Repo
}

// Discover reads one repository-search window, keeps repositories with
// a root agent config, at least MinStars stars, a default branch, and
// no fork or archive flag, and adds new ones with Integrate. Rows
// already in Existing are not probed, so their SHA and harnesses do
// not change.
func Discover(ctx context.Context, c *Client, opt DiscoverOptions, log func(string)) ([]Repo, error) {
	if opt.Window < 0 || opt.Window >= len(DiscoverWindows) {
		return nil, fmt.Errorf("discover window %d is outside 0..%d", opt.Window, len(DiscoverWindows)-1)
	}
	if opt.Pages <= 0 || opt.Pages > 10 {
		opt.Pages = 10
	}
	if opt.Target <= 0 {
		opt.Target = 1000
	}
	if log == nil {
		log = func(string) {}
	}
	date := opt.Now.UTC().Format(time.DateOnly)
	have := map[string]bool{}
	for _, r := range opt.Existing {
		have[strings.ToLower(r.Name)] = true
	}
	query := DiscoverWindows[opt.Window]
	var fresh []Repo
	var stop error
	for page := 1; page <= opt.Pages; page++ {
		names, total, err := c.SearchRepos(ctx, query, page)
		if err != nil {
			stop = err
			break
		}
		var need []string
		for _, n := range names {
			if !have[strings.ToLower(n)] {
				need = append(need, n)
			}
		}
		probes, err := c.ProbeRoots(ctx, need)
		kept := 0
		for _, p := range probes {
			if p.Missing || p.Fork || p.Archived || p.Stars < MinStars || p.SHA == "" || len(p.Harnesses) == 0 {
				continue
			}
			have[strings.ToLower(p.Name)] = true
			license := p.License
			if !knownLicense(license) {
				license = "NOASSERTION"
			}
			fresh = append(fresh, Repo{
				Name:      p.Name,
				SHA:       strings.ToLower(p.SHA),
				License:   license,
				Harnesses: p.Harnesses,
				Date:      date,
				Band:      SizeBand(p.SizeKB),
				Stars:     p.Stars,
				SizeKB:    p.SizeKB,
			})
			kept++
		}
		log(fmt.Sprintf("discover window %d page %d: %d repositories, %d new, %d with a root config, %d indexed", opt.Window, page, len(names), len(need), kept, total))
		if err != nil {
			stop = err
			break
		}
		if len(names) < 100 {
			break
		}
	}
	var valid []Repo
	for _, r := range fresh {
		if checkRepo(r) == nil {
			valid = append(valid, r)
		} else {
			log(fmt.Sprintf("skipping %s: fails the row rules", r.Name))
		}
	}
	return Integrate(opt.Existing, valid, opt.Target, false), stop
}
