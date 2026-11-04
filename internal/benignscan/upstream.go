package benignscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vgmartinez/tripcord/internal/embedded"
)

// Upstream is one row of schemas/upstream.lock: the URL tripcord
// depends on, the SHA-256 of its bytes, and the same file at an exact
// commit, read only to print a diff when the hash drifts.
type Upstream struct {
	Name   string
	URL    string
	SHA256 string
	Pinned string
}

var (
	upstreamName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	upstreamHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pinnedURL    = regexp.MustCompile(`^https://raw\.githubusercontent\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/[0-9a-f]{40}/[A-Za-z0-9._/-]+$`)
)

// ParseUpstream reads upstream.lock. Lines starting with # are
// comments. A row is name, URL, SHA-256, and the pinned raw URL, tab
// separated. Names are unique.
func ParseUpstream(data []byte) ([]Upstream, error) {
	var out []Upstream
	seen := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		n := i + 1
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("upstream.lock:%d: %d columns, want 4", n, len(f))
		}
		u := Upstream{Name: f[0], URL: f[1], SHA256: f[2], Pinned: f[3]}
		switch {
		case !upstreamName.MatchString(u.Name):
			return nil, fmt.Errorf("upstream.lock:%d: bad name %q", n, u.Name)
		case seen[u.Name]:
			return nil, fmt.Errorf("upstream.lock:%d: duplicate name %q", n, u.Name)
		case !strings.HasPrefix(u.URL, "https://") || strings.ContainsAny(u.URL, " \"'<>"):
			return nil, fmt.Errorf("upstream.lock:%d: URL must be https", n)
		case !upstreamHash.MatchString(u.SHA256):
			return nil, fmt.Errorf("upstream.lock:%d: SHA-256 must be 64 lowercase hex digits", n)
		case !pinnedURL.MatchString(u.Pinned):
			return nil, fmt.Errorf("upstream.lock:%d: pinned URL must be a raw.githubusercontent.com URL at a 40-digit commit", n)
		}
		seen[u.Name] = true
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("upstream.lock: no rows")
	}
	return out, nil
}

// Getter fetches a URL.
type Getter func(ctx context.Context, url string) ([]byte, error)

// Drift is one row whose bytes no longer match the lock.
type Drift struct {
	Name string
	URL  string
	Want string
	Got  string
	Diff string
	Err  error
}

func (d Drift) String() string {
	if d.Err != nil {
		return fmt.Sprintf("%s: %s: %v", d.Name, d.URL, d.Err)
	}
	return fmt.Sprintf("%s: %s\n  want sha256 %s\n  got  sha256 %s\n%s", d.Name, d.URL, d.Want, d.Got, d.Diff)
}

// CheckUpstream fetches every URL and returns the rows that drifted or
// could not be read. The diff is against the pinned commit's copy,
// which must itself still hash to the locked value.
func CheckUpstream(ctx context.Context, rows []Upstream, get Getter) []Drift {
	var out []Drift
	for _, u := range rows {
		body, err := get(ctx, u.URL)
		if err != nil {
			out = append(out, Drift{Name: u.Name, URL: u.URL, Err: err})
			continue
		}
		got := sum(body)
		if got == u.SHA256 {
			continue
		}
		d := Drift{Name: u.Name, URL: u.URL, Want: u.SHA256, Got: got}
		old, err := get(ctx, u.Pinned)
		switch {
		case err != nil:
			d.Diff = fmt.Sprintf("(no diff: pinned copy %s: %v)\n", u.Pinned, err)
		case sum(old) != u.SHA256:
			d.Diff = fmt.Sprintf("(no diff: pinned copy %s hashes to %s, not the locked value)\n", u.Pinned, sum(old))
		default:
			d.Diff = embedded.UnifiedDiff(embedded.Change{Path: u.Name, Old: old, New: body})
		}
		out = append(out, d)
	}
	return out
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// maxUpstreamBytes caps one upstream file.
const maxUpstreamBytes = 8 << 20

// HTTPGet is the network Getter. Redirects are followed only to https.
func HTTPGet(ctx context.Context, url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 5 {
				return fmt.Errorf("redirect to %s refused", req.URL)
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tripcord-upstream-check")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxUpstreamBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxUpstreamBytes)
	}
	return body, nil
}
