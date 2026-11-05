package corpus

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
	"github.com/vgmartinez/tripcord/internal/txtar"
)

// KindVendor is a vendored snippet whose provenance does not check out.
const KindVendor = "vendored"

// VendoredDir holds third-party benign snippets, relative to a corpus
// root. A snippet is <owner>/<repo>/<name>.txtar there.
const VendoredDir = "benign/vendored"

// NoticesFile is the attribution file at the module root, the sibling
// of the corpus directory.
const NoticesFile = "THIRD_PARTY_NOTICES"

// VendoredLicenses are the SPDX ids a vendored snippet may carry: the
// permissive licenses whose terms an attribution entry satisfies.
var VendoredLicenses = []string{"Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT"}

var (
	sourceRE    = regexp.MustCompile(`^([A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,64})@([0-9a-f]{40}):(\S+)$`)
	noticeRule  = strings.Repeat("=", 80)
	noticeSplit = strings.Repeat("-", 80)
)

// Vendored is one parsed snippet. Its txtar comment is exactly two
// lines, "source: owner/repo@sha:path" and "license: SPDX", and it has
// one member named path.
type Vendored struct {
	Repo    string
	SHA     string
	Path    string
	License string
	Archive *txtar.Archive
}

// ParseVendored reads a vendored snippet and checks its header.
func ParseVendored(data []byte) (Vendored, error) {
	arc := txtar.Parse(data)
	v := Vendored{Archive: arc}
	seen := map[string]bool{}
	for line := range strings.Lines(string(arc.Comment)) {
		line = strings.TrimSuffix(line, "\n")
		key, value, ok := strings.Cut(line, ": ")
		if !ok || value != strings.TrimSpace(value) || value == "" {
			return v, fmt.Errorf("header line %q is not key: value", line)
		}
		if seen[key] {
			return v, fmt.Errorf("duplicate header %s", key)
		}
		seen[key] = true
		switch key {
		case "source":
			m := sourceRE.FindStringSubmatch(value)
			if m == nil {
				return v, fmt.Errorf("source %q is not owner/repo@sha:path", value)
			}
			v.Repo, v.SHA, v.Path = m[1], m[2], m[3]
		case "license":
			v.License = value
		default:
			return v, fmt.Errorf("unknown header %s", key)
		}
	}
	if v.Repo == "" || v.License == "" {
		return v, errors.New("needs source and license headers")
	}
	if !slices.Contains(VendoredLicenses, v.License) {
		return v, fmt.Errorf("license %s is not one of %s", v.License, strings.Join(VendoredLicenses, ", "))
	}
	if len(arc.Files) != 1 {
		return v, fmt.Errorf("has %d members, want 1", len(arc.Files))
	}
	if arc.Files[0].Name != v.Path {
		return v, fmt.Errorf("member %q is not the source path %q", arc.Files[0].Name, v.Path)
	}
	if clean, err := txtar.Rel(v.Path); err != nil || clean != v.Path {
		return v, fmt.Errorf("source path %q is not a clean relative path", v.Path)
	}
	return v, nil
}

type noticeEntry struct {
	Repo    string
	SHA     string
	License string
	Files   []string
}

// parseNotices reads THIRD_PARTY_NOTICES. A block starts at a line of
// 80 '=' followed by a "Repository: " or "License text: " line; a rule
// line inside a reproduced license or NOTICE text does not start one.
// Text before the first block is the preamble. An entry block has
// Repository, Commit, License, License file, one or more Copyright
// lines, and Files with one indented path per line, then a line of 80
// '-' and the license or NOTICE text. The "License text: Apache-2.0"
// block holds that license once for every Apache-2.0 entry.
func parseNotices(data []byte) (map[string]noticeEntry, error) {
	var blocks []string
	lines := strings.SplitAfter(string(data), "\n")
	start := -1
	for i, l := range lines {
		next := ""
		if i+1 < len(lines) {
			next = lines[i+1]
		}
		if l != noticeRule+"\n" || (!strings.HasPrefix(next, "Repository: ") && !strings.HasPrefix(next, "License text: ")) {
			continue
		}
		if start >= 0 {
			blocks = append(blocks, strings.Join(lines[start:i], ""))
		}
		start = i + 1
	}
	if start < 0 {
		return nil, errors.New("no entries")
	}
	blocks = append(blocks, strings.Join(lines[start:], ""))
	entries := map[string]noticeEntry{}
	apacheText := false
	needApache := false
	for i, block := range blocks {
		head, body, ok := strings.Cut(block, noticeSplit+"\n")
		if !ok || strings.TrimSpace(body) == "" {
			return nil, fmt.Errorf("block %d has no text after the separator", i+1)
		}
		if head == "License text: Apache-2.0\n" {
			apacheText = strings.Contains(body, "Apache License") && strings.Contains(body, "Version 2.0, January 2004")
			continue
		}
		e, err := parseNoticeHead(head)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i+1, err)
		}
		if _, dup := entries[e.Repo]; dup {
			return nil, fmt.Errorf("duplicate entry for %s", e.Repo)
		}
		if e.License == "Apache-2.0" {
			needApache = true
		}
		entries[e.Repo] = e
	}
	if needApache && !apacheText {
		return nil, errors.New("Apache-2.0 entries need the License text: Apache-2.0 block")
	}
	return entries, nil
}

func parseNoticeHead(head string) (noticeEntry, error) {
	var e noticeEntry
	lines := strings.Split(strings.TrimSuffix(head, "\n"), "\n")
	want := []string{"Repository: ", "Commit: ", "License: ", "License file: "}
	if len(lines) < len(want) {
		return e, errors.New("short entry header")
	}
	vals := make([]string, len(want))
	for i, prefix := range want {
		v, ok := strings.CutPrefix(lines[i], prefix)
		if !ok || v == "" {
			return e, fmt.Errorf("line %d is not %q", i+1, strings.TrimSpace(prefix)+" <value>")
		}
		vals[i] = v
	}
	e.Repo, e.SHA, e.License = vals[0], vals[1], vals[2]
	rest := lines[len(want):]
	copyrights := 0
	for len(rest) > 0 && strings.HasPrefix(rest[0], "Copyright: ") {
		copyrights++
		rest = rest[1:]
	}
	if copyrights == 0 {
		return e, fmt.Errorf("%s: no Copyright line", e.Repo)
	}
	if len(rest) == 0 || rest[0] != "Files:" {
		return e, fmt.Errorf("%s: Copyright lines are not followed by a Files line", e.Repo)
	}
	for _, l := range rest[1:] {
		f, ok := strings.CutPrefix(l, "  ")
		if !ok || f == "" || strings.TrimSpace(f) != f {
			return e, fmt.Errorf("%s: Files line %q is not an indented path", e.Repo, l)
		}
		e.Files = append(e.Files, f)
	}
	if len(e.Files) == 0 {
		return e, fmt.Errorf("%s: no Files", e.Repo)
	}
	return e, nil
}

// vendorCheck checks the snippets under one corpus root against
// repos.lock and THIRD_PARTY_NOTICES. Both are loaded on the first
// snippet, so a corpus without vendored files needs neither.
type vendorCheck struct {
	root    string
	abs     string
	loaded  bool
	loadErr error
	lock    map[string]benign.Repo
	notices map[string]noticeEntry
	seen    map[string]bool
}

func newVendorCheck(root, abs string) *vendorCheck {
	return &vendorCheck{root: root, abs: abs, seen: map[string]bool{}}
}

// vendored reports whether rel, from a root named corpus, is under
// VendoredDir.
func vendored(rootAbs, rel string) bool {
	return filepath.Base(rootAbs) == "corpus" && strings.HasPrefix(rel, VendoredDir+"/")
}

func (c *vendorCheck) load() error {
	if c.loaded {
		return c.loadErr
	}
	c.loaded = true
	raw, err := os.ReadFile(filepath.Join(c.abs, "benign", "repos.lock"))
	if err != nil {
		c.loadErr = fmt.Errorf("repos.lock: %w", err)
		return c.loadErr
	}
	repos, err := benign.LoadLock(raw)
	if err != nil {
		c.loadErr = fmt.Errorf("repos.lock: %w", err)
		return c.loadErr
	}
	c.lock = map[string]benign.Repo{}
	for _, r := range repos {
		c.lock[r.Name] = r
	}
	raw, err = os.ReadFile(filepath.Join(filepath.Dir(c.abs), NoticesFile))
	if err != nil {
		c.loadErr = fmt.Errorf("%s: %w", NoticesFile, err)
		return c.loadErr
	}
	if c.notices, err = parseNotices(raw); err != nil {
		c.loadErr = fmt.Errorf("%s: %w", NoticesFile, err)
	}
	return c.loadErr
}

func (c *vendorCheck) finding(rel, detail string) []Finding {
	return []Finding{{Root: c.root, Path: rel, Kind: KindVendor, Detail: detail}}
}

// check validates one regular file under VendoredDir.
func (c *vendorCheck) check(rel, p string) []Finding {
	if !strings.HasSuffix(rel, ".txtar") {
		return c.finding(rel, "a vendored file is a .txtar snippet")
	}
	c.seen["corpus/"+rel] = true
	data, err := os.ReadFile(p)
	if err != nil {
		return c.finding(rel, err.Error())
	}
	v, err := ParseVendored(data)
	if err != nil {
		return c.finding(rel, err.Error())
	}
	if path.Dir(rel) != VendoredDir+"/"+v.Repo {
		return c.finding(rel, fmt.Sprintf("a snippet from %s lives in %s/%s/", v.Repo, VendoredDir, v.Repo))
	}
	if err := c.load(); err != nil {
		return c.finding(rel, err.Error())
	}
	lock, ok := c.lock[v.Repo]
	switch {
	case !ok:
		return c.finding(rel, v.Repo+" is not in repos.lock")
	case lock.SHA != v.SHA:
		return c.finding(rel, fmt.Sprintf("commit %s is not the repos.lock pin %s", v.SHA, lock.SHA))
	case lock.License != v.License:
		return c.finding(rel, fmt.Sprintf("license %s is not the repos.lock license %s", v.License, lock.License))
	}
	e, ok := c.notices[v.Repo]
	switch {
	case !ok:
		return c.finding(rel, v.Repo+" has no "+NoticesFile+" entry")
	case e.SHA != v.SHA || e.License != v.License:
		return c.finding(rel, fmt.Sprintf("%s entry is %s %s, the snippet is %s %s", NoticesFile, e.SHA, e.License, v.SHA, v.License))
	case !slices.Contains(e.Files, "corpus/"+rel):
		return c.finding(rel, NoticesFile+" entry for "+v.Repo+" does not list this file")
	}
	return nil
}

// finish reports notice entries that list a file that is not vendored.
// A corpus with no snippets and no notices file has nothing to check.
func (c *vendorCheck) finish() []Finding {
	if len(c.seen) == 0 {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(c.abs), NoticesFile)); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err := c.load(); err != nil {
			return c.finding(VendoredDir, err.Error())
		}
	}
	if c.loadErr != nil {
		return nil
	}
	var out []Finding
	for _, e := range c.notices {
		for _, f := range e.Files {
			if !c.seen[f] {
				out = append(out, Finding{Root: c.root, Path: VendoredDir, Kind: KindVendor, Detail: fmt.Sprintf("%s lists %s for %s, which is not vendored", NoticesFile, f, e.Repo)})
			}
		}
	}
	slices.SortFunc(out, func(a, b Finding) int { return strings.Compare(a.Detail, b.Detail) })
	return out
}
