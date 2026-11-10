// Package wiki renders docs/ into the pages of the GitHub Wiki.
//
// docs/ is the source of truth. Every docs/**/*.md file maps to exactly
// one page, relative links become wiki page links or links into the
// repository on main, and the rules catalog is built from rules/*.yaml and
// rules/ADVISORIES.json. Rendering fails on a docs file with no page, a
// link to a file or page that does not exist, or an anchor no heading
// produces, so a broken wiki cannot be pushed.
package wiki

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/project"
)

const (
	// RepoURL is the repository on GitHub.
	RepoURL = "https://github.com/" + project.Repository
	// WikiURL is the prefix of an absolute wiki page link.
	WikiURL = RepoURL + "/wiki/"

	sidebarPage = "_Sidebar"
	footerPage  = "_Footer"
)

// docPages names the wiki page of each docs file, by path under docs/.
// rules/<id>.md pages are named after the rule id (see PageName).
var docPages = map[string]string{
	"README.md":                         "Home",
	"getting-started.md":                "Getting-Started",
	"commands.md":                       "Commands",
	"scan.md":                           "Scan",
	"init.md":                           "Init",
	"hook.md":                           "Hook",
	"preopen.md":                        "Preopen",
	"pr-context.md":                     "PR-Context",
	"fingerprint.md":                    "Fingerprints",
	"output.md":                         "Output-and-Sinks",
	"privacy.md":                        "Privacy-and-Redaction",
	"github-action.md":                  "GitHub-Action",
	"pre-commit.md":                     "Pre-commit",
	"policy.md":                         "Policy",
	"faq.md":                            "FAQ",
	"roadmap.md":                        "Roadmap",
	"development.md":                    "Development",
	"release-notes.md":                  "Release-Notes",
	"design/tc-cfg-016-version-skew.md": "Design-TC-CFG-016-Version-Skew",
	"adapters/README.md":                "Harness-Adapters",
	"adapters/claude.md":                "Adapter-Claude-Code",
	"adapters/codex.md":                 "Adapter-Codex",
	"adapters/copilot.md":               "Adapter-GitHub-Copilot",
	"adapters/cursor.md":                "Adapter-Cursor",
	"adapters/devcontainer.md":          "Adapter-Dev-Container",
	"adapters/devin.md":                 "Adapter-Devin",
	"adapters/gemini.md":                "Adapter-Gemini-CLI",
	"adapters/generic.md":               "Adapter-Shared-Files",
	"adapters/opencode.md":              "Adapter-OpenCode",
	"adapters/windsurf.md":              "Adapter-Windsurf",
	"rules/README.md":                   "Rules-Catalog",
}

var rulePageRE = regexp.MustCompile(`^rules/(TC-[A-Z]+-[0-9]{3})\.md$`)

type group struct {
	title string
	pages []string
}

// sidebar groups pages for _Sidebar. Rule pages are reached from
// Rules-Catalog.
var sidebar = []group{
	{"Start", []string{"Home", "Getting-Started", "Commands", "FAQ"}},
	{"Commands", []string{"Scan", "Init", "Hook", "Preopen", "PR-Context", "Fingerprints", "Output-and-Sinks", "Privacy-and-Redaction"}},
	{"CI and hooks", []string{"GitHub-Action", "Pre-commit"}},
	{"Configuration", []string{"Policy", "Harness-Adapters", "Rules-Catalog"}},
	{"Adapters", []string{
		"Adapter-Claude-Code", "Adapter-Codex", "Adapter-Cursor", "Adapter-GitHub-Copilot",
		"Adapter-Gemini-CLI", "Adapter-OpenCode", "Adapter-Windsurf", "Adapter-Devin",
		"Adapter-Dev-Container", "Adapter-Shared-Files",
	}},
	{"Project", []string{"Roadmap", "Release-Notes", "Development"}},
}

// PageName returns the wiki page for a file under docs/, given as a
// slash path relative to docs/.
func PageName(rel string) (string, bool) {
	return defaultLayout.pageName(rel)
}

// layout is the page map and sidebar a render uses. Tests render
// fixtures with their own.
type layout struct {
	pages   map[string]string
	sidebar []group
}

var defaultLayout = layout{pages: docPages, sidebar: sidebar}

func (l layout) pageName(rel string) (string, bool) {
	if name, ok := l.pages[rel]; ok {
		return name, true
	}
	if m := rulePageRE.FindStringSubmatch(rel); m != nil {
		return m[1], true
	}
	return "", false
}

// Page is one rendered wiki page. Source is the docs file it came from,
// relative to the repository root, or "" for a generated page.
type Page struct {
	Name   string
	Source string
	Body   string
}

// Site is a rendered wiki.
type Site struct {
	root    string
	Pages   []Page
	byName  map[string]*Page
	anchors map[string]map[string]bool
}

// Render reads docs/ and rules/ under root and returns every page,
// sorted by name. It fails if any link in the output does not resolve.
func Render(root string) (*Site, error) {
	return render(root, defaultLayout)
}

func render(root string, l layout) (*Site, error) {
	docsDir := filepath.Join(root, "docs")
	var rels []string
	err := filepath.WalkDir(docsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(p) != ".md" {
			return nil
		}
		rel, err := filepath.Rel(docsDir, p)
		if err != nil {
			return err
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(rels)

	sourcePage := map[string]string{}
	ruleDocs := map[string]bool{}
	var errs []error
	owner := map[string]string{}
	for _, rel := range rels {
		name, ok := l.pageName(rel)
		if !ok {
			errs = append(errs, fmt.Errorf("docs/%s has no wiki page: add it to docPages in internal/wiki", rel))
			continue
		}
		if prev, dup := owner[name]; dup {
			errs = append(errs, fmt.Errorf("docs/%s and docs/%s both map to wiki page %s", prev, rel, name))
			continue
		}
		owner[name] = rel
		sourcePage["docs/"+rel] = name
		if m := rulePageRE.FindStringSubmatch(rel); m != nil {
			ruleDocs[m[1]] = true
		}
	}
	for rel, name := range l.pages {
		if _, ok := owner[name]; !ok {
			errs = append(errs, fmt.Errorf("wiki page %s: docs/%s does not exist", name, rel))
		}
	}
	if len(errs) > 0 {
		sortErrors(errs)
		return nil, errors.Join(errs...)
	}

	s := &Site{root: root, byName: map[string]*Page{}, anchors: map[string]map[string]bool{}}
	for _, rel := range rels {
		src := "docs/" + rel
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(src)))
		if err != nil {
			return nil, err
		}
		body := string(data)
		if rel == "rules/README.md" {
			if !strings.Contains(body, CatalogMarker) {
				return nil, fmt.Errorf("%s: missing %s", src, CatalogMarker)
			}
			specs, err := loadSpecs(filepath.Join(root, "rules"))
			if err != nil {
				return nil, err
			}
			adv, err := loadAdvisories(filepath.Join(root, "rules"))
			if err != nil {
				return nil, err
			}
			body = strings.Replace(body, CatalogMarker, catalog(specs, adv, ruleDocs), 1)
		}
		body, err = mapLinks(body, func(t string) (string, error) {
			return s.rewrite(src, t, sourcePage)
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		header := fmt.Sprintf("<!-- Generated from %s by cmd/wikigen. Do not edit the wiki; change %s instead. -->\n\n", src, src)
		s.add(Page{Name: sourcePage[src], Source: src, Body: header + body})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	s.add(Page{Name: sidebarPage, Body: sidebarBody(l.sidebar)})
	s.add(Page{Name: footerPage, Body: footer()})
	sort.Slice(s.Pages, func(i, j int) bool { return s.Pages[i].Name < s.Pages[j].Name })
	for i := range s.Pages {
		s.byName[s.Pages[i].Name] = &s.Pages[i]
	}

	for _, p := range s.Pages {
		if err := s.checkPage(p); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.checkReachable(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return s, nil
}

func (s *Site) add(p Page) {
	s.Pages = append(s.Pages, p)
	s.anchors[p.Name] = Anchors(p.Body)
}

// Page returns the page with this name.
func (s *Site) Page(name string) (Page, bool) {
	p, ok := s.byName[name]
	if !ok {
		return Page{}, false
	}
	return *p, true
}

func hasScheme(t string) bool {
	return strings.Contains(t, "://") || strings.HasPrefix(t, "mailto:")
}

// rewrite turns one link target in the docs file src into a wiki target:
// a docs page becomes its page name, any other repository path a link to
// it on main, and an absolute URL or a same-page anchor stays.
func (s *Site) rewrite(src, target string, sourcePage map[string]string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("%s: empty link target", src)
	}
	if hasScheme(target) || strings.HasPrefix(target, "#") {
		return target, nil
	}
	p, frag, _ := strings.Cut(target, "#")
	repoPath := path.Clean(path.Join(path.Dir(src), p))
	if repoPath == ".." || strings.HasPrefix(repoPath, "../") || path.IsAbs(p) {
		return "", fmt.Errorf("%s: link %q leaves the repository", src, target)
	}
	suffix := ""
	if frag != "" {
		suffix = "#" + frag
	}
	if page, ok := sourcePage[repoPath]; ok {
		return page + suffix, nil
	}
	info, err := os.Stat(filepath.Join(s.root, filepath.FromSlash(repoPath)))
	if err != nil {
		return "", fmt.Errorf("%s: link %q: %s does not exist", src, target, repoPath)
	}
	kind := "blob"
	if info.IsDir() {
		kind = "tree"
	}
	return RepoURL + "/" + kind + "/main/" + repoPath + suffix, nil
}

// checkPage resolves every link on a rendered page.
func (s *Site) checkPage(p Page) error {
	var errs []error
	for _, t := range links(p.Body) {
		if err := s.checkWikiTarget(p.Name, t); err != nil {
			errs = append(errs, fmt.Errorf("wiki page %s: %w", p.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Site) checkWikiTarget(from, t string) error {
	switch {
	case strings.HasPrefix(t, "#"):
		return s.checkAnchor(from, t[1:], t)
	case hasScheme(t):
		return s.checkAbsolute(t)
	case strings.Contains(t, "/"):
		return fmt.Errorf("link %q is a relative path, not a page name", t)
	}
	name, frag, _ := strings.Cut(t, "#")
	if _, ok := s.byName[name]; !ok {
		return fmt.Errorf("link %q: no page %s", t, name)
	}
	if frag == "" {
		return nil
	}
	return s.checkAnchor(name, frag, t)
}

func (s *Site) checkAnchor(page, frag, t string) error {
	if !s.anchors[page][frag] {
		return fmt.Errorf("link %q: page %s has no heading #%s", t, page, frag)
	}
	return nil
}

// checkAbsolute resolves a wiki page URL or a blob or tree URL on main.
// Other absolute URLs are not checked.
func (s *Site) checkAbsolute(t string) error {
	if rest, ok := strings.CutPrefix(t, WikiURL); ok {
		name, frag, _ := strings.Cut(rest, "#")
		if _, ok := s.byName[name]; !ok {
			return fmt.Errorf("link %q: no wiki page %s", t, name)
		}
		if frag != "" {
			return s.checkAnchor(name, frag, t)
		}
		return nil
	}
	for _, kind := range []string{"/blob/main/", "/tree/main/"} {
		rest, ok := strings.CutPrefix(t, RepoURL+kind)
		if !ok {
			continue
		}
		return s.checkRepoPath(rest, kind == "/tree/main/", t)
	}
	return nil
}

func (s *Site) checkRepoPath(rest string, wantDir bool, t string) error {
	p, frag, _ := strings.Cut(rest, "#")
	full := filepath.Join(s.root, filepath.FromSlash(p))
	info, err := os.Stat(full)
	if err != nil {
		return fmt.Errorf("link %q: %s does not exist", t, p)
	}
	if info.IsDir() != wantDir {
		return fmt.Errorf("link %q: %s is the wrong kind of path for this URL", t, p)
	}
	if frag == "" || filepath.Ext(p) != ".md" {
		return nil
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	if !Anchors(string(data))[frag] {
		return fmt.Errorf("link %q: %s has no heading #%s", t, p, frag)
	}
	return nil
}

// CheckRepoFile resolves every link in a repository Markdown file, such
// as README.md, given as a slash path relative to the root. Relative
// links must name existing repository files (and headings, for a .md
// file); wiki URLs must name a rendered page and heading.
func (s *Site) CheckRepoFile(rel string) error {
	data, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(rel)))
	if err != nil {
		return err
	}
	md := string(data)
	var errs []error
	for _, t := range links(md) {
		var err error
		switch {
		case strings.HasPrefix(t, "#"):
			if !Anchors(md)[t[1:]] {
				err = fmt.Errorf("link %q: no heading #%s", t, t[1:])
			}
		case hasScheme(t):
			err = s.checkAbsolute(t)
		default:
			p, frag, _ := strings.Cut(t, "#")
			repoPath := path.Clean(path.Join(path.Dir(rel), p))
			if repoPath == ".." || strings.HasPrefix(repoPath, "../") || path.IsAbs(p) {
				err = fmt.Errorf("link %q leaves the repository", t)
				break
			}
			info, statErr := os.Stat(filepath.Join(s.root, filepath.FromSlash(repoPath)))
			if statErr != nil {
				err = fmt.Errorf("link %q: %s does not exist", t, repoPath)
				break
			}
			target := repoPath
			if frag != "" {
				target += "#" + frag
			}
			err = s.checkRepoPath(target, info.IsDir(), t)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", rel, err))
		}
	}
	return errors.Join(errs...)
}

// checkReachable requires every page to be linked from the sidebar, the
// home page, or a page reachable from them.
func (s *Site) checkReachable() error {
	seen := map[string]bool{sidebarPage: true, footerPage: true}
	queue := []string{sidebarPage, footerPage, "Home"}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		seen[name] = true
		p, ok := s.byName[name]
		if !ok {
			continue
		}
		for _, t := range links(p.Body) {
			if hasScheme(t) {
				rest, ok := strings.CutPrefix(t, WikiURL)
				if !ok {
					continue
				}
				t = rest
			}
			target, _, _ := strings.Cut(t, "#")
			if target != "" && !seen[target] {
				seen[target] = true
				queue = append(queue, target)
			}
		}
	}
	var missing []string
	for _, p := range s.Pages {
		if !seen[p.Name] {
			missing = append(missing, p.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("pages no other page links to: %s", strings.Join(missing, ", "))
	}
	return nil
}

func sidebarBody(groups []group) string {
	var b strings.Builder
	b.WriteString("<!-- Generated by cmd/wikigen. Do not edit. -->\n\n")
	b.WriteString("**[tripcord](Home)**\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "\n**%s**\n\n", g.title)
		for _, name := range g.pages {
			label := strings.ReplaceAll(strings.TrimPrefix(name, "Adapter-"), "-", " ")
			if name == "Pre-commit" {
				label = "pre-commit"
			}
			fmt.Fprintf(&b, "- [%s](%s)\n", label, name)
		}
	}
	return b.String()
}

func footer() string {
	return "<!-- Generated by cmd/wikigen. Do not edit. -->\n\n" +
		"This wiki is generated from [`docs/`](" + RepoURL + "/tree/main/docs) on `main` by `cmd/wikigen`. " +
		"Do not edit it here: change `docs/` and open a pull request. " +
		"[Apache-2.0](" + RepoURL + "/blob/main/LICENSE).\n"
}

func sortErrors(errs []error) {
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
}

// Write writes each page to dir as <Name>.md. dir must be absent or
// empty, so a stale page can never survive a render.
func Write(dir string, pages []Page) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty", dir)
	}
	for _, p := range pages {
		if err := os.WriteFile(filepath.Join(dir, p.Name+".md"), []byte(p.Body), 0o644); err != nil {
			return err
		}
	}
	return nil
}
