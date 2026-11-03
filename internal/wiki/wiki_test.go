package wiki

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const repoRoot = "../.."

func renderRepo(t *testing.T) *Site {
	t.Helper()
	s, err := Render(repoRoot)
	if err != nil {
		t.Fatalf("render the wiki from docs/:\n%v", err)
	}
	return s
}

func docsFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	docs := filepath.Join(repoRoot, "docs")
	err := filepath.WalkDir(docs, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".md" {
			return err
		}
		rel, err := filepath.Rel(docs, p)
		out = append(out, filepath.ToSlash(rel))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestEveryDocMapsToOnePage requires each docs/**/*.md file to render to
// its own page, so nothing in docs/ is missing from the wiki.
func TestEveryDocMapsToOnePage(t *testing.T) {
	s := renderRepo(t)
	seen := map[string]string{}
	for _, rel := range docsFiles(t) {
		name, ok := PageName(rel)
		if !ok {
			t.Errorf("docs/%s has no wiki page", rel)
			continue
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("docs/%s and docs/%s both map to %s", prev, rel, name)
		}
		seen[name] = rel
		p, ok := s.Page(name)
		if !ok {
			t.Errorf("docs/%s: page %s was not rendered", rel, name)
			continue
		}
		if p.Source != "docs/"+rel {
			t.Errorf("page %s source = %s, want docs/%s", name, p.Source, rel)
		}
	}
	for _, name := range []string{"_Sidebar", "_Footer"} {
		if _, ok := s.Page(name); !ok {
			t.Errorf("no %s page", name)
		}
	}
	if got, want := len(s.Pages), len(seen)+2; got != want {
		t.Errorf("rendered %d pages, want %d (one per docs file plus _Sidebar and _Footer)", got, want)
	}
}

// TestRequiredPages pins the pages the wiki promises.
func TestRequiredPages(t *testing.T) {
	s := renderRepo(t)
	for _, name := range []string{
		"Home", "Getting-Started", "Commands", "Scan", "Init", "Preopen", "Fingerprints",
		"PR-Context", "Output-and-Sinks", "GitHub-Action", "Pre-commit", "Policy",
		"Harness-Adapters", "Rules-Catalog", "FAQ",
	} {
		if _, ok := s.Page(name); !ok {
			t.Errorf("missing page %s", name)
		}
	}
}

// TestRenderedLinksResolve re-checks every rendered page on its own, so a
// regression in Render's own check cannot hide a broken link.
func TestRenderedLinksResolve(t *testing.T) {
	s := renderRepo(t)
	n := 0
	for _, p := range s.Pages {
		for _, target := range links(p.Body) {
			n++
			if strings.HasSuffix(strings.SplitN(target, "#", 2)[0], ".md") && !hasScheme(target) {
				t.Errorf("page %s: link %q still points at a .md file", p.Name, target)
			}
		}
		if err := s.checkPage(p); err != nil {
			t.Error(err)
		}
	}
	if n < 100 {
		t.Fatalf("found only %d links; the link scanner is broken", n)
	}
}

// TestReadmeLinksResolve checks README.md: relative links name existing
// files and headings, and wiki links name rendered pages and headings.
func TestReadmeLinksResolve(t *testing.T) {
	s := renderRepo(t)
	if err := s.CheckRepoFile("README.md"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"Commands", "Policy", "Rules-Catalog", "Harness-Adapters", "FAQ"} {
		if !strings.Contains(string(data), "]("+WikiURL+page) {
			t.Errorf("README.md does not link to the %s wiki page", page)
		}
	}
	for _, f := range []string{"CONTRIBUTING.md", "SECURITY.md"} {
		if err := s.CheckRepoFile(f); err != nil {
			t.Error(err)
		}
	}
}

// TestCatalogCoversPack requires a catalog row per rule file and per
// current advisory, and a known-gaps entry for each documented id that
// has no rule file.
func TestCatalogCoversPack(t *testing.T) {
	s := renderRepo(t)
	page, ok := s.Page("Rules-Catalog")
	if !ok {
		t.Fatal("no Rules-Catalog page")
	}
	if strings.Contains(page.Body, CatalogMarker) {
		t.Fatal("catalog marker was not replaced")
	}
	specs, err := loadSpecs(filepath.Join(repoRoot, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) == 0 {
		t.Fatal("no rule files")
	}
	hasRule := map[string]bool{}
	for _, spec := range specs {
		hasRule[spec.ID] = true
		row := regexp.MustCompile(`(?m)^\| \[` + regexp.QuoteMeta(spec.ID) + `\]\(` + regexp.QuoteMeta(spec.ID) + `\) \| .*\| ` +
			regexp.QuoteMeta(spec.Severity) + `[ |(]`)
		if !row.MatchString(page.Body) {
			t.Errorf("catalog has no row for %s with severity %s", spec.ID, spec.Severity)
		}
		if !strings.Contains(page.Body, cell(spec.Fix)) {
			t.Errorf("catalog row for %s is missing its fix", spec.ID)
		}
	}
	advisories, err := loadAdvisories(filepath.Join(repoRoot, "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) == 0 {
		t.Fatal("no advisories")
	}
	for _, a := range advisories {
		if !strings.Contains(page.Body, "\n| "+a.ID+" | ") {
			t.Errorf("catalog has no row for advisory %s", a.ID)
		}
	}

	_, gaps, ok := strings.Cut(page.Body, "\n## Known gaps\n")
	if !ok {
		t.Fatal("no Known gaps section")
	}
	gaps, _, _ = strings.Cut(gaps, "\n## ")
	for _, rel := range docsFiles(t) {
		m := rulePageRE.FindStringSubmatch(rel)
		if m == nil || hasRule[m[1]] {
			continue
		}
		if !strings.Contains(gaps, "["+m[1]+"]("+m[1]+")") {
			t.Errorf("%s is documented without a rule file but is not under Known gaps", m[1])
		}
	}
	if !strings.Contains(gaps, "documentation-only in v0") || !strings.Contains(gaps, "/issues/41") {
		t.Error("Known gaps must call TC-CFG-013 documentation-only in v0 and link #41")
	}
}

// TestNoVendorNames keeps vendor names that are not part of this project
// out of the docs, the README, and the wiki.
func TestNoVendorNames(t *testing.T) {
	banned := []string{"neural" + "trust", "trust" + "gate"}
	check := func(label, text string) {
		lower := strings.ToLower(text)
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("%s mentions %q", label, b)
			}
		}
	}
	for _, p := range renderRepo(t).Pages {
		check("wiki page "+p.Name, p.Body)
	}
	for _, f := range []string{"README.md", "CONTRIBUTING.md", "SECURITY.md"} {
		data, err := os.ReadFile(filepath.Join(repoRoot, f))
		if err != nil {
			t.Fatal(err)
		}
		check(f, string(data))
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, b := renderRepo(t), renderRepo(t)
	if len(a.Pages) != len(b.Pages) {
		t.Fatalf("page count %d then %d", len(a.Pages), len(b.Pages))
	}
	for i := range a.Pages {
		if a.Pages[i] != b.Pages[i] {
			t.Errorf("page %s differs between renders", a.Pages[i].Name)
		}
	}
}

func TestEveryPageSaysItIsGenerated(t *testing.T) {
	for _, p := range renderRepo(t).Pages {
		if !strings.HasPrefix(p.Body, "<!-- Generated ") || !strings.Contains(p.Body, "Do not edit") {
			t.Errorf("page %s has no generated-file header", p.Name)
		}
	}
}

func TestWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wiki")
	pages := []Page{{Name: "Home", Body: "home\n"}, {Name: "_Footer", Body: "foot\n"}}
	if err := Write(dir, pages); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "Home.md"))
	if err != nil || string(got) != "home\n" {
		t.Fatalf("Home.md = %q, %v", got, err)
	}
	if err := Write(dir, pages); err == nil {
		t.Fatal("Write into a non-empty directory succeeded")
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if _, ok := files["LICENSE"]; !ok {
		files["LICENSE"] = "license\n"
	}
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var fixtureLayout = layout{
	pages:   map[string]string{"README.md": "Home", "guide.md": "Guide"},
	sidebar: []group{{"Start", []string{"Home", "Guide"}}},
}

func TestRenderRewritesLinks(t *testing.T) {
	root := writeTree(t, map[string]string{
		"docs/README.md": "# Home\n\nSee [the guide](guide.md#two-words), [code](../src/main.go), " +
			"[src](../src), [here](#home), and [out](https://example.com/x.md).\n\n" +
			"`[not](a-link.md)` and\n\n```md\n[also not](missing.md)\n```\n",
		"docs/guide.md": "# Guide\n\n## Two words\n\n## Two words\n\nBack [home](README.md) and [again](#two-words-1).\n",
		"src/main.go":   "package main\n",
	})
	s, err := render(root, fixtureLayout)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := s.Page("Home")
	for _, want := range []string{
		"[the guide](Guide#two-words)",
		"[code](" + RepoURL + "/blob/main/src/main.go)",
		"[src](" + RepoURL + "/tree/main/src)",
		"[here](#home)",
		"[out](https://example.com/x.md)",
		"`[not](a-link.md)`",
		"[also not](missing.md)",
	} {
		if !strings.Contains(home.Body, want) {
			t.Errorf("Home is missing %q:\n%s", want, home.Body)
		}
	}
	guide, _ := s.Page("Guide")
	if !strings.Contains(guide.Body, "[home](Home)") || !strings.Contains(guide.Body, "[again](#two-words-1)") {
		t.Errorf("Guide links not rewritten:\n%s", guide.Body)
	}
}

func TestRenderRejects(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"unmapped doc": {
			files: map[string]string{"docs/README.md": "# Home\n[g](guide.md)\n", "docs/guide.md": "# G\n", "docs/extra.md": "# X\n"},
			want:  "docs/extra.md has no wiki page",
		},
		"missing doc": {
			files: map[string]string{"docs/README.md": "# Home\n"},
			want:  "docs/guide.md does not exist",
		},
		"broken file link": {
			files: map[string]string{"docs/README.md": "# Home\n[x](../nope.go)\n", "docs/guide.md": "# G\n"},
			want:  "nope.go does not exist",
		},
		"missing anchor": {
			files: map[string]string{"docs/README.md": "# Home\n[x](guide.md#nope)\n", "docs/guide.md": "# G\n"},
			want:  "page Guide has no heading #nope",
		},
		"missing same-page anchor": {
			files: map[string]string{"docs/README.md": "# Home\n[x](#nope)\n", "docs/guide.md": "# G\n"},
			want:  "page Home has no heading #nope",
		},
		"leaves the repository": {
			files: map[string]string{"docs/README.md": "# Home\n[x](../../etc/passwd)\n", "docs/guide.md": "# G\n"},
			want:  "leaves the repository",
		},
		"repo anchor": {
			files: map[string]string{"docs/README.md": "# Home\n[x](../NOTES.md#gone)\n", "docs/guide.md": "# G\n", "NOTES.md": "# Notes\n"},
			want:  "NOTES.md has no heading #gone",
		},
		"bad wiki URL": {
			files: map[string]string{"docs/README.md": "# Home\n[x](" + WikiURL + "Nope)\n", "docs/guide.md": "# G\n"},
			want:  "no wiki page Nope",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := render(writeTree(t, tc.files), fixtureLayout)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestUnreachablePage(t *testing.T) {
	l := layout{
		pages:   map[string]string{"README.md": "Home", "guide.md": "Guide"},
		sidebar: []group{{"Start", []string{"Home"}}},
	}
	_, err := render(writeTree(t, map[string]string{"docs/README.md": "# Home\n", "docs/guide.md": "# G\n"}), l)
	if err == nil || !strings.Contains(err.Error(), "pages no other page links to: Guide") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckRepoFile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"docs/README.md": "# Home\n\n## Install\n[g](guide.md)\n",
		"docs/guide.md":  "# G\n",
		"README.md": "# R\n\n[l](LICENSE) [d](docs/guide.md) [w](" + WikiURL + "Home#install) " +
			"[bad](" + WikiURL + "Home#nope) [gone](MISSING.md) [self](#r)\n",
	})
	s, err := render(root, fixtureLayout)
	if err != nil {
		t.Fatal(err)
	}
	err = s.CheckRepoFile("README.md")
	if err == nil {
		t.Fatal("broken README links passed")
	}
	msg := err.Error()
	for _, want := range []string{"page Home has no heading #nope", "MISSING.md does not exist"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
	if strings.Count(msg, "\n")+1 != 2 {
		t.Errorf("want exactly two errors, got:\n%s", msg)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Exit codes":            "exit-codes",
		"With `--embed`":        "with---embed",
		"User (`--scope user`)": "user---scope-user",
		"Repository (`--scope repo`, the default)": "repository---scope-repo-the-default",
		"Fail-closed vs s1 fallback":               "fail-closed-vs-s1-fallback",
		"What is fetched, and how":                 "what-is-fetched-and-how",
		"TC-CFG-014":                               "tc-cfg-014",
		"See [the docs](x.md) now":                 "see-the-docs-now",
		"snake_case":                               "snake_case",
	} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnchors(t *testing.T) {
	got := Anchors("# A\n\n## B ##\n```sh\n# not a heading\n```\n## B\n    ## indented code\n#nohash\n")
	for _, want := range []string{"a", "b", "b-1"} {
		if !got[want] {
			t.Errorf("missing anchor %q in %v", want, got)
		}
	}
	for _, bad := range []string{"not-a-heading", "indented-code", "nohash"} {
		if got[bad] {
			t.Errorf("unexpected anchor %q", bad)
		}
	}
}

// TestWikiSyncWorkflow pins the wiki-sync workflow's triggers, token
// scope, and push target.
func TestWikiSyncWorkflow(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "wiki-sync.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		On struct {
			Push struct {
				Branches []string `yaml:"branches"`
				Paths    []string `yaml:"paths"`
			} `yaml:"push"`
		} `yaml:"on"`
		Permissions map[string]string `yaml:"permissions"`
		Concurrency struct {
			Group string `yaml:"group"`
		} `yaml:"concurrency"`
		Jobs map[string]struct {
			If          string            `yaml:"if"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
				Run  string            `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	if strings.Join(wf.On.Push.Branches, ",") != "main" {
		t.Errorf("push branches = %v, want [main]", wf.On.Push.Branches)
	}
	for _, p := range []string{"docs/**", "rules/**"} {
		if !strings.Contains(strings.Join(wf.On.Push.Paths, " "), p) {
			t.Errorf("push paths %v do not include %s", wf.On.Push.Paths, p)
		}
	}
	var triggers struct {
		On map[string]any `yaml:"on"`
	}
	if err := yaml.Unmarshal(data, &triggers); err != nil {
		t.Fatal(err)
	}
	if _, ok := triggers.On["workflow_dispatch"]; !ok {
		t.Error("no workflow_dispatch trigger")
	}
	if len(wf.Permissions) != 0 {
		t.Errorf("top-level permissions = %v, want none", wf.Permissions)
	}
	if wf.Concurrency.Group == "" {
		t.Error("no concurrency group")
	}
	if len(wf.Jobs) != 1 {
		t.Fatalf("want one job, got %d", len(wf.Jobs))
	}
	shaPin := regexp.MustCompile(`^[a-z0-9-]+/[a-z0-9-]+@[0-9a-f]{40}$`)
	const wantGuard = "github.repository == 'vgmartinez/tripcord' && github.ref == 'refs/heads/main'"
	for id, job := range wf.Jobs {
		if job.If != wantGuard {
			t.Errorf("job %s if = %q, want %q", id, job.If, wantGuard)
		}
		if len(job.Permissions) != 1 || job.Permissions["contents"] != "write" {
			t.Errorf("job %s permissions = %v, want only contents: write", id, job.Permissions)
		}
		var run strings.Builder
		for _, step := range job.Steps {
			if step.Uses != "" {
				if !shaPin.MatchString(step.Uses) {
					t.Errorf("job %s: %s is not pinned by full commit SHA", id, step.Uses)
				}
				if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["persist-credentials"] != "false" {
					t.Errorf("job %s: checkout keeps credentials", id)
				}
			}
			if strings.Contains(step.Run, "${{") {
				t.Errorf("job %s: a run script interpolates an expression", id)
			}
			run.WriteString(step.Run)
		}
		script := run.String()
		for _, want := range []string{"go run ./cmd/wikigen", ".wiki.git", "HEAD:master", "diff --cached --quiet"} {
			if !strings.Contains(script, want) {
				t.Errorf("job %s: run scripts do not contain %q", id, want)
			}
		}
		// A missing wiki is GitHub's "Repository not found" line and
		// nothing else. A broader match would treat an auth or transport
		// error that happens to end in "not found" as success.
		if !strings.Contains(script, "grep -F -q 'Repository not found'") {
			t.Errorf("job %s: missing-wiki check must be a fixed-string match of %q", id, "Repository not found")
		}
		for _, broad := range []string{"not found$", "grep -qi", "grep -qE", "grep -E", "does not appear to be a git repository"} {
			if strings.Contains(script, broad) {
				t.Errorf("job %s: missing-wiki check matches more than %q (contains %q)", id, "Repository not found", broad)
			}
		}
	}
}
