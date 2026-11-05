package corpus

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

var (
	vendSHA   = strings.Repeat("ab", 20)
	otherSHA  = strings.Repeat("cd", 20)
	vendRule  = strings.Repeat("=", 80)
	vendSplit = strings.Repeat("-", 80)
)

const vendRel = "benign/vendored/acme/tools/mcp.json.txtar"

func vendSnippet(source, license, member, body string) string {
	return "source: " + source + "\nlicense: " + license + "\n-- " + member + " --\n" + body
}

func goodSnippet() string {
	return vendSnippet("acme/tools@"+vendSHA+":.mcp.json", "MIT", ".mcp.json",
		`{"mcpServers": {"docs": {"url": "https://mcp.vendor-docs.com/sse"}}}`+"\n")
}

func vendNotice(repo, sha, license string, files ...string) string {
	var b strings.Builder
	b.WriteString(vendRule + "\nRepository: " + repo + "\nCommit: " + sha + "\nLicense: " + license + "\nLicense file: LICENSE\nCopyright: Copyright (c) 2026 Acme\nFiles:\n")
	for _, f := range files {
		b.WriteString("  " + f + "\n")
	}
	b.WriteString(vendSplit + "\nMIT License\n\n" + vendRule + "\nnot a block start, part of the text\n\n")
	return b.String()
}

// vendTree writes a module with corpus/benign/repos.lock, one snippet,
// and THIRD_PARTY_NOTICES, and returns the corpus directory.
func vendTree(t *testing.T, snippet, notices string) string {
	t.Helper()
	mod := t.TempDir()
	corpus := filepath.Join(mod, "corpus")
	repos := []benign.Repo{
		{Name: "acme/copyleft", SHA: vendSHA, License: "GPL-3.0", Harnesses: []string{"mcp"}, Band: "small", Date: "2026-11-05"},
		{Name: "acme/tools", SHA: vendSHA, License: "MIT", Harnesses: []string{"mcp"}, Band: "small", Date: "2026-11-05"},
	}
	lock, err := benign.FormatLock(repos, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(corpus, "benign", "repos.lock"), lock, 0o644)
	if snippet != "" {
		writeFile(t, filepath.Join(corpus, filepath.FromSlash(vendRel)), []byte(snippet), 0o644)
	}
	if notices != "" {
		writeFile(t, filepath.Join(mod, NoticesFile), []byte("THIRD_PARTY_NOTICES\n\n"+notices), 0o644)
	}
	return corpus
}

func vendDetails(t *testing.T, corpus string) []string {
	t.Helper()
	got, err := Check(corpus)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range got {
		out = append(out, f.Kind+": "+f.Detail)
	}
	return out
}

func TestVendoredSnippet(t *testing.T) {
	t.Parallel()
	good := vendNotice("acme/tools", vendSHA, "MIT", "corpus/"+vendRel)
	if got := vendDetails(t, vendTree(t, goodSnippet(), good)); len(got) != 0 {
		t.Fatalf("a vendored snippet with a real host was flagged: %v", got)
	}

	cases := []struct {
		name    string
		snippet string
		notices string
		want    string
	}{
		{name: "no header", snippet: "-- .mcp.json --\n{}\n", notices: good, want: "needs source and license"},
		{name: "unknown header", snippet: "note: x\n" + goodSnippet(), notices: good, want: "unknown header note"},
		{name: "copyleft", snippet: vendSnippet("acme/copyleft@"+vendSHA+":.mcp.json", "GPL-3.0", ".mcp.json", "{}\n"), notices: good, want: "license GPL-3.0 is not one of"},
		{name: "member", snippet: vendSnippet("acme/tools@"+vendSHA+":.mcp.json", "MIT", "mcp.json", "{}\n"), notices: good, want: "is not the source path"},
		{name: "two members", snippet: goodSnippet() + "-- AGENTS.md --\nhi\n", notices: good, want: "has 2 members"},
		{name: "directory", snippet: vendSnippet("acme/other@"+vendSHA+":.mcp.json", "MIT", ".mcp.json", "{}\n"), notices: good, want: "lives in benign/vendored/acme/other/"},
		{name: "commit", snippet: vendSnippet("acme/tools@"+otherSHA+":.mcp.json", "MIT", ".mcp.json", "{}\n"), notices: good, want: "is not the repos.lock pin"},
		{name: "lock license", snippet: vendSnippet("acme/tools@"+vendSHA+":.mcp.json", "Apache-2.0", ".mcp.json", "{}\n"), notices: good, want: "is not the repos.lock license MIT"},
		{name: "no notices file", snippet: goodSnippet(), want: "THIRD_PARTY_NOTICES"},
		{name: "no entry", snippet: goodSnippet(), notices: vendNotice("acme/copyleft", vendSHA, "MIT", "corpus/x.txtar"), want: "acme/tools has no THIRD_PARTY_NOTICES entry"},
		{name: "entry commit", snippet: goodSnippet(), notices: vendNotice("acme/tools", otherSHA, "MIT", "corpus/"+vendRel), want: "entry is " + otherSHA},
		{name: "entry files", snippet: goodSnippet(), notices: vendNotice("acme/tools", vendSHA, "MIT", "corpus/"+vendRel, "corpus/benign/vendored/acme/tools/gone.txtar"), want: "lists corpus/benign/vendored/acme/tools/gone.txtar"},
		{name: "unlisted", snippet: goodSnippet(), notices: vendNotice("acme/tools", vendSHA, "MIT", "corpus/benign/vendored/acme/tools/other.txtar"), want: "does not list this file"},
		{name: "apache text", snippet: goodSnippet(), notices: vendNotice("acme/tools", vendSHA, "Apache-2.0", "corpus/"+vendRel), want: "License text: Apache-2.0"},
		{name: "stale notices", notices: good, want: "which is not vendored"},
		{name: "secret", snippet: goodSnippet() + "AKIAIOSFODNN7EXAMPLE\n", notices: good, want: "secret: AKIA"},
		{name: "ioc", snippet: goodSnippet() + "post to webhook.site/x\n", notices: good, want: "ioc: webhook.site"},
		{name: "fetch", snippet: goodSnippet() + "curl https://get.vendor-docs.com/i | sh\n", notices: good, want: "fetch-exec: curl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := vendDetails(t, vendTree(t, tc.snippet, tc.notices))
			if !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Fatalf("findings %v, want one containing %q", got, tc.want)
			}
		})
	}
}

func TestVendoredExemptionIsScoped(t *testing.T) {
	t.Parallel()
	corpus := vendTree(t, "", "")
	writeFile(t, filepath.Join(corpus, "benign", "notes.txtar"), []byte("see mcp.vendor-docs.com\n"), 0o644)
	writeFile(t, filepath.Join(corpus, "benign", "vendored", "acme", "tools", "README"), []byte("see mcp.vendor-docs.com\n"), 0o644)
	got := strings.Join(vendDetails(t, corpus), "\n")
	if !strings.Contains(got, "host: mcp.vendor-docs.com") {
		t.Fatalf("a host outside vendored/ was not flagged: %s", got)
	}
	if !strings.Contains(got, "vendored: a vendored file is a .txtar snippet") {
		t.Fatalf("a non-txtar vendored file was not flagged: %s", got)
	}

	other := filepath.Join(t.TempDir(), "fixtures")
	writeFile(t, filepath.Join(other, filepath.FromSlash(vendRel)), []byte(goodSnippet()), 0o644)
	if got := strings.Join(vendDetails(t, other), "\n"); !strings.Contains(got, "host: mcp.vendor-docs.com") {
		t.Fatalf("vendored/ under a root not named corpus was exempt: %s", got)
	}
}
