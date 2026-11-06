package advisory

import (
	"os"
	"strings"
	"testing"
)

func TestSeedList(t *testing.T) {
	t.Parallel()
	db := loadSeed(t)
	if db.Count() != 16 || db.LatestReview() != "2026-11-06" {
		t.Fatalf("count %d reviewed %s", db.Count(), db.LatestReview())
	}
	hits, err := db.Match([]PackageRef{{
		Ecosystem: EcoPyPI,
		Name:      "prefab-ui",
		Kind:      KindExact,
		Version:   "0.20.2",
		Spec:      "prefab-ui==0.20.2",
	}})
	if err != nil || len(hits) != 1 || hits[0].ID != "TCA-2026-0001" || hits[0].Severity != "critical" {
		t.Fatalf("prefab hits = %+v %v", hits, err)
	}
	if hits[0].PURL != "pkg:pypi/prefab-ui@0.20.2" {
		t.Fatalf("purl %s", hits[0].PURL)
	}
	if Excerpt(hits) != "pkg:pypi/prefab-ui@0.20.2 TCA-2026-0001" {
		t.Fatalf("excerpt %q", Excerpt(hits))
	}
	if got := Title("ui", hits); got != "MCP server ui pins prefab-ui@0.20.2: CVE-2026-120338, GHSA-3g72-rrqc-f76c (fixed in 0.21.0)" {
		t.Fatalf("title %q", got)
	}

	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoPyPI, Name: "mcp-server-git", Kind: KindExact, Version: "2025.9.0",
	}})
	if err != nil || len(hits) != 4 {
		t.Fatalf("git server hits = %d %v", len(hits), err)
	}
	if Excerpt(hits) != "pkg:pypi/mcp-server-git@2025.9.0 TCA-2026-0005 TCA-2026-0006 TCA-2026-0007 TCA-2026-0008" {
		t.Fatalf("excerpt %q", Excerpt(hits))
	}
	title := Title("git", hits)
	if !strings.Contains(title, "(fixed in 2026.1.14)") || !strings.Contains(title, "CVE-2025-68143") {
		t.Fatalf("title %q", title)
	}

	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoPyPI, Name: "mcp-server-git", Kind: KindExact, Version: "2025.12.17",
	}})
	if err != nil || len(hits) != 3 {
		t.Fatalf("2025.12.17 hits = %+v %v", hits, err)
	}

	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoGit,
		Name:      "github.com/alishahid74/kali-gpt",
		Repo:      "https://github.com/alishahid74/kali-gpt",
		Kind:      KindUnpinned,
		Spec:      "git+https://github.com/alishahid74/kali-gpt",
	}})
	if err != nil || len(hits) != 1 || hits[0].ID != "TCA-2026-0002" || hits[0].Fixed != "" {
		t.Fatalf("kali git = %+v %v", hits, err)
	}
	if !strings.Contains(Title("kali", hits), "has no fixed version") {
		t.Fatalf("title %q", Title("kali", hits))
	}
	if !strings.HasPrefix(hits[0].PURL, "pkg:generic/github.com/alishahid74/kali-gpt") || strings.Contains(hits[0].PURL, "@") {
		t.Fatalf("unpinned git purl %s", hits[0].PURL)
	}

	for _, rev := range []string{"v3.0.0", "4df42a5", "a608c74e99910232dd208fee99de860458672b82"} {
		hits, err = db.Match([]PackageRef{{
			Ecosystem: EcoGit,
			Name:      "github.com/alishahid74/kali-gpt",
			Repo:      "https://github.com/alishahid74/kali-gpt",
			Kind:      KindExact,
			Version:   rev,
		}})
		if err != nil || len(hits) != 1 || hits[0].PURL != "pkg:generic/github.com/alishahid74/kali-gpt@"+rev {
			t.Fatalf("kali git @%s = %+v %v", rev, hits, err)
		}
	}

	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoModule, Name: "kali_gpt.tools.mcp_server", Kind: KindUnpinned,
	}})
	if err != nil || len(hits) != 1 || hits[0].ID != "TCA-2026-0002" {
		t.Fatalf("module = %+v %v", hits, err)
	}
	abs := "/home/someone/src/kali-gpt/kali_gpt/tools/mcp_server.py"
	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoModule, Name: abs, Spec: abs, Kind: KindUnpinned,
	}})
	if err != nil || len(hits) != 1 {
		t.Fatalf("path = %+v %v", hits, err)
	}
	if h := hits[0]; h.Name != "kali_gpt/tools/mcp_server.py" || h.Spec != h.Name || h.PURL != "pkg:generic/kali_gpt/tools/mcp_server.py" {
		t.Fatalf("path hit carries the argv path: %+v", h)
	}
	if text := Title("kali", hits) + Excerpt(hits); strings.Contains(text, "/home/") {
		t.Fatalf("local path in title or excerpt: %s", text)
	}

	// Unpinned specs do not match an advisory that has a fix.
	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoNPM, Name: "figma-developer-mcp", Kind: KindUnpinned,
	}})
	if err != nil || len(hits) != 0 {
		t.Fatalf("unpinned figma = %+v %v", hits, err)
	}
	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoNPM, Name: "figma-developer-mcp", Kind: KindExact, Version: "0.6.3",
	}})
	if err != nil || len(hits) != 0 {
		t.Fatalf("fixed figma = %+v %v", hits, err)
	}
	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoNPM, Name: "figma-developer-mcp", Kind: KindRange, Version: "~0.5.0",
	}})
	if err != nil || len(hits) != 1 {
		t.Fatalf("tilde = %+v %v", hits, err)
	}
	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoNPM, Name: "figma-developer-mcp", Kind: KindRange, Version: "^0.6.0",
	}})
	if err != nil || len(hits) != 0 {
		t.Fatalf("caret = %+v %v", hits, err)
	}
	if _, err := db.Match([]PackageRef{{
		Ecosystem: EcoNPM, Name: "figma-developer-mcp", Kind: KindDigest,
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestMCPHubBounds(t *testing.T) {
	t.Parallel()
	db := loadSeed(t)
	// 0.9.10 is the first release that contains 66b6053, which adds the
	// unguarded passthroughHeaders loop. 0.9.9 is the release before it.
	// 1.1.8 is the fix and 1.2.0 is a later release.
	affected := []string{"0.9.10", "0.12.17", "1.0.0", "1.0.46", "1.1.7"}
	clear := []string{"0.9.9", "1.1.8", "1.2.0"}
	for _, version := range affected {
		hits, err := db.Match([]PackageRef{{
			Ecosystem: EcoNPM, Name: "@samanhappy/mcphub", Kind: KindExact, Version: version,
		}})
		if err != nil || len(hits) != 1 || hits[0].ID != "TCA-2026-0010" {
			t.Fatalf("%s hits = %+v %v", version, hits, err)
		}
	}
	for _, version := range clear {
		hits, err := db.Match([]PackageRef{{
			Ecosystem: EcoNPM, Name: "@samanhappy/mcphub", Kind: KindExact, Version: version,
		}})
		if err != nil || len(hits) != 0 {
			t.Fatalf("%s hits = %+v %v", version, hits, err)
		}
	}
}

func TestTSParticlesBounds(t *testing.T) {
	t.Parallel()
	db := loadSeed(t)
	// 4.3.0 is the last release before the 4.3.1 fixes. 4.3.1 still shares
	// one HTTP transport; 4.3.2 gives each session its own.
	before := []string{"4.2.1", "4.3.0"}
	for _, version := range before {
		hits, err := db.Match([]PackageRef{{
			Ecosystem: EcoNPM, Name: "@tsparticles/mcp-server", Kind: KindExact, Version: version,
		}})
		if err != nil || len(hits) != 3 {
			t.Fatalf("%s hits = %+v %v", version, hits, err)
		}
	}
	hits, err := db.Match([]PackageRef{{
		Ecosystem: EcoNPM, Name: "@tsparticles/mcp-server", Kind: KindExact, Version: "4.3.1",
	}})
	if err != nil || len(hits) != 1 || hits[0].ID != "TCA-2026-0015" {
		t.Fatalf("4.3.1 hits = %+v %v", hits, err)
	}
	for _, version := range []string{"4.3.2", "4.5.1"} {
		hits, err = db.Match([]PackageRef{{
			Ecosystem: EcoNPM, Name: "@tsparticles/mcp-server", Kind: KindExact, Version: version,
		}})
		if err != nil || len(hits) != 0 {
			t.Fatalf("%s hits = %+v %v", version, hits, err)
		}
	}
	hits, err = db.Match([]PackageRef{{
		Ecosystem: EcoNPM, Name: "@tsparticles/mcp-server", Kind: KindUnpinned,
	}})
	if err != nil || len(hits) != 0 {
		t.Fatalf("unpinned hits = %+v %v", hits, err)
	}
}

func TestOpenEncodedCommandBounds(t *testing.T) {
	t.Parallel()
	db := loadSeed(t)
	// Each package is affected from its introduced version up to, but
	// not including, the fixed version. An unpinned spec does not match.
	cases := []struct {
		name     string
		affected []string
		clear    []string
	}{
		{
			name:     "open",
			affected: []string{"7.2.0", "8.0.0", "10.2.1"},
			clear:    []string{"7.1.9", "11.0.0", "11.1.0"},
		},
		{
			name:     "@modelcontextprotocol/inspector",
			affected: []string{"2.0.0", "2.11.0"},
			clear:    []string{"1.9.9", "2.12.0", "2.13.0"},
		},
		{
			name:     "opencode-ai",
			affected: []string{"1.0.137", "1.18.32"},
			clear:    []string{"1.0.136", "1.18.33", "1.19.0"},
		},
	}
	for _, tc := range cases {
		for _, version := range tc.affected {
			hits, err := db.Match([]PackageRef{{
				Ecosystem: EcoNPM, Name: tc.name, Kind: KindExact, Version: version,
			}})
			if err != nil || len(hits) != 1 || hits[0].ID != "TCA-2026-0016" || hits[0].Severity != "high" {
				t.Fatalf("%s@%s hits = %+v %v", tc.name, version, hits, err)
			}
		}
		for _, version := range tc.clear {
			hits, err := db.Match([]PackageRef{{
				Ecosystem: EcoNPM, Name: tc.name, Kind: KindExact, Version: version,
			}})
			if err != nil || len(hits) != 0 {
				t.Fatalf("%s@%s hits = %+v %v", tc.name, version, hits, err)
			}
		}
		hits, err := db.Match([]PackageRef{{
			Ecosystem: EcoNPM, Name: tc.name, Kind: KindUnpinned,
		}})
		if err != nil || len(hits) != 0 {
			t.Fatalf("unpinned %s hits = %+v %v", tc.name, hits, err)
		}
	}
}

func TestAdvisoryRejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"inverted":      `{"format":1,"advisories":[{"id":"TCA-2026-0099","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"npm","name":"a","ranges":[{"introduced":"2.0.0","fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`,
		"http ref":      `{"format":1,"advisories":[{"id":"TCA-2026-0099","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"npm","name":"a","ranges":[{"fixed":"1.0.0"}]}],"refs":["http://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`,
		"duplicate":     `{"format":1,"advisories":[{"id":"TCA-2026-0099","aliases":[],"summary":"x","severity":"low","affected":[{"ecosystem":"npm","name":"a","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"},{"id":"TCA-2026-0099","aliases":[],"summary":"y","severity":"low","affected":[{"ecosystem":"npm","name":"b","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/b"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`,
		"module fixed":  `{"format":1,"advisories":[{"id":"TCA-2026-0099","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"module","signatures":[{"module":"m"}],"ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`,
		"git fixed":     `{"format":1,"advisories":[{"id":"TCA-2026-0099","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"git","repo":"https://github.com/example/pkg","ranges":[{"fixed":"1.0.0"}],"affected_commits":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`,
		"unknown field": `{"format":1,"advisories":[{"id":"TCA-2026-0099","aliases":[],"summary":"x","severity":"high","note":"no","affected":[{"ecosystem":"npm","name":"a","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`,
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEvolution(t *testing.T) {
	t.Parallel()
	old, err := Parse([]byte(`{"format":1,"advisories":[{"id":"TCA-2026-0001","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"npm","name":"a","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	renumbered, err := Parse([]byte(`{"format":1,"advisories":[{"id":"TCA-2026-0002","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"npm","name":"a","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckEvolution(old, renumbered); err == nil {
		t.Fatal("renumber accepted")
	}
	withdrawn, err := Parse([]byte(`{"format":1,"advisories":[{"id":"TCA-2026-0001","aliases":[],"summary":"corrected","severity":"low","affected":[{"ecosystem":"npm","name":"a","ranges":[{"fixed":"1.2.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-03","withdrawn":"2026-11-03"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckEvolution(old, withdrawn); err != nil {
		t.Fatal(err)
	}
	if err := CheckEvolution(withdrawn, old); err == nil {
		t.Fatal("cleared withdrawn")
	}
}

func loadSeed(t *testing.T) *DB {
	t.Helper()
	raw, err := os.ReadFile("../../rules/ADVISORIES.json")
	if err != nil {
		t.Fatal(err)
	}
	db, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
