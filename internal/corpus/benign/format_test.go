package benign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatAndValidate(t *testing.T) {
	when := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	repos := []Repo{
		{Name: "b/b", SHA: strings.Repeat("ab", 20), License: "MIT", Harnesses: []string{"cursor", "agents"}, Date: "2026-11-04", Stars: 80, SizeKB: 10},
		{Name: "a/a", SHA: strings.Repeat("cd", 20), License: "", Harnesses: []string{"claude"}, Date: "2026-11-04", Stars: 50, SizeKB: 20000},
	}
	raw, err := FormatLock(repos, when)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "GitHub code search") || !strings.Contains(text, "changes only through a pull request") {
		t.Fatalf("header missing generation note:\n%s", text)
	}
	if !strings.Contains(text, "a/a") || strings.Index(text, "a/a") > strings.Index(text, "b/b") {
		t.Fatalf("rows are not sorted:\n%s", text)
	}
	parsed, err := ParseLock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed[0].License != "NOASSERTION" || parsed[1].Harnesses[0] != "agents" || parsed[1].Harnesses[1] != "cursor" {
		t.Fatalf("parsed %#v", parsed)
	}
	triage := []Triage{{
		Fingerprint: "fp-1", RuleID: "TC-CFG-001", Repo: "a/a", Verdict: VerdictFP, Reason: "local task", Date: "2026-11-04",
	}}
	if err := Validate(parsed, triage); err != nil {
		t.Fatal(err)
	}
	dup := append(triage, triage[0])
	if err := Validate(parsed, dup); err == nil || !strings.Contains(err.Error(), "duplicate fingerprint") {
		t.Fatalf("duplicate fingerprint: %v", err)
	}
	missing := []Triage{{Fingerprint: "fp-2", RuleID: "TC-CFG-001", Repo: "z/z", Verdict: VerdictTP, Reason: "x", Date: "2026-11-04"}}
	if err := Validate(parsed, missing); err == nil || !strings.Contains(err.Error(), "not in repos.lock") {
		t.Fatalf("missing repo: %v", err)
	}
	badVerdict := []byte("# comment\nfp\tTC-CFG-001\ta/a\tMAYBE\treason\t2026-11-04\n")
	if _, err := ParseTriage(badVerdict); err == nil || !strings.Contains(err.Error(), "bad verdict") {
		t.Fatalf("verdict: %v", err)
	}
	if _, err := ParseLock([]byte("a/a\tshort\tMIT\tagents\t2026-11-04\n")); err == nil {
		t.Fatal("short SHA was accepted")
	}
	empty, err := ParseTriage([]byte("# no rows yet\n\n"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty triage: %v %#v", err, empty)
	}
	if err := Validate(parsed, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSelectStratifies(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	repos := []Repo{
		{Name: "a/low", SHA: sha, License: "MIT", Harnesses: []string{"agents"}, Date: "2026-11-04", Stars: 10, SizeKB: 10},
		{Name: "a/high", SHA: sha, License: "MIT", Harnesses: []string{"agents"}, Date: "2026-11-04", Stars: 90, SizeKB: 10},
		{Name: "c/big", SHA: sha, License: "MIT", Harnesses: []string{"claude"}, Date: "2026-11-04", Stars: 70, SizeKB: 20000},
	}
	got := Select(repos, 2)
	if len(got) != 2 || got[0].Name != "a/high" || got[1].Name != "c/big" {
		t.Fatalf("selected %#v", names(got))
	}
	if len(Select(repos, 10)) != 3 {
		t.Fatal("target above the candidate count dropped a repository")
	}
}

func TestCommittedLists(t *testing.T) {
	root := moduleRoot(t)
	lockPath := filepath.Join(root, "corpus", "benign", "repos.lock")
	triagePath := filepath.Join(root, "corpus", "benign", "triage.tsv")
	lockRaw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	triageRaw, err := os.ReadFile(triagePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"GitHub code search", "changes only through a pull request", "NOASSERTION"} {
		if !strings.Contains(string(lockRaw), phrase) {
			t.Errorf("repos.lock header missing %q", phrase)
		}
	}
	for _, phrase := range []string{"fingerprint", "rule id", "verdict", "TP", "FP", "accepted-risk", "changes only through a pull request"} {
		if !strings.Contains(string(triageRaw), phrase) {
			t.Errorf("triage.tsv header missing %q", phrase)
		}
	}
	repos, err := ParseLock(lockRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) == 0 {
		t.Fatal("repos.lock has no repositories")
	}
	triage, err := ParseTriage(triageRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(repos, triage); err != nil {
		t.Fatal(err)
	}
}

func names(repos []Repo) []string {
	out := make([]string, len(repos))
	for i, r := range repos {
		out[i] = r.Name
	}
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
