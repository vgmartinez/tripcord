package benign

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/model"
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
	if !bytes.HasPrefix(raw, []byte(Header(parsedPreview(repos), when))) {
		t.Fatal("formatted lock does not start with Header")
	}
	if !strings.Contains(text, "size band") || !strings.Contains(text, "Harness counts:") {
		t.Fatalf("header missing size and harness counts:\n%s", text)
	}
	if !strings.Contains(text, "a/a") || strings.Index(text, "a/a") > strings.Index(text, "b/b") {
		t.Fatalf("rows are not sorted:\n%s", text)
	}
	parsed, err := ParseLock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed[0].License != "NOASSERTION" || parsed[0].Band != "large" || parsed[1].Band != "small" || parsed[1].Harnesses[0] != "agents" || parsed[1].Harnesses[1] != "cursor" {
		t.Fatalf("parsed %#v", parsed)
	}
	rules := map[string]bool{"TC-CFG-001": true}
	triage := []Triage{{
		Fingerprint: "tcf_c761c03b24e7b179", RuleID: "TC-CFG-001", Repo: "a/a", Verdict: VerdictFP, Reason: "local task only echoes", Date: "2026-11-04",
	}}
	if err := Validate(parsed, triage, rules); err != nil {
		t.Fatal(err)
	}
	otherRepo := triage[0]
	otherRepo.Repo = "b/b"
	if err := Validate(parsed, []Triage{triage[0], otherRepo}, rules); err != nil {
		t.Fatalf("same fingerprint in two repositories: %v", err)
	}
	dup := append([]Triage{triage[0]}, triage[0])
	err = Validate(parsed, dup, rules)
	if err == nil || !strings.Contains(err.Error(), "duplicate fingerprint tcf_c761c03b24e7b179 in repository a/a") {
		t.Fatalf("duplicate fingerprint: %v", err)
	}
	missing := []Triage{{Fingerprint: "tcf_ae4bd8fa3ea4035c", RuleID: "TC-CFG-001", Repo: "z/z", Verdict: VerdictTP, Reason: "reviewed as a local task", Date: "2026-11-04"}}
	if err := Validate(parsed, missing, rules); err == nil || !strings.Contains(err.Error(), "not in repos.lock") {
		t.Fatalf("missing repo: %v", err)
	}
	badVerdict := []byte(TriageHeader + "tcf_c761c03b24e7b179\tTC-CFG-001\ta/a\tMAYBE\tlocal task only echoes\t2026-11-04\n")
	if _, err := ParseTriage(badVerdict); err == nil || !strings.Contains(err.Error(), "bad verdict") {
		t.Fatalf("verdict: %v", err)
	}
	if _, err := ParseLock([]byte(Header(nil, when) + "a/a\tshort\tMIT\tagents\tsmall\t2026-11-04\n")); err == nil {
		t.Fatal("short SHA was accepted")
	}
	empty, err := ParseTriage([]byte(TriageHeader))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty triage: %v %#v", err, empty)
	}
	if err := Validate(parsed, nil, nil); err != nil {
		t.Fatal(err)
	}
	later, err := FormatLock(repos, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil || !bytes.Contains(later, []byte("# Generated 2026-11-05.\n")) {
		t.Fatalf("generation date: %v", err)
	}
}

func parsedPreview(repos []Repo) []Repo {
	out := slices.Clone(repos)
	for i := range out {
		if out[i].Band == "" {
			out[i].Band = SizeBand(out[i].SizeKB)
		}
		if out[i].License == "" {
			out[i].License = "NOASSERTION"
		}
	}
	return out
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
	if !bytes.HasPrefix(triageRaw, []byte(TriageHeader)) {
		t.Fatal("triage.tsv header is not TriageHeader")
	}
	repos, err := LoadLock(lockRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) < 132 {
		t.Fatalf("repos.lock has %d repositories, want at least 132", len(repos))
	}
	if bytes.HasPrefix(lockRaw, []byte(legacyLockHeader)) {
		if len(repos) != 132 {
			t.Fatalf("legacy lock has %d repositories, want 132", len(repos))
		}
	} else {
		when, err := headerDate(string(lockRaw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := FormatLock(repos, when)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, lockRaw) {
			t.Fatal("repos.lock is not the generated lock")
		}
		for _, r := range repos {
			if r.Band == "" {
				t.Fatalf("%s has no size band", r.Name)
			}
		}
	}
	triage, err := ParseTriage(triageRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(triage) != 102 {
		t.Fatalf("triage.tsv has %d rows, want 102", len(triage))
	}
	regRaw, err := os.ReadFile(filepath.Join(root, "rules", "REGISTRY"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ParseRegistry(regRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(repos, triage, rules); err != nil {
		t.Fatal(err)
	}
	fp, err := model.Fingerprint("TC-CFG-002", model.Location{Harness: model.SurfaceVSCode, Path: ".vscode/tasks.json"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprintRE.MatchString(fp) || fp != "tcf_"+fp[4:] || len(fp) != len("tcf_")+16 {
		t.Fatalf("scanner fingerprint %q is not tcf_ plus 16 hex digits", fp)
	}
}

func TestRejectedRows(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	head := Header(nil, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	row := func(name, license string) []byte {
		return []byte(head + name + "\t" + sha + "\t" + license + "\tagents\tsmall\t2026-11-04\n")
	}
	beacon := "see https://tracking.evil.com/beacon " + "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	payload100 := strings.Repeat("Q2hhcmFjdGVyc0FuZFBheWxvYWQ", 4)[:100]
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"comment URL", []byte(head + "# " + beacon + "\n"), "comment or blank line"},
		{"40KB line", []byte(head + strings.Repeat("x", 40*1024) + "\n"), "limit"},
		{"repo URL", row("zzzz/https://tracking.evil.com/beacon", "MIT"), "bad repository"},
		{"repo base64", row("zzzz/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "MIT"), "bad repository"},
		{"repo dotdot", row("zzzz/..", "MIT"), "bad repository"},
		{"repo 100-char payload", row("zzzz/"+payload100, "MIT"), "bad repository"},
		{"repo 39-char owner and 100-char payload", row(strings.Repeat("o", 39)+"/"+payload100, "MIT"), "bad repository"},
		{"repo 65 chars", row("zzzz/"+strings.Repeat("a", 65), "MIT"), "bad repository"},
		{"repo random under the cap", row("AbCdEfGhIjKlMnOpQr/StUvWxYz0123456789gHiJ", "MIT"), "bad repository"},
		{"repo random split by hyphens", row("AbCdEfGhIjKlMnOpQr/StUvWx-Yz0123-456789-gHiJ", "MIT"), "bad repository"},
		{"repo padded owner", row(strings.Repeat("z", 39)+"/"+strings.Repeat("Q", 24)+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn", "MIT"), "bad repository"},
		{"repo padded payload", row("zzzz/"+strings.Repeat("z", 28)+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "MIT"), "bad repository"},
		{"repo 24-char hex run", row("acme/0123456789abcdef01234567", "MIT"), "bad repository"},
		{"unknown license", row("zzzz/name", "NotALicense"), "unknown license"},
		{"license junk", row("zzzz/name", "MIT "+beacon), "unknown license"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseLock(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	triage := func(rule, fp, reason string) []byte {
		return []byte(TriageHeader + fp + "\t" + rule + "\tzzzz/name\tFP\t" + reason + "\t2026-11-04\n")
	}
	fp := "tcf_c761c03b24e7b179"
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"bad rule", triage("nope", fp, "local task only echoes"), "bad rule id"},
		{"bad fingerprint", triage("TC-CFG-001", "fp-1", "local task only echoes"), "bad fingerprint"},
		{"reason URL", triage("TC-CFG-001", fp, "see https://tracking.evil.com/beacon today"), "URL or host"},
		{"reason base64", triage("TC-CFG-001", fp, "token AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="), "high-entropy"},
		{"over-long reason", triage("TC-CFG-001", fp, strings.Repeat("x", maxReasonBytes+1)), "reason length"},
		{"anything goes", triage("TC-CFG-001", fp, "anything goes"), "reason length"},
		{"reason fullwidth dot", triage("TC-CFG-001", fp, "see evil\uff0ecom for the beacon"), "printable ASCII"},
		{"reason ideographic dot", triage("TC-CFG-001", fp, "see evil\u3002com for the beacon"), "printable ASCII"},
		{"reason Cyrillic letters", triage("TC-CFG-001", fp, "see \u0435vil.\u0441\u043em for the beacon"), "printable ASCII"},
		{"reason host top", triage("TC-CFG-001", fp, "the task posts to evil.top"), "URL or host"},
		{"reason host biz", triage("TC-CFG-001", fp, "the task posts to evil.biz"), "URL or host"},
		{"reason host ly", triage("TC-CFG-001", fp, "the task posts to evil.ly"), "URL or host"},
		{"reason host internal", triage("TC-CFG-001", fp, "the task posts to tracker.internal"), "URL or host"},
		{"reason decimal IP", triage("TC-CFG-001", fp, "the task posts to 3232235777"), "IP address"},
		{"reason hex IP", triage("TC-CFG-001", fp, "the task posts to 0xC0A80101"), "IP address"},
		{"reason octal IP", triage("TC-CFG-001", fp, "the task posts to 0300.0250.1.1"), "IP address"},
		{"reason bracketed IPv6", triage("TC-CFG-001", fp, "the task posts to [::ffff:c0a8:101]"), "IP address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseTriage(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	good, err := FormatLock([]Repo{{
		Name: "zzzz/name", SHA: sha, License: "MIT", Harnesses: []string{"agents"}, Band: "small", Date: "2026-11-04",
	}}, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	repos, err := ParseLock(good)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseTriage(triage("TC-CFG-999", fp, "local task only echoes"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(repos, rows, map[string]bool{"TC-CFG-001": true}); err == nil || !strings.Contains(err.Error(), "not in the registry") {
		t.Fatalf("fake rule: %v", err)
	}
	upper := strings.ToUpper(sha)
	if _, err := ParseLock([]byte(head + "zzzz/name\t" + upper + "\tMIT\tagents\tsmall\t2026-11-04\n")); err == nil || !strings.Contains(err.Error(), "bad SHA") {
		t.Fatalf("uppercase SHA: %v", err)
	}
	if _, err := ParseTriage([]byte(TriageHeader + fp + "\tTC-CFG-001\tzzzz/name\tFP\tlocal task only echoes\t2026-11-4\n")); err == nil || !strings.Contains(err.Error(), "bad date") {
		t.Fatalf("date: %v", err)
	}
}

func TestAcceptedNamesAndReasons(t *testing.T) {
	for _, name := range []string{
		"RinDevJunior/matterbridge-roborock-vacuum-plugin",
		"PrayerfulDrop/ESPHome-Guition-ESP32-S3-4848S040",
		"AzureAD/microsoft-authentication-library-common-for-objc",
		"acme/0123456789abcdef0123456",
	} {
		if !validRepoName(name) {
			t.Errorf("rejected %s", name)
		}
	}
	for _, reason := range []string{
		"local task only echoes package.json.",
		"runs 2 times, then reads SKILL.md and tasks.json",
		"hook prints the branch name, nothing else",
	} {
		if err := checkReason(reason); err != nil {
			t.Errorf("rejected %q: %v", reason, err)
		}
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
