package benignscan

import (
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

func TestBuildMetrics(t *testing.T) {
	results := []Result{
		{Repo: "acme/one", Findings: []Finding{
			{Rule: "TC-CFG-002", Severity: "high", Fingerprint: "tcf_0000000000000001"},
			{Rule: "TC-CFG-010", Severity: "medium", Fingerprint: "tcf_0000000000000002"},
		}},
		{Repo: "acme/two", Findings: []Finding{
			{Rule: "TC-CFG-002", Severity: "critical", Fingerprint: "tcf_0000000000000003", Path: ".vscode/tasks.json"},
			{Rule: "TC-CFG-010", Severity: "medium", Fingerprint: "tcf_0000000000000004"},
		}},
		{Repo: "acme/three", Findings: []Finding{}},
		{Repo: "acme/gone", Err: "fetch: boom"},
	}
	triage := []benign.Triage{
		{Repo: "Acme/One", Fingerprint: "tcf_0000000000000001", RuleID: "TC-CFG-002", Verdict: "FP"},
		{Repo: "acme/one", Fingerprint: "tcf_0000000000000002", RuleID: "TC-CFG-010", Verdict: "TP"},
		// Same fingerprint, other rule: does not triage the finding.
		{Repo: "acme/two", Fingerprint: "tcf_0000000000000003", RuleID: "TC-CFG-001", Verdict: "FP"},
		{Repo: "acme/two", Fingerprint: "tcf_0000000000000004", RuleID: "TC-CFG-010", Verdict: "FP"},
	}
	r := Build(results, triage)
	if r.Repos != 4 || r.Scanned != 3 || r.Findings != 4 {
		t.Fatalf("counts: %+v", r)
	}
	if len(r.Failed) != 1 || r.Failed[0].Repo != "acme/gone" {
		t.Fatalf("failed: %+v", r.Failed)
	}
	if r.FPPerRepo["acme/one"] != 1 || r.FPPerRepo["acme/two"] != 1 || r.FPPerRepo["acme/three"] != 0 {
		t.Fatalf("fp per repo: %v", r.FPPerRepo)
	}
	if _, ok := r.FPPerRepo["acme/gone"]; ok {
		t.Fatal("a failed repository has an FP count")
	}
	if got := r.MeanFPPerRepo; got < 0.66 || got > 0.67 {
		t.Fatalf("mean fp per repo %v", got)
	}
	if got := r.FPRateByRule["TC-CFG-002"]; got.Findings != 2 || got.FP != 1 || got.Rate != 0.5 {
		t.Fatalf("TC-CFG-002 rate %+v", got)
	}
	if got := r.FPRateByRule["TC-CFG-010"]; got.Findings != 2 || got.FP != 1 || got.Rate != 0.5 {
		t.Fatalf("TC-CFG-010 rate %+v", got)
	}
	if got := r.HighRepoShare; got < 0.66 || got > 0.67 {
		t.Fatalf("high repo share %v", got)
	}
	if len(r.NewUntriagedHigh) != 1 {
		t.Fatalf("untriaged: %+v", r.NewUntriagedHigh)
	}
	u := r.NewUntriagedHigh[0]
	if u.Repo != "acme/two" || u.Fingerprint != "tcf_0000000000000003" || u.Severity != "critical" || u.Path != ".vscode/tasks.json" {
		t.Fatalf("untriaged: %+v", u)
	}
	if ExitCode(r, 0.5) != 1 {
		t.Fatal("an untriaged high finding did not fail the run")
	}
}

func TestExitCode(t *testing.T) {
	clean := Build([]Result{{Repo: "a/b"}, {Repo: "a/c"}}, nil)
	if ExitCode(clean, 0.05) != 0 {
		t.Fatal("clean run failed")
	}
	triaged := Build([]Result{{Repo: "a/b", Findings: []Finding{{Rule: "TC-CFG-002", Severity: "high", Fingerprint: "tcf_00000000000000aa"}}}},
		[]benign.Triage{{Repo: "a/b", Fingerprint: "tcf_00000000000000aa", RuleID: "TC-CFG-002", Verdict: "accepted-risk"}})
	if ExitCode(triaged, 0.05) != 0 || len(triaged.NewUntriagedHigh) != 0 {
		t.Fatal("a triaged high finding failed the run")
	}
	medium := Build([]Result{{Repo: "a/b", Findings: []Finding{{Rule: "TC-CFG-010", Severity: "medium", Fingerprint: "tcf_00000000000000bb"}}}}, nil)
	if ExitCode(medium, 0.05) != 0 {
		t.Fatal("an untriaged medium finding failed the run")
	}
	someFailed := Build([]Result{{Repo: "a/b"}, {Repo: "a/c", Err: "x"}}, nil)
	if ExitCode(someFailed, 0.5) != 0 || ExitCode(someFailed, 0.25) != 1 {
		t.Fatal("failure share is not gated by max-failed")
	}
	if ExitCode(Build(nil, nil), 1) != 1 {
		t.Fatal("an empty run passed")
	}
}

func TestParseScan(t *testing.T) {
	out := strings.Join([]string{
		`{"schema":"tripcord.finding/v1","rule":"TC-CFG-002","title":"t","severity":"high","fingerprint":"tcf_0f5206ed40597289","location":{"harness":"vscode","scope":"repo","path":".vscode/tasks.json"}}`,
		`{"schema":"tripcord.diagnostic/v1","incomplete":true,"level":"error","path":".mcp.json","message":"invalid JSON"}`,
		``,
	}, "\n")
	findings, diags, err := ParseScan(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if diags != 1 || len(findings) != 1 {
		t.Fatalf("findings %v diagnostics %d", findings, diags)
	}
	want := Finding{Rule: "TC-CFG-002", Severity: "high", Fingerprint: "tcf_0f5206ed40597289", Path: ".vscode/tasks.json"}
	if findings[0] != want {
		t.Fatalf("got %+v", findings[0])
	}
	for _, bad := range []string{
		`{"schema":"tripcord.summary/v9"}`,
		`{"schema":"tripcord.finding/v1","rule":"TC-CFG-002"}`,
		`not json`,
	} {
		if _, _, err := ParseScan(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
