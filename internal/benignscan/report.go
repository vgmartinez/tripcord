// Package benignscan scans the pinned benign repositories with tripcord
// and reports false-positive metrics against triage.tsv.
package benignscan

import (
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

// Finding is the part of a tripcord finding the report reads.
type Finding struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Fingerprint string `json:"fingerprint"`
	Path        string `json:"path,omitempty"`
}

// Result is one repository's scan. Err is set when the repository could
// not be fetched or scanned; its findings are then not counted.
type Result struct {
	Repo        string    `json:"repo"`
	SHA         string    `json:"sha"`
	Findings    []Finding `json:"findings"`
	Diagnostics int       `json:"diagnostics"`
	Err         string    `json:"error,omitempty"`
}

// Untriaged is a high or critical finding with no triage row.
type Untriaged struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Repo        string `json:"repo"`
	Path        string `json:"path,omitempty"`
}

// RuleRate is the false-positive rate of one rule.
type RuleRate struct {
	Findings int     `json:"findings"`
	FP       int     `json:"fp"`
	Rate     float64 `json:"rate"`
}

// Failure is a repository that was not scanned.
type Failure struct {
	Repo  string `json:"repo"`
	Error string `json:"error"`
}

// Report is the JSON written by scripts/benign-scan.
type Report struct {
	Schema           string              `json:"schema"`
	Repos            int                 `json:"repos"`
	Scanned          int                 `json:"scanned"`
	Failed           []Failure           `json:"failed"`
	Findings         int                 `json:"findings"`
	FPPerRepo        map[string]int      `json:"fp_per_repo"`
	MeanFPPerRepo    float64             `json:"mean_fp_per_repo"`
	FPRateByRule     map[string]RuleRate `json:"fp_rate_by_rule"`
	HighRepoShare    float64             `json:"high_repo_share"`
	NewUntriagedHigh []Untriaged         `json:"new_untriaged_high"`
}

// ReportSchema names the report format.
const ReportSchema = "tripcord.benign-report/v1"

// ExitCode is 1 when a high or critical finding is untriaged, or when
// more than maxFailed of the repositories could not be scanned, and 0
// otherwise. An empty lock is a failure, not a clean run.
func ExitCode(r Report, maxFailed float64) int {
	if len(r.NewUntriagedHigh) > 0 || r.Scanned == 0 {
		return 1
	}
	if float64(len(r.Failed)) > maxFailed*float64(r.Repos) {
		return 1
	}
	return 0
}

// High reports whether severity counts as a high finding.
func High(severity string) bool {
	return severity == "high" || severity == "critical"
}

// Build computes the report. A finding matches a triage row when the
// repository, the fingerprint, and the rule are all equal. FP counts
// rows with verdict FP; TP and accepted-risk rows are triaged but are
// not false positives.
func Build(results []Result, triage []benign.Triage) Report {
	type key struct{ repo, fp string }
	rows := map[key]benign.Triage{}
	for _, t := range triage {
		rows[key{strings.ToLower(t.Repo), t.Fingerprint}] = t
	}
	r := Report{
		Schema:           ReportSchema,
		Repos:            len(results),
		Failed:           []Failure{},
		FPPerRepo:        map[string]int{},
		FPRateByRule:     map[string]RuleRate{},
		NewUntriagedHigh: []Untriaged{},
	}
	high := 0
	fps := 0
	for _, res := range results {
		if res.Err != "" {
			r.Failed = append(r.Failed, Failure{Repo: res.Repo, Error: res.Err})
			continue
		}
		r.Scanned++
		hasHigh := false
		repoFP := 0
		for _, f := range res.Findings {
			r.Findings++
			rate := r.FPRateByRule[f.Rule]
			rate.Findings++
			row, ok := rows[key{strings.ToLower(res.Repo), f.Fingerprint}]
			ok = ok && row.RuleID == f.Rule
			if ok && row.Verdict == "FP" {
				rate.FP++
				repoFP++
			}
			r.FPRateByRule[f.Rule] = rate
			if !High(f.Severity) {
				continue
			}
			hasHigh = true
			if !ok {
				r.NewUntriagedHigh = append(r.NewUntriagedHigh, Untriaged{
					Fingerprint: f.Fingerprint, Rule: f.Rule, Severity: f.Severity, Repo: res.Repo, Path: f.Path,
				})
			}
		}
		r.FPPerRepo[res.Repo] = repoFP
		fps += repoFP
		if hasHigh {
			high++
		}
	}
	for rule, rate := range r.FPRateByRule {
		if rate.Findings > 0 {
			rate.Rate = float64(rate.FP) / float64(rate.Findings)
		}
		r.FPRateByRule[rule] = rate
	}
	if r.Scanned > 0 {
		r.MeanFPPerRepo = float64(fps) / float64(r.Scanned)
		r.HighRepoShare = float64(high) / float64(r.Scanned)
	}
	slices.SortFunc(r.NewUntriagedHigh, func(a, b Untriaged) int {
		if c := strings.Compare(a.Repo, b.Repo); c != 0 {
			return c
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
	slices.SortFunc(r.Failed, func(a, b Failure) int { return strings.Compare(a.Repo, b.Repo) })
	return r
}
