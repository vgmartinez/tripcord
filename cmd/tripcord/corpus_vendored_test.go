package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/benignscan"
	"github.com/vgmartinez/tripcord/internal/corpus"
	"github.com/vgmartinez/tripcord/internal/corpus/benign"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/txtar"
)

// TestVendoredBenign scans every snippet under corpus/benign/vendored
// the way scripts/benign-scan scans a fetched repository, and fails on
// a high or critical finding with no triage.tsv row for that repository,
// fingerprint, and rule. The corpus lint checks each snippet's source,
// license, and THIRD_PARTY_NOTICES entry.
func TestVendoredBenign(t *testing.T) {
	clearPrContextEnv(t)
	t.Setenv(fpkey.EnvVar, "")
	t.Setenv("CI", "true")
	root := moduleRoot(t)
	paths, err := filepath.Glob(filepath.Join(root, "corpus", filepath.FromSlash(corpus.VendoredDir), "*", "*", "*.txtar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no snippets under corpus/benign/vendored")
	}
	raw, err := os.ReadFile(filepath.Join(root, "corpus", "benign", "triage.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	triage, err := benign.ParseTriage(raw)
	if err != nil {
		t.Fatal(err)
	}
	results := make([]benignscan.Result, 0, len(paths))
	for _, p := range paths {
		rel, _ := filepath.Rel(root, p)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		v, err := corpus.ParseVendored(data)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		findings, diags := scanVendored(t, v.Archive)
		if diags > 0 {
			t.Errorf("%s: %d diagnostics; a vendored snippet must load", rel, diags)
		}
		results = append(results, benignscan.Result{Repo: v.Repo, SHA: v.SHA, Findings: findings})
	}
	report := benignscan.Build(results, triage)
	for _, u := range report.NewUntriagedHigh {
		t.Errorf("%s %s %s %s in %s: untriaged; add a triage.tsv row", u.Repo, u.Rule, u.Severity, u.Fingerprint, u.Path)
	}
	t.Logf("%d snippets, %d findings", len(paths), report.Findings)
}

// scanVendored unpacks a snippet into a fresh directory whose parent is
// HOME and the Git ceiling, so no key file is read and no enclosing
// repository is found, and scans it at repository scope.
func scanVendored(t *testing.T, arc *txtar.Archive) ([]benignscan.Finding, int) {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "repo")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := txtar.Write(dir, arc); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", parent)
	t.Setenv("GIT_CEILING_DIRECTORIES", parent)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "-format", "json", "-scope", "repo", dir}, &stdout, &stderr)
	if code != int(exitcode.OK) && code != int(exitcode.Findings) {
		t.Fatalf("scan exit %d\nstderr: %s", code, strings.TrimSpace(stderr.String()))
	}
	findings, diags, err := benignscan.ParseScan(&stdout)
	if err != nil {
		t.Fatal(err)
	}
	return findings, diags
}
