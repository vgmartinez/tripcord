// Command benign-scan shallow-fetches every pinned commit in
// corpus/benign/repos.lock, scans it with tripcord, and writes a JSON
// false-positive report. It exits 1 when a high or critical finding has
// no triage.tsv row, or when more than -max-failed of the repositories
// could not be scanned. Fetched trees are written to a temporary
// directory, never executed, and removed after each scan.
//
//	go run ./scripts/benign-scan -tripcord bin/tripcord [-out report.json] [-workers 8] [-timeout 40m]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vgmartinez/tripcord/internal/benignscan"
	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

func main() {
	lockPath := flag.String("lock", filepath.Join("corpus", "benign", "repos.lock"), "repos.lock path")
	triagePath := flag.String("triage", filepath.Join("corpus", "benign", "triage.tsv"), "triage.tsv path")
	bin := flag.String("tripcord", "", "tripcord binary to scan with")
	out := flag.String("out", "-", "report path or - for stdout")
	workers := flag.Int("workers", 8, "repositories fetched and scanned at once")
	timeout := flag.Duration("timeout", 40*time.Minute, "total time for the run")
	perRepo := flag.Duration("per-repo", 5*time.Minute, "time for one repository")
	maxFailed := flag.Float64("max-failed", 0.05, "largest share of repositories that may fail to scan")
	flag.Parse()
	if *bin == "" || *workers < 1 || *maxFailed < 0 || *maxFailed > 1 || flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: benign-scan -tripcord PATH [-lock FILE] [-triage FILE] [-out FILE] [-workers N] [-timeout D] [-per-repo D] [-max-failed F]")
		os.Exit(2)
	}
	code, err := run(*lockPath, *triagePath, *bin, *out, *workers, *timeout, *perRepo, *maxFailed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benign-scan:", err)
	}
	os.Exit(code)
}

func run(lockPath, triagePath, bin, out string, workers int, timeout, perRepo time.Duration, maxFailed float64) (int, error) {
	lockRaw, err := os.ReadFile(lockPath)
	if err != nil {
		return 2, err
	}
	repos, err := benign.ParseLock(lockRaw)
	if err != nil {
		return 2, err
	}
	triageRaw, err := os.ReadFile(triagePath)
	if err != nil {
		return 2, err
	}
	triage, err := benign.ParseTriage(triageRaw)
	if err != nil {
		return 2, err
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		return 2, err
	}
	temp, err := os.MkdirTemp("", "tripcord-benign-")
	if err != nil {
		return 2, err
	}
	defer func() { _ = os.RemoveAll(temp) }()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	results := benignscan.Run(ctx, repos, benignscan.GitFetcher{}, benignscan.Tripcord{Bin: abs}, benignscan.Options{
		Workers: workers,
		PerRepo: perRepo,
		Temp:    temp,
		Log:     func(s string) { fmt.Fprintln(os.Stderr, s) },
	})
	report := benignscan.Build(results, triage)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return 2, err
	}
	data = append(data, '\n')
	if out == "-" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(out, data, 0o644)
	}
	if err != nil {
		return 2, err
	}
	fmt.Fprintf(os.Stderr, "scanned %d of %d repositories in %s; %d failed; %d new untriaged high findings\n",
		report.Scanned, report.Repos, time.Since(start).Round(time.Second), len(report.Failed), len(report.NewUntriagedHigh))
	return benignscan.ExitCode(report, maxFailed), nil
}
