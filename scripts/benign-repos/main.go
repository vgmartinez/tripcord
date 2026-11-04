// Command benign-repos builds corpus/benign/repos.lock from the GitHub
// code search API. It does not download repository contents. A run
// merges into the lock already at -out. Rows already there keep their
// commit SHA unless -repin is set.
//
//	GITHUB_TOKEN=... go run ./scripts/benign-repos [-out corpus/benign/repos.lock] [-target 1000] [-batch 8] [-min-harness 40]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

func main() {
	out := flag.String("out", filepath.Join("corpus", "benign", "repos.lock"), "repos.lock path to write")
	statePath := flag.String("state", filepath.Join("corpus", "benign", "crawl.state"), "crawl cursor path")
	target := flag.Int("target", 1000, "repositories to keep")
	batch := flag.Int("batch", 8, "code-search requests in this run; 0 does not stop early")
	minHarness := flag.Int("min-harness", benign.DefaultMinPerHarness, "search harnesses under this count first")
	partial := flag.Bool("partial", false, "exit 0 when the batch ends before the target")
	repin := flag.Bool("repin", false, "replace the commit SHA of a repository already in the lock")
	flag.Parse()
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" || *target < 1 || *batch < 0 || *minHarness < 0 || flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: GITHUB_TOKEN=... benign-repos [-out corpus/benign/repos.lock] [-target 1000] [-batch 8] [-min-harness 40] [-partial] [-repin]")
		os.Exit(2)
	}
	existing, err := readExisting(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos:", err)
		os.Exit(1)
	}
	cursors, err := readState(*statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
	defer cancel()
	client := benign.NewClient(token)
	log := func(msg string) {
		fmt.Fprintln(os.Stderr, msg)
		_ = os.Stderr.Sync()
	}
	client.Log = log
	when := time.Now().UTC()
	res, err := benign.Build(ctx, client, benign.Options{
		Target:        *target,
		Now:           when,
		MinPerHarness: *minHarness,
		Batch:         *batch,
		Existing:      existing,
		Repin:         *repin,
		State:         cursors,
		Save: func(repos []benign.Repo, cursors []benign.Cursor) error {
			return writeProgress(*out, *statePath, repos, cursors, when, len(existing))
		},
	}, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos:", err)
		os.Exit(1)
	}
	if len(res.Repos) < len(existing) {
		fmt.Fprintf(os.Stderr, "benign-repos: refusing to replace %d repositories with %d\n", len(existing), len(res.Repos))
		os.Exit(1)
	}
	if err := writeProgress(*out, *statePath, res.Repos, res.Cursors, res.When, len(existing)); err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %d repositories to %s\n", len(res.Repos), *out)
	for _, note := range res.Notes {
		fmt.Fprintln(os.Stderr, note)
	}
	fmt.Fprintln(os.Stderr, "harness distribution (a repository is counted in each harness it has):")
	for _, h := range benign.Harnesses {
		n := 0
		for _, r := range res.Repos {
			for _, got := range r.Harnesses {
				if got == h {
					n++
				}
			}
		}
		fmt.Fprintf(os.Stderr, "  %s %d\n", h, n)
	}
	bands := map[string]int{}
	for _, r := range res.Repos {
		bands[r.Band]++
	}
	fmt.Fprintf(os.Stderr, "size distribution: small %d, medium %d, large %d\n", bands["small"], bands["medium"], bands["large"])
	os.Exit(benign.ExitCode(res, *partial))
}

func readExisting(path string) ([]benign.Repo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return benign.LoadLock(raw)
}

func readState(path string) ([]benign.Cursor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return benign.ParseState(raw)
}

func writeProgress(lockPath, statePath string, repos []benign.Repo, cursors []benign.Cursor, when time.Time, before int) error {
	if len(repos) < before {
		return fmt.Errorf("refusing to replace %d repositories with %d", before, len(repos))
	}
	data, err := benign.FormatLock(repos, when)
	if err != nil {
		return err
	}
	if err := benign.WriteLock(lockPath, data); err != nil {
		return err
	}
	state, err := benign.FormatState(cursors)
	if err != nil {
		return err
	}
	return benign.WriteAtomic(statePath, state)
}
