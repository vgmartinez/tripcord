// Command benign-repos builds corpus/benign/repos.lock from the GitHub
// code search API, or with -discover from one repository-search window.
// It does not download repository contents. A run merges into the lock
// already at -out. Rows already there keep their commit SHA unless
// -repin is set; -discover never changes them.
//
//	GITHUB_TOKEN=... go run ./scripts/benign-repos [-out corpus/benign/repos.lock] [-target 1000] [-batch 8] [-min-harness 40] [-only h1,h2]
//	GITHUB_TOKEN=... go run ./scripts/benign-repos -discover 0 [-pages 10]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	onlyList := flag.String("only", "", "comma-separated harnesses to search in this run; empty searches all")
	discover := flag.Int("discover", -1, "read this repository-search window instead of code search; -1 uses code search")
	pages := flag.Int("pages", 10, "repository-search pages to read in the -discover window, 1 to 10")
	flag.Parse()
	token := os.Getenv("GITHUB_TOKEN")
	only, onlyOK := parseOnly(*onlyList)
	if token == "" || *target < 1 || *batch < 0 || *minHarness < 0 || !onlyOK || *pages < 1 || *pages > 10 || flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: GITHUB_TOKEN=... benign-repos [-out corpus/benign/repos.lock] [-target 1000] [-batch 8] [-min-harness 40] [-only h1,h2] [-partial] [-repin] [-discover N [-pages 10]]")
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
	if *discover >= 0 {
		os.Exit(runDiscover(ctx, client, *discover, *pages, *target, *out, *statePath, existing, cursors, when, log))
	}
	res, err := benign.Build(ctx, client, benign.Options{
		Target:        *target,
		Now:           when,
		MinPerHarness: *minHarness,
		Batch:         *batch,
		Existing:      existing,
		Repin:         *repin,
		State:         cursors,
		Only:          only,
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

// runDiscover reads one repository-search window and writes what it
// found, even when the window stopped early. crawl.state is rewritten
// unchanged. The exit status is 1 when the window stopped early.
func runDiscover(ctx context.Context, client *benign.Client, window, pages, target int, out, statePath string, existing []benign.Repo, cursors []benign.Cursor, when time.Time, log func(string)) int {
	repos, err := benign.Discover(ctx, client, benign.DiscoverOptions{
		Window:   window,
		Pages:    pages,
		Target:   target,
		Now:      when,
		Existing: existing,
	}, log)
	if repos != nil {
		if werr := writeProgress(out, statePath, repos, cursors, when, len(existing)); werr != nil {
			fmt.Fprintln(os.Stderr, "benign-repos:", werr)
			return 1
		}
		fmt.Fprintf(os.Stderr, "wrote %d repositories to %s from discover window %d\n", len(repos), out, window)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos: discover window stopped early:", err)
		return 1
	}
	return 0
}

func parseOnly(list string) ([]string, bool) {
	if list == "" {
		return nil, true
	}
	var out []string
	for _, h := range strings.Split(list, ",") {
		if !slices.Contains(benign.Harnesses, h) {
			return nil, false
		}
		out = append(out, h)
	}
	return out, true
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
