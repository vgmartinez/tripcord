// Command benign-repos builds corpus/benign/repos.lock from the GitHub
// code search API. It does not download repository contents.
//
//	GITHUB_TOKEN=... go run ./scripts/benign-repos [-out corpus/benign/repos.lock] [-target 1000]
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
	target := flag.Int("target", 1000, "repositories to keep")
	flag.Parse()
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" || *target < 1 || flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: GITHUB_TOKEN=... benign-repos [-out corpus/benign/repos.lock] [-target 1000]")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
	defer cancel()
	client := benign.NewClient(token)
	log := func(msg string) {
		fmt.Fprintln(os.Stderr, msg)
		_ = os.Stderr.Sync()
	}
	client.Log = log
	res, err := benign.Build(ctx, client, benign.Options{
		Target: *target,
		Now:    time.Now().UTC(),
	}, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos:", err)
		os.Exit(1)
	}
	if len(res.Repos) == 0 {
		fmt.Fprintln(os.Stderr, "benign-repos: no repositories")
		os.Exit(1)
	}
	data, err := benign.FormatLock(res.Repos, res.When)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "benign-repos:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
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
		bands[benign.SizeBand(r.SizeKB)]++
	}
	fmt.Fprintf(os.Stderr, "size distribution: small %d, medium %d, large %d\n", bands["small"], bands["medium"], bands["large"])
}
