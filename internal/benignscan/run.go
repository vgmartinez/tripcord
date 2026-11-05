package benignscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

// Options bound one run. Workers is the pool size. PerRepo caps one
// fetch and scan. Temp is the parent of the per-repository directories.
type Options struct {
	Workers int
	PerRepo time.Duration
	Temp    string
	Log     func(string)
}

// Run fetches and scans every repository with a bounded worker pool.
// Each tree lives in its own temporary directory and is removed after
// its scan. A repository not reached before ctx ends is a failure, so
// the report never silently covers fewer repositories than the lock.
// Results keep the order of repos.
func Run(ctx context.Context, repos []benign.Repo, f Fetcher, s Scanner, opt Options) []Result {
	if opt.Workers < 1 {
		opt.Workers = 1
	}
	if opt.PerRepo <= 0 {
		opt.PerRepo = 5 * time.Minute
	}
	log := opt.Log
	if log == nil {
		log = func(string) {}
	}
	out := make([]Result, len(repos))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < opt.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = scanOne(ctx, repos[i], i, f, s, opt)
				if out[i].Err != "" {
					log(fmt.Sprintf("%s: %s", repos[i].Name, out[i].Err))
				}
			}
		}()
	}
	for i := range repos {
		out[i] = Result{Repo: repos[i].Name, SHA: repos[i].SHA, Err: "not scanned before the deadline"}
	}
feed:
	for i := range repos {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

func scanOne(ctx context.Context, r benign.Repo, i int, f Fetcher, s Scanner, opt Options) Result {
	res := Result{Repo: r.Name, SHA: r.SHA, Findings: []Finding{}}
	ctx, cancel := context.WithTimeout(ctx, opt.PerRepo)
	defer cancel()
	parent, err := os.MkdirTemp(opt.Temp, "benign-")
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer func() { _ = os.RemoveAll(parent) }()
	dir := filepath.Join(parent, fmt.Sprintf("r%04d", i))
	if err := f.Fetch(ctx, r.Name, r.SHA, dir); err != nil {
		res.Err = "fetch: " + err.Error()
		return res
	}
	findings, diags, err := s.Scan(ctx, dir)
	if err != nil {
		res.Err = "scan: " + err.Error()
		return res
	}
	res.Findings = append(res.Findings, findings...)
	res.Diagnostics = diags
	return res
}
