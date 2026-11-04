package benignscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

type fakeFetcher struct {
	mu      sync.Mutex
	active  int
	peak    int
	dirs    []string
	fail    string
	block   chan struct{}
	started atomic.Int32
}

func (f *fakeFetcher) Fetch(ctx context.Context, repo, sha, dir string) error {
	f.started.Add(1)
	f.mu.Lock()
	f.active++
	if f.active > f.peak {
		f.peak = f.active
	}
	f.dirs = append(f.dirs, dir)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		time.Sleep(2 * time.Millisecond)
	}
	if repo == f.fail {
		return errors.New("no such commit")
	}
	if err := os.MkdirAll(filepath.Join(dir, ".vscode"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ".vscode", "tasks.json"), []byte(repo), 0o644)
}

type fakeScanner struct{}

func (fakeScanner) Scan(ctx context.Context, dir string) ([]Finding, int, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ".vscode", "tasks.json"))
	if err != nil {
		return nil, 0, err
	}
	if strings.HasSuffix(string(raw), "-hot") {
		return []Finding{{Rule: "TC-CFG-002", Severity: "high", Fingerprint: "tcf_00000000000000ff"}}, 0, nil
	}
	return nil, 1, nil
}

func repoList(names ...string) []benign.Repo {
	out := make([]benign.Repo, len(names))
	for i, n := range names {
		out[i] = benign.Repo{Name: n, SHA: strings.Repeat("ab", 20)}
	}
	return out
}

func TestRunBoundsWorkersAndCleansUp(t *testing.T) {
	var names []string
	for i := 0; i < 20; i++ {
		names = append(names, "acme/r"+string(rune('a'+i)))
	}
	names[3] = "acme/broken"
	names[7] = "acme/r-hot"
	f := &fakeFetcher{fail: "acme/broken"}
	temp := t.TempDir()
	results := Run(context.Background(), repoList(names...), f, fakeScanner{}, Options{Workers: 3, PerRepo: time.Second, Temp: temp})
	if f.peak > 3 || f.peak < 2 {
		t.Fatalf("peak concurrency %d, want 2..3", f.peak)
	}
	for i, r := range results {
		if r.Repo != names[i] {
			t.Fatalf("result %d is %s, want %s", i, r.Repo, names[i])
		}
	}
	if !strings.Contains(results[3].Err, "no such commit") {
		t.Fatalf("broken repo: %+v", results[3])
	}
	if len(results[7].Findings) != 1 || results[0].Diagnostics != 1 {
		t.Fatalf("scan results not kept: %+v %+v", results[7], results[0])
	}
	left, err := os.ReadDir(temp)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("temp dir not cleaned: %d entries", len(left))
	}
	for _, d := range f.dirs {
		if !strings.HasPrefix(d, temp+string(os.PathSeparator)) {
			t.Fatalf("tree %s outside the temp dir", d)
		}
	}
}

func TestRunMarksUnreachedRepositoriesAsFailed(t *testing.T) {
	f := &fakeFetcher{block: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []Result)
	go func() {
		done <- Run(ctx, repoList("a/one", "a/two", "a/three", "a/four"), f, fakeScanner{}, Options{Workers: 1, PerRepo: time.Minute, Temp: t.TempDir()})
	}()
	for f.started.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	results := <-done
	failed := 0
	for _, r := range results {
		if r.Err != "" {
			failed++
		}
	}
	if failed != 4 {
		t.Fatalf("%d of 4 failed after the deadline: %+v", failed, results)
	}
	rep := Build(results, nil)
	if rep.Scanned != 0 || ExitCode(rep, 0.05) != 1 {
		t.Fatalf("a run cut off by the deadline passed: %+v", rep)
	}
}
