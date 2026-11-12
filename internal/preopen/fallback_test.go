package preopen

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/gitrun"
	"github.com/vgmartinez/tripcord/internal/preopen/preopentest"
)

// TestFetchWithoutFilterSupportStillWritesPlaceholders is the
// filter-ignored fallback: a file:// source without uploadpack.allowFilter
// sends every blob (git's own fallback, the same pack f08138f would
// download). Over-cap blobs are still written as cap+1 placeholders, not
// in full, and the configuration file is still copied byte-for-byte.
func TestFetchWithoutFilterSupportStillWritesPlaceholders(t *testing.T) {
	prev := maxTotalBytes
	maxTotalBytes = 4 << 20
	t.Cleanup(func() { maxTotalBytes = prev })

	git := preopentest.RequireTools(t)
	repo := filepath.Join(t.TempDir(), "repo")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "repo")
	// Do not set uploadpack.allowFilter: the clone must ignore the filter.
	preopentest.WriteFile(t, filepath.Join(repo, ".claude", "settings.json"), preopentest.ClaudeSettings, 0o644)
	data := make([]byte, 2<<20)
	if err := os.WriteFile(filepath.Join(repo, "big.bin"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	preopentest.Git(t, git, repo, "add", "-A")
	preopentest.Git(t, git, repo, "commit", "-q", "-m", "fixture")
	oid := gitOutput(t, git, repo, "", "rev-parse", "HEAD:big.bin")

	ws, err := Fetch(context.Background(), repo)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer func() { _ = ws.Close() }()

	got, err := os.ReadFile(filepath.Join(ws.Tree(), ".claude", "settings.json"))
	if err != nil || string(got) != preopentest.ClaudeSettings {
		t.Fatalf("settings.json = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(ws.Tree(), "big.bin"))
	if err != nil || info.Size() != adapters.MaxConfigFileBytes+1 {
		t.Fatalf("placeholder size = %v, %v; want %d", info, err, adapters.MaxConfigFileBytes+1)
	}
	// The blob was downloaded: the server ignored the filter, matching
	// the clone f08138f would have made.
	if !objectExists(t, git, filepath.Join(ws.Dir(), "git"), oid) {
		t.Fatal("big.bin oid is missing from the clone; the filter was not ignored")
	}
}

// TestCommandSetsNoLazyFetch is the invariant preopen relies on: every
// gitrun.Command, including cat-file, gets GIT_NO_LAZY_FETCH=1, so a
// filtered blob is never filled in later.
func TestCommandSetsNoLazyFetch(t *testing.T) {
	cmd, err := gitrun.Command(context.Background(), "", "cat-file", "--batch-check")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range cmd.Env {
		if e == "GIT_NO_LAZY_FETCH=1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Command env lacks GIT_NO_LAZY_FETCH=1: %v", cmd.Env)
	}
}

// manyBlobCount is larger than a typical 64 KiB pipe can hold as
// cat-file requests (a 40-byte oid plus newline is 41 bytes, so 2,000
// requests already exceed 64 KiB). Writing them all before reading
// stdout deadlocks inspectBlobs and BlobSizes.
const manyBlobCount = 5000

func TestFetchManyBlobsDoesNotDeadlock(t *testing.T) {
	prev := maxTotalBytes
	maxTotalBytes = 16 << 20
	t.Cleanup(func() { maxTotalBytes = prev })

	git := preopentest.RequireTools(t)
	repo, oids := manyBlobRepo(t, git)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ws, err := Fetch(ctx, repo)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer func() { _ = ws.Close() }()

	info, err := os.Stat(filepath.Join(ws.Tree(), "big.bin"))
	if err != nil || info.Size() != adapters.MaxConfigFileBytes+1 {
		t.Fatalf("placeholder size = %v, %v", info, err)
	}
	got, err := os.ReadFile(filepath.Join(ws.Tree(), "files", "0000"))
	if err != nil || string(got) != "0\n" {
		t.Fatalf("small file = %q, %v", got, err)
	}
	if n := ws.Placeholders(); n != 1 {
		t.Fatalf("Placeholders() = %d, want 1", n)
	}

	// BlobSizes is the same pipe pattern, used by scan --staged.
	gitDir := filepath.Join(repo, ".git")
	sizes, err := BlobSizes(ctx, gitDir, oids)
	if err != nil {
		t.Fatalf("BlobSizes: %v", err)
	}
	if len(sizes) != len(oids) {
		t.Fatalf("BlobSizes returned %d oids, want %d", len(sizes), len(oids))
	}
}

func manyBlobRepo(t *testing.T, git string) (repo string, oids []string) {
	t.Helper()
	repo = filepath.Join(t.TempDir(), "repo")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "repo")
	preopentest.Git(t, git, repo, "config", "uploadpack.allowFilter", "true")
	preopentest.WriteFile(t, filepath.Join(repo, ".claude", "settings.json"), preopentest.ClaudeSettings, 0o644)
	dir := filepath.Join(repo, "files")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < manyBlobCount; i++ {
		preopentest.WriteFile(t, filepath.Join(dir, fmt.Sprintf("%04d", i)), fmt.Sprintf("%d\n", i), 0o644)
	}
	big := make([]byte, 2<<20)
	if err := os.WriteFile(filepath.Join(repo, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	preopentest.Git(t, git, repo, "add", "-A")
	preopentest.Git(t, git, repo, "commit", "-q", "-m", "fixture")
	raw := gitOutput(t, git, repo, "", "ls-tree", "-r", "--object-only", "HEAD")
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line != "" {
			oids = append(oids, line)
		}
	}
	if len(oids) < manyBlobCount+1 {
		t.Fatalf("ls-tree oids = %d, want at least %d", len(oids), manyBlobCount+1)
	}
	return repo, oids
}
