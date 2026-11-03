package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/indexfiles"
)

// stagedBulkBudget is the wall-clock allowance for materializing and
// scanning an index of about 50k files and a few hundred megabytes of
// non-config blobs. The CI perf job runs this with TRIPCORD_PERF_BUDGET.
// The byte check is what rejects writing those blobs.
const stagedBulkBudget = 30 * time.Second

func TestStagedBulkBlobsAreNotWritten(t *testing.T) {
	stagedBulk(t, 32, 4<<10, 0)
}

func TestStagedBulkBlobsPerfBudget(t *testing.T) {
	if os.Getenv("TRIPCORD_PERF_BUDGET") == "" {
		t.Skip("set TRIPCORD_PERF_BUDGET=1 to check the staged index budget")
	}
	stagedBulk(t, 50_000, 8<<10, stagedBulkBudget)
}

func stagedBulk(t *testing.T, n, size int, budget time.Duration) {
	t.Helper()
	repo := stagedRepo(t)
	stagedWrite(t, repo, ".claude/settings.json", stagedBad)
	stagedGit(t, repo, "add", ".claude/settings.json")
	stageBulkBlobs(t, repo, n, size)

	start := time.Now()
	ws, notes, _, err := indexfiles.Materialize(context.Background(), repo, "")
	materialize := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	if len(notes) != 0 {
		t.Fatalf("notes: %+v", notes)
	}
	sample := filepath.Join(ws.Tree(), "bulk", "f00000.bin")
	if _, err := os.Lstat(sample); !os.IsNotExist(err) {
		t.Fatalf("non-config blob %s: %v", sample, err)
	}
	files, blocks, err := stagedTreeUse(ws.Tree())
	if err != nil {
		t.Fatal(err)
	}
	logical := int64(n) * int64(size)
	if files != 1 || blocks > 1<<20 {
		t.Fatalf("tree files=%d allocated=%d logical_blob_bytes=%d", files, blocks, logical)
	}

	bin := buildStagedBinary(t)
	scanStart := time.Now()
	code, out := stagedScan(t, bin, repo, ".claude/settings.json")
	scan := time.Since(scanStart)
	t.Logf("staged bulk: files=%d logical_blob_bytes=%d written_blocks=%d materialize=%s scan=%s", n, logical, blocks, materialize, scan)
	if code != 1 || !bytes.Contains([]byte(out), []byte("TC-CFG-001")) {
		t.Fatalf("scan = %d, want 1\n%s", code, out)
	}
	if budget > 0 && materialize+scan > budget {
		t.Fatalf("materialize %s + scan %s exceeds %s", materialize, scan, budget)
	}
}

func stageBulkBlobs(t *testing.T, repo string, n, size int) {
	t.Helper()
	oid := stagedHashObject(t, repo, bytes.Repeat([]byte("x"), size))
	var buf bytes.Buffer
	for i := range n {
		fmt.Fprintf(&buf, "100644 %s 0\tbulk/f%05d.bin\n", oid, i)
	}
	cmd := exec.Command("git", "update-index", "--add", "--index-info")
	cmd.Dir = repo
	cmd.Stdin = &buf
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("update-index: %v\n%s", err, out)
	}
}

func stagedHashObject(t *testing.T, repo string, body []byte) string {
	t.Helper()
	cmd := exec.Command("git", "hash-object", "-w", "--stdin")
	cmd.Dir = repo
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("hash-object: %v", err)
	}
	return string(bytes.TrimSpace(out))
}

func stagedTreeUse(root string) (files int, blocks int64, err error) {
	err = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		info, err := d.Info()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			blocks += info.Size()
			return nil
		}
		blocks += st.Blocks * 512
		return nil
	})
	return files, blocks, err
}
