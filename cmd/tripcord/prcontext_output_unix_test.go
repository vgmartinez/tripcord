//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// TestPrContextOutputFIFORefused is a regression test for a FIFO swapped
// in for GITHUB_OUTPUT: a plain open(2) for writing blocks forever when
// nobody has opened the other end for reading. O_NONBLOCK must make the
// open fail immediately instead of hanging the command.
func TestPrContextOutputFIFORefused(t *testing.T) {
	clearPrContextEnv(t)
	out := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(out, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	t.Setenv("GITHUB_OUTPUT", out)
	empty, base, head := emptyRange(t)
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"pr-context", "--repo", empty, "--base", base, "--head", head}, &stdout, &stderr)
	}()
	select {
	case code := <-done:
		if code != int(exitcode.Config) {
			t.Fatalf("fifo output: exit %d, want 3\nstderr: %s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pr-context hung opening a FIFO GITHUB_OUTPUT")
	}
}

// TestPrContextOutputLeadingNewline is a regression test for
// GITHUB_OUTPUT content being run together with a previous line that
// lacked a trailing newline (e.g. "prevagents=...is_agent=false").
func TestPrContextOutputLeadingNewline(t *testing.T) {
	clearPrContextEnv(t)
	out := filepath.Join(t.TempDir(), "github_output")
	if err := os.WriteFile(out, []byte("prev=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_OUTPUT", out)
	empty, base, head := emptyRange(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pr-context", "--repo", empty, "--base", base, "--head", head}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want := "prev=1\nis_agent=false\nagents=\n"
	if string(got) != want {
		t.Fatalf("GITHUB_OUTPUT = %q, want %q", got, want)
	}
}
