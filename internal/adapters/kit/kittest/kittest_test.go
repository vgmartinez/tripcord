package kittest

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
)

// failTB records Fatal from AssertGolden without failing the caller.
// AssertGolden stops the calling goroutine, so run it in its own goroutine.
type failTB struct {
	*testing.T
	failed bool
	msg    string
}

func (f *failTB) Helper() {}

func (f *failTB) Fatal(args ...any) {
	f.Fatalf("%s", fmt.Sprint(args...))
}

func (f *failTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestArchiveFixtures(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(filepath.Join("testdata", "hook"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := "-- .mcp.json --\n{}\r\n-- .claude/settings.json --\n{\"hooks\":{}}\n"
	if err := os.WriteFile(filepath.Join("testdata", "repo.txtar"), []byte(archive), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "hook", "event.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	root := CopyTree(t, filepath.Join("testdata", "repo"))
	for rel, want := range map[string]string{".mcp.json": "{}\r\n", ".claude/settings.json": "{\"hooks\":{}}\n"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		got, err := os.ReadFile(p)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", rel, got, err, want)
		}
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, %v; want 0600", rel, info.Mode().Perm(), err)
		}
	}

	if got, err := ReadFixture("testdata/repo/.claude/settings.json"); err != nil || string(got) != "{\"hooks\":{}}\n" {
		t.Fatalf("archive member = %q, %v", got, err)
	}
	if got, err := ReadFixture("testdata/hook/event.json"); err != nil || string(got) != "{}\n" {
		t.Fatalf("plain file = %q, %v", got, err)
	}
	if _, err := ReadFixture("testdata/repo/missing.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing member: %v", err)
	}
	if _, err := ReadFixture("testdata/none/x.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestVersions(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(filepath.Join("testdata", "hook"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "README.md"), []byte("notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"zeta-baseline", "alpha-baseline"} {
		p := filepath.Join("testdata", version)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "repo.txtar"), []byte("-- a --\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join("testdata", "notes"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := Versions(t)
	want := []string{"alpha-baseline", "zeta-baseline"}
	if !slices.Equal(got, want) {
		t.Fatalf("Versions = %v, want %v", got, want)
	}
}

func TestAssertGoldenUpdate(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	prev := adapters.GoldenUpdate
	t.Cleanup(func() { adapters.GoldenUpdate = prev })

	adapters.GoldenUpdate = false
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "discover.golden"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tb := &failTB{T: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		AssertGolden(tb, "discover.golden", []byte("new\n"))
	}()
	<-done
	if !tb.failed || !strings.Contains(tb.msg, "mismatch") || !strings.Contains(tb.msg, "go test ./internal/adapters/... -update") {
		t.Fatalf("golden diff did not fail: failed=%v msg=%q", tb.failed, tb.msg)
	}
	got, err := os.ReadFile(filepath.Join("testdata", "discover.golden"))
	if err != nil || string(got) != "old\n" {
		t.Fatalf("golden changed without -update: %q, %v", got, err)
	}

	adapters.GoldenUpdate = true
	AssertGolden(t, filepath.Join("extra", "discover.golden"), []byte("new\n"))
	got, err = os.ReadFile(filepath.Join("testdata", "extra", "discover.golden"))
	if err != nil || string(got) != "new\n" {
		t.Fatalf("rewritten golden = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join("testdata", "extra", "discover.golden"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, %v; want 0644", info.Mode().Perm(), err)
	}
}

func TestUpdateFlagRegistered(t *testing.T) {
	if flag.Lookup("update") == nil {
		t.Fatal("-update is not registered")
	}
}
