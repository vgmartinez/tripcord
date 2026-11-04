package kittest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

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
