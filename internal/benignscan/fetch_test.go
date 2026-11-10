package benignscan

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTreeEntry(t *testing.T) {
	oid := strings.Repeat("a", 40)
	for _, tc := range []struct {
		ent  string
		ok   bool
		fail bool
	}{
		{"100644 blob " + oid + "\t.vscode/tasks.json", true, false},
		{"100755 blob " + oid + "\tscripts/run.sh", true, false},
		{"120000 blob " + oid + "\tlink", false, false},
		{"160000 commit " + oid + "\tvendor/sub", false, false},
		{"100644 blob " + oid + "\t../escape", false, true},
		{"100644 blob " + oid + "\tsub/.git/config", false, true},
		{"100644 blob " + oid + "\t/abs", false, true},
		{"garbage", false, true},
	} {
		_, ok, err := parseTreeEntry(tc.ent)
		if ok != tc.ok || (err != nil) != tc.fail {
			t.Errorf("%q: ok=%v err=%v", tc.ent, ok, err)
		}
	}
}

// TestGitFetcherLocal fetches from a local bare repository, so it needs
// git but no network.
func TestGitFetcherLocal(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	src := filepath.Join(root, "src")
	runGit := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.MkdirAll(filepath.Join(src, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(src, "init", "-q", "-b", "main")
	write := func(rel string, data []byte, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(src, rel), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(".vscode/tasks.json", []byte(`{"tasks":[]}`), 0o644)
	write("run.sh", []byte("#!/bin/sh\necho hi\n"), 0o755)
	write("big.bin", bytes.Repeat([]byte("x"), int(oversize)+10), 0o644)
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	runGit(src, "add", "-A")
	runGit(src, "commit", "-q", "-m", "init")
	sha := runGit(src, "rev-parse", "HEAD")
	bare := filepath.Join(root, "vgmartinez", "repo.git")
	runGit(root, "clone", "-q", "--bare", src, bare)
	runGit(bare, "config", "uploadpack.allowFilter", "true")
	runGit(bare, "config", "uploadpack.allowAnySHA1InWant", "true")

	dir := filepath.Join(root, "out", "tree")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	f := GitFetcher{BaseURL: "file://" + root}
	if err := f.Fetch(context.Background(), "vgmartinez/repo", sha, dir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".vscode", "tasks.json"))
	if err != nil || string(got) != `{"tasks":[]}` {
		t.Fatalf("tasks.json: %q %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, "run.sh"))
	if err != nil || info.Mode().Perm()&0o111 != 0 {
		t.Fatalf("run.sh is executable or missing: %v %v", info, err)
	}
	big, err := os.Stat(filepath.Join(dir, "big.bin"))
	if err != nil || big.Size() != oversize {
		t.Fatalf("oversize placeholder: %v %v", big, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "link")); !os.IsNotExist(err) {
		t.Fatalf("symlink was written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatal("tree has a .git directory")
	}
	if _, err := os.Stat(dir + ".git"); !os.IsNotExist(err) {
		t.Fatal("bare fetch repository left behind")
	}
}
