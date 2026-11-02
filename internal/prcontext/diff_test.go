package prcontext

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChangedPathsListsThePullRequestDiff(t *testing.T) {
	git := requireGit(t)
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	gitCmd(t, repo, "config", "user.email", "t@example.invalid")
	gitCmd(t, repo, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "README"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "README")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	base := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	gitCmd(t, repo, "checkout", "-q", "-b", "feature")
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "hooks.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", ".cursor/hooks.json")
	gitCmd(t, repo, "commit", "-q", "-m", "add hooks")
	head := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	// A commit on main after the branch point must not appear in the
	// three-dot diff.
	gitCmd(t, repo, "checkout", "-q", "main")
	if err := os.WriteFile(filepath.Join(repo, "later.txt"), []byte("later\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "later.txt")
	gitCmd(t, repo, "commit", "-q", "-m", "later on main")

	diff, err := ChangedPaths(context.Background(), repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Missing || diff.Truncated {
		t.Fatalf("diff = %+v", diff)
	}
	if len(diff.Paths) != 1 || diff.Paths[0] != ".cursor/hooks.json" {
		t.Fatalf("paths = %v", diff.Paths)
	}

	missing, err := ChangedPaths(context.Background(), repo, "0123456789abcdef0123456789abcdef01234567", head)
	if err != nil {
		t.Fatal(err)
	}
	if !missing.Missing || len(missing.Paths) != 0 {
		t.Fatalf("missing revision = %+v", missing)
	}
}

func TestParseNameStatusRejectsControlCharacters(t *testing.T) {
	for _, path := range []string{
		".cursor/hooks.json\n::error::injected",
		".cursor/hooks.json\r::error::injected",
		".cursor/hooks.json\x1b::error::injected",
	} {
		raw := append([]byte(":000000 100644 0000000 1111111 A\x00"), path...)
		raw = append(raw, 0)
		_, _, err := parseRawDiff(raw, 10)
		var input *InputError
		if !errors.As(err, &input) {
			t.Fatalf("path %q: err = %v", path, err)
		}
		if strings.Contains(err.Error(), "::error::") || strings.Contains(err.Error(), path) {
			t.Fatalf("error echoed the path: %v", err)
		}
	}
}
