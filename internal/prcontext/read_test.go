package prcontext

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireGit(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	return git
}

func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(requireGit(t), args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestReadCommitsTrailersNotesAndMissingHistory(t *testing.T) {
	git := requireGit(t)
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	gitCmd(t, repo, "config", "user.email", "t@example.invalid")
	gitCmd(t, repo, "config", "user.name", "t")
	// A repo alias and a hook must not run while the commits are read.
	sentinel := filepath.Join(t.TempDir(), "ran")
	gitCmd(t, repo, "config", "alias.log", "!touch "+sentinel)
	gitCmd(t, repo, "config", "alias.rev-list", "!touch "+sentinel)
	gitCmd(t, repo, "config", "alias.notes", "!touch "+sentinel)
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "a.txt")
	gitCmd(t, repo, "commit", "-q", "-m", "init\n\nCo-authored-by: devin-ai-integration[bot] <devin-ai-integration[bot]@users.noreply.github.com>")
	base := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	gitCmd(t, repo, "checkout", "-q", "-b", "cursor/add-thing")
	if err := os.WriteFile(filepath.Join(repo, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "b.txt")
	cmd := exec.Command(git, "commit", "-q", "-m", "add thing\n\nCo-authored-by: Ada Lovelace <ada@example.com>\nCo-authored-by: Claude <noreply@anthropic.com>\n")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=copilot-swe-agent[bot]",
		"GIT_AUTHOR_EMAIL=198982749+copilot-swe-agent[bot]@users.noreply.github.com",
		"GIT_COMMITTER_NAME=Ada Lovelace",
		"GIT_COMMITTER_EMAIL=ada@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	head := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))
	note := filepath.Join(t.TempDir(), "note")
	if err := os.WriteFile(note, []byte(aiNote("cursor")), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "notes", "--ref=ai", "add", "-F", note, head)

	commits, warnings, err := ReadCommits(context.Background(), repo, base, head)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("ReadCommits = %v, warnings %v, err %v", commits, warnings, err)
	}
	if len(commits) != 1 || commits[0].SHA != head {
		t.Fatalf("commits = %+v, want only %s", commits, head)
	}
	if !strings.Contains(commits[0].Note, `"tool":"cursor"`) {
		t.Fatalf("note = %q", commits[0].Note)
	}
	got := Detect(Input{Branch: "cursor/add-thing", Commits: commits, Warnings: warnings})
	if strings.Join(got.Agents, ",") != "claude,copilot,cursor" {
		t.Fatalf("agents = %v, signals %+v", got.Agents, got.Signals)
	}
	for _, s := range got.Signals {
		if s.Agent == "devin" {
			t.Fatalf("base commit trailer was scanned: %+v", got.Signals)
		}
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("git alias ran")
	}

	missing := "0123456789abcdef0123456789abcdef01234567"
	commits, warnings, err = ReadCommits(context.Background(), repo, missing, head)
	if err != nil || len(commits) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "not in this clone") {
		t.Fatalf("missing base: commits %v warnings %v err %v", commits, warnings, err)
	}

	_, _, err = ReadCommits(context.Background(), t.TempDir(), base, head)
	var input *InputError
	if !errors.As(err, &input) {
		t.Fatalf("non-repo = %v, want InputError", err)
	}
}

func gitOutput(t *testing.T, git, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}
