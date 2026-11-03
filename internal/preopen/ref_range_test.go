package preopen

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefRangeChangeSetUsesThreeDot(t *testing.T) {
	repo := initRefRepo(t)
	writeRefFile(t, repo, "README", "base\n")
	refGit(t, repo, "add", "README")
	refGit(t, repo, "commit", "-qm", "base")
	refGit(t, repo, "checkout", "-q", "-b", "feature")
	writeRefFile(t, repo, ".claude/settings.json", "{}\n")
	refGit(t, repo, "add", ".claude/settings.json")
	refGit(t, repo, "commit", "-qm", "settings")
	refGit(t, repo, "checkout", "-q", "main")
	writeRefFile(t, repo, "other.txt", "main only\n")
	refGit(t, repo, "add", "other.txt")
	refGit(t, repo, "commit", "-qm", "other")

	got, err := RefRangeChangeSet(context.Background(), repo, "main", "feature")
	if err != nil {
		t.Fatal(err)
	}
	if !got[".claude/settings.json"] {
		t.Fatalf("three-dot range missing the feature file: %#v", got)
	}
	if got["other.txt"] {
		t.Fatalf("three-dot range included a file that exists only on main: %#v", got)
	}
}

func TestRefRangeChangeSetFallsBackToTwoDot(t *testing.T) {
	repo := initRefRepo(t)
	writeRefFile(t, repo, "on-main.txt", "main\n")
	refGit(t, repo, "add", "on-main.txt")
	refGit(t, repo, "commit", "-qm", "main")
	refGit(t, repo, "checkout", "-q", "--orphan", "other")
	refGit(t, repo, "rm", "-rfq", ".")
	writeRefFile(t, repo, "on-other.txt", "other\n")
	refGit(t, repo, "add", "on-other.txt")
	refGit(t, repo, "commit", "-qm", "other")

	got, err := RefRangeChangeSet(context.Background(), repo, "main", "other")
	if err != nil {
		t.Fatal(err)
	}
	if !got["on-main.txt"] || !got["on-other.txt"] {
		t.Fatalf("two-dot fallback = %#v, want both roots' files", got)
	}
}

func TestRefRangeChangeSetRejectsFlagLikeRevision(t *testing.T) {
	repo := initRefRepo(t)
	if _, err := RefRangeChangeSet(context.Background(), repo, "--all", "HEAD"); err == nil {
		t.Fatal("accepted a revision that starts with -")
	}
}

func initRefRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	refGit(t, repo, "init", "-q", "-b", "main")
	refGit(t, repo, "config", "user.email", "test@example.invalid")
	refGit(t, repo, "config", "user.name", "Tripcord Test")
	return repo
}

func writeRefFile(t *testing.T, repo, rel, text string) {
	t.Helper()
	dest := filepath.Join(repo, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func refGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}
