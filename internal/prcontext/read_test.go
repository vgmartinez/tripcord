package prcontext

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if got := strings.Join(commits[0].NoteTools, ","); got != "cursor" {
		t.Fatalf("note tools = %q", got)
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

// TestReadCommitsOversizedIdentityField is a regression test for a commit
// whose author name is built directly as a git object (via
// `git hash-object -t commit -w --stdin`, bypassing argv/env length
// limits) and is larger than the old whole-record cap. Previously this
// made the record unsplittable into its six \x1e fields and ReadCommits
// failed with "git log record has an unexpected shape", hiding the
// commit (and, upstream, the bot-author signal on the event) entirely.
func TestReadCommitsOversizedIdentityField(t *testing.T) {
	git := requireGit(t)
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	gitCmd(t, repo, "config", "user.email", "t@example.invalid")
	gitCmd(t, repo, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "a.txt")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	base := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))
	tree := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD^{tree}"))

	hugeName := strings.Repeat("A", 5<<20)
	raw := "tree " + tree + "\n" +
		"parent " + base + "\n" +
		"author " + hugeName + " <attacker@example.invalid> 1700000000 +0000\n" +
		"committer t <t@example.invalid> 1700000000 +0000\n" +
		"\n" +
		"malicious commit\n"
	cmd := exec.Command(git, "hash-object", "-t", "commit", "-w", "--stdin")
	cmd.Dir = repo
	cmd.Stdin = strings.NewReader(raw)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}
	head := strings.TrimSpace(string(out))

	commits, warnings, err := ReadCommits(context.Background(), repo, base, head)
	if err != nil {
		t.Fatalf("ReadCommits = %v, warnings %v, err %v, want no error", commits, warnings, err)
	}
	if len(commits) != 1 || commits[0].SHA != head {
		t.Fatalf("commits = %+v, want only %s", commits, head)
	}
	if got := len(commits[0].AuthorName); got != maxIdentityField {
		t.Fatalf("AuthorName len = %d, want %d (truncated)", got, maxIdentityField)
	}
	if commits[0].CommitterName != "t" {
		t.Fatalf("CommitterName = %q, fields after the oversized one were lost", commits[0].CommitterName)
	}
	if commits[0].Message != "malicious commit\n" {
		t.Fatalf("Message = %q, fields after the oversized one were lost", commits[0].Message)
	}
}

func TestReadCommitsStreamsNotesAndCollapsesMalformedWarnings(t *testing.T) {
	git := requireGit(t)
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	gitCmd(t, repo, "config", "user.email", "t@example.invalid")
	gitCmd(t, repo, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "a.txt")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	base := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	// Every note points at the same 2MiB blob. Retaining note text on each
	// Commit makes this modest repository retain hundreds of MiB; streaming
	// them leaves only the tool id on each commit.
	const noteCount = 8
	note := "---\n" + `{"sessions":{"s":{"agent_id":{"tool":"cursor"}}},"padding":"` + strings.Repeat("x", (2<<20)-128) + `"}` + "\n"
	notePath := filepath.Join(t.TempDir(), "note")
	if err := os.WriteFile(notePath, []byte(note), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < noteCount; i++ {
		gitCmd(t, repo, "commit", "-q", "--allow-empty", "-m", "with note")
		sha := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))
		gitCmd(t, repo, "notes", "--ref=ai", "add", "-F", notePath, sha)
	}
	head := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	commits, warnings, err := ReadCommits(context.Background(), repo, base, head)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 || len(commits) != noteCount {
		t.Fatalf("commits %d warnings %v", len(commits), warnings)
	}
	for _, c := range commits {
		if c.Note != "" || strings.Join(c.NoteTools, ",") != "cursor" {
			t.Fatalf("retained note %q tools %v", c.Note, c.NoteTools)
		}
	}
	const slack = 24 << 20
	if after.HeapAlloc > before.HeapAlloc+slack {
		t.Fatalf("heap grew %d bytes, want at most %d while streaming %d notes", after.HeapAlloc-before.HeapAlloc, slack, noteCount)
	}

	badPath := filepath.Join(t.TempDir(), "bad-note")
	if err := os.WriteFile(badPath, []byte("not a git-ai log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range commits[:3] {
		gitCmd(t, repo, "notes", "--ref=ai", "add", "-f", "-F", badPath, c.SHA)
	}
	_, warnings, err = ReadCommits(context.Background(), repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0] != "3 authorship notes were not git-ai authorship logs and were skipped" {
		t.Fatalf("warnings = %v", warnings)
	}
}

// TestLargeNotesRSS reproduces the shared-note shape without paying for 300
// separate git notes processes. Each reader exposes the same 2MiB note blob,
// as refs/notes/ai does when many notes point at one object. Set
// TRIPCORD_NOTE_REPRO=1 to run it under a process memory limit.
func TestLargeNotesRSS(t *testing.T) {
	if os.Getenv("TRIPCORD_NOTE_REPRO") == "" {
		t.Skip("set TRIPCORD_NOTE_REPRO=1 to stream 300 large git-ai notes")
	}
	const (
		n      = 300
		rssCap = 256 << 20
	)
	note := []byte("---\n" + `{"sessions":{"s":{"agent_id":{"tool":"cursor"}}},"padding":"` + strings.Repeat("x", (2<<20)-128) + `"}` + "\n")
	for range n {
		tools, _, err := toolsFromNoteReader(bytes.NewReader(note))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(tools, ",") != "cursor" {
			t.Fatalf("tools = %v", tools)
		}
	}
	hwm := vmHWM(t)
	t.Logf("streamed %d %d-byte notes; VmHWM %d bytes", n, len(note), hwm)
	if hwm > rssCap {
		t.Fatalf("VmHWM %d bytes exceeds %d", hwm, rssCap)
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
