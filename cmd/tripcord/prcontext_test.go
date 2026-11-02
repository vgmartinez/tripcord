package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

func TestPrContextHumanFixture(t *testing.T) {
	repo := initRepo(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"pr-context", "--format", "json", "--repo", repo, "--event", filepath.Join("testdata", "prcontext", "human.json")}, &stdout, &stderr)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}
	var got struct {
		Agent    bool     `json:"agent"`
		Agents   []string `json:"agents"`
		Signals  []any    `json:"signals"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout.String())
	}
	if got.Agent || len(got.Agents) != 0 || len(got.Signals) != 0 {
		t.Fatalf("human fixture detected an agent: %+v", got)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "not in this clone") {
		t.Fatalf("warnings = %v", got.Warnings)
	}
}

func TestPrContextAgentFixture(t *testing.T) {
	git, repo, base, head := agentRepo(t)
	_ = git
	raw, err := os.ReadFile(filepath.Join("testdata", "prcontext", "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	event := filepath.Join(t.TempDir(), "event.json")
	body := strings.ReplaceAll(string(raw), "__BASE__", base)
	body = strings.ReplaceAll(body, "__HEAD__", head)
	if err := os.WriteFile(event, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "github_output")
	t.Setenv("GITHUB_OUTPUT", out)
	t.Setenv("GITHUB_EVENT_PATH", event)
	var stdout, stderr bytes.Buffer
	code := run([]string{"pr-context", "--format", "json", "--repo", repo}, &stdout, &stderr)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}
	var got struct {
		Agent   bool `json:"agent"`
		Agents  []string
		Signals []struct {
			Type   string `json:"type"`
			Agent  string `json:"agent"`
			Value  string `json:"value"`
			Source string `json:"source"`
		}
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout.String())
	}
	if !got.Agent || strings.Join(got.Agents, ",") != "claude,copilot,cursor" {
		t.Fatalf("agents = %v\nsignals %+v", got.Agents, got.Signals)
	}
	found := map[string]bool{}
	for _, s := range got.Signals {
		found[s.Type+" "+s.Agent] = true
		if s.Agent == "devin" {
			t.Fatalf("base commit was scanned: %+v", got.Signals)
		}
		if s.Value == "ada@example.com" {
			t.Fatalf("human co-author matched: %+v", s)
		}
	}
	for _, want := range []string{"branch-prefix cursor", "bot-login copilot", "co-authored-by claude", "git-ai cursor"} {
		if !found[want] {
			t.Errorf("missing %s in %+v", want, got.Signals)
		}
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != "is_agent=true\nagents=claude,copilot,cursor\n" {
		t.Fatalf("GITHUB_OUTPUT = %q", written)
	}
}

func TestPrContextCleanHumanPullRequest(t *testing.T) {
	git := lookGit(t)
	repo := initRepo(t)
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/docs")
	if err := os.WriteFile(filepath.Join(repo, "docs.txt"), []byte("docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", "docs.txt")
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q",
		"-m", "document\n\nCo-authored-by: Grace Hopper <grace@example.com>\n")
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	event := filepath.Join(t.TempDir(), "event.json")
	body := `{"pull_request":{"user":{"login":"octocat"},"head":{"ref":"feature/docs","sha":"` + head + `"},"base":{"ref":"main","sha":"` + base + `"}}}`
	if err := os.WriteFile(event, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"pr-context", "--repo", repo, "--event", event}, &stdout, &stderr)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "agent: false\n") || strings.Contains(stdout.String(), "warnings:") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestPrContextUsage(t *testing.T) {
	repo := initRepo(t)
	for name, args := range map[string][]string{
		"no input":           {"pr-context", "--repo", repo},
		"bad format":         {"pr-context", "--format", "sarif", "--base", "a", "--head", "b"},
		"bad revision":       {"pr-context", "--repo", repo, "--base", "-upload-pack", "--head", "HEAD"},
		"gha without output": {"pr-context", "--format", "gha", "--repo", repo, "--base", "HEAD", "--head", "HEAD"},
		"positional":         {"pr-context", "extra"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != int(exitcode.Config) {
			t.Errorf("%s: exit %d, want 3\nstderr: %s", name, code, stderr.String())
		}
		if !strings.HasPrefix(stderr.String(), "tripcord pr-context: ") {
			t.Errorf("%s: stderr = %q", name, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"pr-context", "--help"}, &stdout, &stderr); code != int(exitcode.OK) || !strings.Contains(stdout.String(), "-event") {
		t.Fatalf("help = %d %q", code, stdout.String())
	}

	out := filepath.Join(t.TempDir(), "out")
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), out); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_OUTPUT", out)
	stdout.Reset()
	stderr.Reset()
	// A human branch with no commits in range still has to refuse the symlink.
	empty, base, head := emptyRange(t)
	if code := run([]string{"pr-context", "--repo", empty, "--base", base, "--head", head}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("symlink output: exit %d\nstderr: %s", code, stderr.String())
	}
}

func initRepo(t *testing.T) string {
	t.Helper()
	git := lookGit(t)
	repo := t.TempDir()
	runGitCmd(t, git, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "README"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", "README")
	runGitCmd(t, git, repo, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "init")
	return repo
}

func emptyRange(t *testing.T) (repo, base, head string) {
	t.Helper()
	git := lookGit(t)
	repo = initRepo(t)
	head = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	base = head
	return repo, base, head
}

func agentRepo(t *testing.T) (git, repo, base, head string) {
	t.Helper()
	git = lookGit(t)
	repo = t.TempDir()
	runGitCmd(t, git, repo, "init", "-q", "-b", "main")
	runGitCmd(t, git, repo, "config", "user.email", "t@example.invalid")
	runGitCmd(t, git, repo, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", "a.txt")
	runGitCmd(t, git, repo, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q",
		"-m", "init\n\nCo-authored-by: devin-ai-integration[bot] <devin-ai-integration[bot]@users.noreply.github.com>")
	base = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "cursor/add-thing")
	if err := os.WriteFile(filepath.Join(repo, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", "b.txt")
	cmd := exec.Command(git, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q",
		"-m", "add thing\n\nCo-authored-by: Ada Lovelace <ada@example.com>\nCo-authored-by: Claude <noreply@anthropic.com>\n")
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
	head = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	note := filepath.Join(t.TempDir(), "note")
	noteBody := "src/b.txt\n---\n" +
		`{"schema_version":"authorship/3.0.0","base_commit_sha":"` + base + `","prompts":{},"sessions":{"s_aaaaaaaaaaaaaa":{"agent_id":{"tool":"cursor","id":"1","model":"m"}}}}` + "\n"
	if err := os.WriteFile(note, []byte(noteBody), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "notes", "--ref=ai", "add", "-F", note, head)
	return git, repo, base, head
}

func lookGit(t *testing.T) string {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	return git
}

func runGitCmd(t *testing.T, git, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func gitOut(t *testing.T, git, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}
