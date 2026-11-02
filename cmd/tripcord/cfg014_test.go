package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

func TestCfg014AgentConfigChange(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	repo := initRepo(t)
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "hooks.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", ".cursor/hooks.json")
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "add hooks")
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))

	t.Run("missing reviews", func(t *testing.T) {
		code, stdout, stderr, output := runCfg014(t, repo, "no-reviews.json", base, head, "text")
		if code != int(exitcode.Config) {
			t.Fatalf("exit %d, want 3\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if !strings.Contains(stderr, "TC-CFG-014 incomplete: review data is not available") {
			t.Fatalf("stderr = %s", stderr)
		}
		if !strings.Contains(stdout, "agent: true\n") || !strings.Contains(stdout, "tc-cfg-014: incomplete\n") {
			t.Fatalf("stdout = %s", stdout)
		}
		if !strings.Contains(output, "is_agent=true\n") || !strings.Contains(output, "tc_cfg_014=incomplete\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
	t.Run("empty review list", func(t *testing.T) {
		code, stdout, stderr, output := runCfg014(t, repo, "empty-reviews.json", base, head, "json")
		if code != int(exitcode.Findings) {
			t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		var got struct {
			Agent    bool   `json:"agent"`
			TCCFG014 string `json:"tc_cfg_014"`
			Finding  struct {
				Rule     string `json:"rule"`
				Severity string `json:"severity"`
			} `json:"finding"`
		}
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("json: %v\n%s", err, stdout)
		}
		if !got.Agent || got.TCCFG014 != "match" || got.Finding.Rule != "TC-CFG-014" || got.Finding.Severity != "high" {
			t.Fatalf("decoded = %+v", got)
		}
		if !strings.Contains(output, "tc_cfg_014=match\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
	t.Run("human approval", func(t *testing.T) {
		code, stdout, stderr, output := runCfg014(t, repo, "human-approved.json", base, head, "text")
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(stdout, "tc-cfg-014:") || strings.Contains(output, "tc_cfg_014=") {
			t.Fatalf("approval was reported\nstdout: %s\noutput: %s", stdout, output)
		}
		if !strings.Contains(output, "is_agent=true\nagents=claude\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
	t.Run("lone approval", func(t *testing.T) {
		code, stdout, stderr, _ := runCfg014(t, repo, "lone-approval.json", base, head, "text")
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(stdout, "tc-cfg-014:") {
			t.Fatalf("lone approval did not clear the rule\n%s", stdout)
		}
	})
}

func TestCfg014ReviewsFile(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	repo := initRepo(t)
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "hooks.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", ".cursor/hooks.json")
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "add hooks")
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	event := writeCfg014Event(t, "no-reviews.json", base, head)

	t.Run("approval in the file clears", func(t *testing.T) {
		reviews := writeTemp(t, "reviews.json", `[{"state":"APPROVED","user":{"login":"Ada","type":"User"}}]`)
		code, stdout, stderr, output := runCfg014Args(t, repo, event, "text", "--reviews-file", reviews)
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(stdout, "tc-cfg-014:") || strings.Contains(output, "tc_cfg_014=") {
			t.Fatalf("file approval was reported\nstdout: %s\noutput: %s", stdout, output)
		}
	})
	t.Run("empty array is the complete set", func(t *testing.T) {
		reviews := writeTemp(t, "reviews.json", `[]`)
		code, stdout, stderr, output := runCfg014Args(t, repo, event, "json", "--reviews-file", reviews)
		if code != int(exitcode.Findings) {
			t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if !strings.Contains(stdout, `"tc_cfg_014": "match"`) || !strings.Contains(output, "tc_cfg_014=match\n") {
			t.Fatalf("stdout: %s\noutput: %s", stdout, output)
		}
	})
	t.Run("file replaces event reviews", func(t *testing.T) {
		ev := writeCfg014Event(t, "empty-reviews.json", base, head)
		reviews := writeTemp(t, "reviews.json", `[{"state":"APPROVED","user":{"login":"Ada","type":"User"}}]`)
		code, stdout, stderr, _ := runCfg014Args(t, repo, ev, "text", "--reviews-file", reviews)
		if code != int(exitcode.OK) || strings.Contains(stdout, "tc-cfg-014:") {
			t.Fatalf("exit %d, want the file to win\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
	})
	t.Run("invalid file", func(t *testing.T) {
		cases := []struct {
			name string
			path string
		}{
			{name: "not an array", path: writeTemp(t, "obj.json", `{"reviews":[]}`)},
			{name: "bad json", path: writeTemp(t, "bad.json", `{`)},
			{name: "empty", path: writeTemp(t, "empty.json", ``)},
			{name: "directory", path: t.TempDir()},
			{name: "missing", path: filepath.Join(t.TempDir(), "nope.json")},
			{name: "oversized", path: writeOversized(t)},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, stdout, stderr, _ := runCfg014Args(t, repo, event, "text", "--reviews-file", tc.path)
				if code != int(exitcode.Config) {
					t.Fatalf("exit %d, want 3\nstderr: %s\nstdout: %s", code, stderr, stdout)
				}
				if !strings.HasPrefix(stderr, "tripcord pr-context: ") {
					t.Fatalf("stderr = %s", stderr)
				}
			})
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := writeTemp(t, "reviews.json", `[]`)
		link := filepath.Join(t.TempDir(), "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skip("symlinks are not supported")
		}
		code, _, stderr, _ := runCfg014Args(t, repo, event, "text", "--reviews-file", link)
		if code != int(exitcode.Config) || !strings.Contains(stderr, "regular file") {
			t.Fatalf("exit %d, stderr %s", code, stderr)
		}
	})
}

func TestCfg014PolicyDoesNotFailBelowItsThreshold(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	repo := initRepo(t)
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "hooks.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", ".cursor/hooks.json")
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "add hooks")
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	event := writeCfg014Event(t, "empty-reviews.json", base, head)
	if err := os.MkdirAll(filepath.Join(repo, ".tripcord"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("audit mode", func(t *testing.T) {
		body := "version: 1\nmode: audit\n"
		if err := os.WriteFile(filepath.Join(repo, ".tripcord", "policy.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr, output := runCfg014Args(t, repo, event, "json")
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		var got struct {
			TCCFG014 string `json:"tc_cfg_014"`
			Finding  struct {
				Severity string `json:"severity"`
				Decision string `json:"decision"`
			} `json:"finding"`
		}
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("json: %v\n%s", err, stdout)
		}
		if got.TCCFG014 != "match" || got.Finding.Severity != "high" || got.Finding.Decision != "audit" {
			t.Fatalf("decoded = %+v", got)
		}
		if !strings.Contains(output, "tc_cfg_014=match\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
	t.Run("fail-on critical", func(t *testing.T) {
		body := "version: 1\nmode: enforce\nfail-on: critical\n"
		if err := os.WriteFile(filepath.Join(repo, ".tripcord", "policy.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr, output := runCfg014Args(t, repo, event, "json")
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		var got struct {
			TCCFG014 string `json:"tc_cfg_014"`
			Finding  struct {
				Severity string `json:"severity"`
				Decision string `json:"decision"`
			} `json:"finding"`
		}
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("json: %v\n%s", err, stdout)
		}
		if got.TCCFG014 != "match" || got.Finding.Severity != "high" || got.Finding.Decision != "deny" {
			t.Fatalf("decoded = %+v", got)
		}
		if !strings.Contains(output, "tc_cfg_014=match\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
}

func TestCfg014IgnoresOrdinaryFilesAndHumanAuthors(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	repo := initRepo(t)
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/docs")
	if err := os.WriteFile(filepath.Join(repo, "docs.txt"), []byte("docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", "docs.txt")
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "docs")
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))

	code, stdout, stderr, output := runCfg014(t, repo, "no-reviews.json", base, head, "text")
	if code != int(exitcode.OK) {
		t.Fatalf("ordinary file exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	if strings.Contains(stdout, "tc-cfg-014:") || strings.Contains(output, "tc_cfg_014=") {
		t.Fatalf("ordinary file was reported\nstdout: %s\noutput: %s", stdout, output)
	}

	human := filepath.Join(t.TempDir(), "event.json")
	body := `{"pull_request":{"user":{"login":"octocat","type":"User"},"head":{"ref":"feature/docs","sha":"` + head + `"},"base":{"sha":"` + base + `"}}}`
	if err := os.WriteFile(human, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// A human commit that does touch agent config is still clear.
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "mcp.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", ".cursor/mcp.json")
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "mcp")
	head = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	body = `{"pull_request":{"user":{"login":"octocat","type":"User"},"head":{"ref":"feature/docs","sha":"` + head + `"},"base":{"sha":"` + base + `"}}}`
	if err := os.WriteFile(human, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "github_output")
	t.Setenv("GITHUB_OUTPUT", out)
	var stdoutBuf, stderrBuf bytes.Buffer
	code = run([]string{"pr-context", "--repo", repo, "--event", human}, &stdoutBuf, &stderrBuf)
	if code != int(exitcode.OK) || strings.Contains(stdoutBuf.String(), "tc-cfg-014:") {
		t.Fatalf("human author exit %d\nstderr: %s\nstdout: %s", code, stderrBuf.String(), stdoutBuf.String())
	}
}

func runCfg014(t *testing.T, repo, fixture, base, head, format string) (int, string, string, string) {
	t.Helper()
	event := writeCfg014Event(t, fixture, base, head)
	return runCfg014Args(t, repo, event, format)
}

func writeCfg014Event(t *testing.T, fixture, base, head string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "cfg014", fixture))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(string(raw), "__BASE__", base)
	body = strings.ReplaceAll(body, "__HEAD__", head)
	event := filepath.Join(t.TempDir(), fixture)
	if err := os.WriteFile(event, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return event
}

func runCfg014Args(t *testing.T, repo, event, format string, extra ...string) (int, string, string, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "github_output")
	t.Setenv("GITHUB_OUTPUT", out)
	args := []string{"pr-context", "--format", format, "--repo", repo, "--event", event}
	args = append(args, extra...)
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	written, err := os.ReadFile(out)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return code, stdout.String(), stderr.String(), string(written)
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeOversized(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte(" "), maxEventBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
