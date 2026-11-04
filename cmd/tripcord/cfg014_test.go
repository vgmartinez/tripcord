package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/cfg014"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/policy"
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

func TestCfg014PathCap(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	overRepo, overBase, overHead := commitCursorRules(t, git, 65)
	underRepo, underBase, underHead := commitCursorRules(t, git, 10)

	t.Run("sixty five rules and a hook deny", func(t *testing.T) {
		code, stdout, stderr, output := runCfg014(t, overRepo, "empty-reviews.json", overBase, overHead, "text")
		if code != int(exitcode.Findings) {
			t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		assertPathCapReport(t, stdout, 64, 2)
		if !strings.Contains(output, "tc_cfg_014=match\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
	t.Run("over the cap without reviews still denies", func(t *testing.T) {
		code, stdout, stderr, _ := runCfg014(t, overRepo, "no-reviews.json", overBase, overHead, "text")
		if code != int(exitcode.Findings) {
			t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(stderr, "incomplete") || strings.Contains(stdout, "tc-cfg-014: incomplete") {
			t.Fatalf("over-cap missing reviews stayed incomplete\nstderr: %s\nstdout: %s", stderr, stdout)
		}
		assertPathCapReport(t, stdout, 64, 2)
	})
	t.Run("human approval clears a change past the cap", func(t *testing.T) {
		code, stdout, stderr, output := runCfg014(t, overRepo, "human-approved.json", overBase, overHead, "text")
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(stdout, "tc-cfg-014:") || strings.Contains(output, "tc_cfg_014=") {
			t.Fatalf("approval was reported\nstdout: %s\noutput: %s", stdout, output)
		}
	})
	t.Run("ten rules and a hook stay a full match", func(t *testing.T) {
		code, stdout, stderr, _ := runCfg014(t, underRepo, "empty-reviews.json", underBase, underHead, "text")
		if code != int(exitcode.Findings) {
			t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		section := cfg014Section(t, stdout)
		if strings.Contains(section, "and ") || strings.Contains(section, " more") {
			t.Fatalf("below-cap report has an overflow line:\n%s", section)
		}
		cited := citedPaths(section)
		if len(cited) != 11 {
			t.Fatalf("cited %d paths, want 11\n%s", len(cited), section)
		}
		if cited[0] != ".cursor/hooks.json" || cited[10] != ".cursor/rules/pad-10.md" {
			t.Fatalf("cited range = %s .. %s", cited[0], cited[10])
		}
	})
	t.Run("ten rules without reviews stay incomplete", func(t *testing.T) {
		code, stdout, stderr, _ := runCfg014(t, underRepo, "no-reviews.json", underBase, underHead, "text")
		if code != int(exitcode.Config) {
			t.Fatalf("exit %d, want 3\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if !strings.Contains(stderr, "TC-CFG-014 incomplete: review data is not available") {
			t.Fatalf("stderr = %s", stderr)
		}
	})
}

func commitCursorRules(t *testing.T, git string, rules int) (repo, base, head string) {
	t.Helper()
	repo = initRepo(t)
	base = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
	if err := os.MkdirAll(filepath.Join(repo, ".cursor", "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "hooks.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= rules; i++ {
		name := fmt.Sprintf("pad-%02d.md", i)
		if err := os.WriteFile(filepath.Join(repo, ".cursor", "rules", name), []byte("# pad\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGitCmd(t, git, repo, "add", ".cursor")
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "add cursor config")
	head = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	return repo, base, head
}

func assertPathCapReport(t *testing.T, stdout string, citedN, omitted int) {
	t.Helper()
	section := cfg014Section(t, stdout)
	if !strings.HasPrefix(section, "tc-cfg-014: match\n") {
		t.Fatalf("section = %s", section)
	}
	cited := citedPaths(section)
	if len(cited) != citedN {
		t.Fatalf("cited %d paths, want %d\n%s", len(cited), citedN, section)
	}
	if cited[0] != ".cursor/hooks.json" {
		t.Fatalf("first cited = %s", cited[0])
	}
	last := fmt.Sprintf(".cursor/rules/pad-%02d.md", citedN-1)
	if cited[citedN-1] != last {
		t.Fatalf("last cited = %s, want %s", cited[citedN-1], last)
	}
	for n := citedN; n < citedN+omitted; n++ {
		omittedPath := fmt.Sprintf("pad-%02d.md", n)
		if strings.Contains(section, omittedPath) {
			t.Fatalf("report cites omitted %s\n%s", omittedPath, section)
		}
	}
	suffix := fmt.Sprintf("and %d more\n", omitted)
	if !strings.Contains(section, suffix) {
		t.Fatalf("report missing %q\n%s", suffix, section)
	}
}

func cfg014Section(t *testing.T, stdout string) string {
	t.Helper()
	i := strings.Index(stdout, "tc-cfg-014:")
	if i < 0 {
		t.Fatalf("stdout has no tc-cfg-014 section:\n%s", stdout)
	}
	return stdout[i:]
}

func citedPaths(section string) []string {
	var cited []string
	for _, line := range strings.Split(section, "\n") {
		if path, ok := strings.CutPrefix(line, "- "); ok {
			cited = append(cited, path)
		}
	}
	return cited
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
		reviews := writeTemp(t, "reviews.json", `[{"state":"APPROVED","commit_id":"`+head+`","user":{"login":"Ada","type":"User"}}]`)
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
		reviews := writeTemp(t, "reviews.json", `[{"state":"approved","commit_id":"`+head+`","user":{"login":"Ada","type":"User"}}]`)
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
	t.Run("stale approval does not clear", func(t *testing.T) {
		for _, commitID := range []string{base, "0123456789abcdef0123456789abcdef01234567"} {
			body := `[{"state":"APPROVED","commit_id":"` + commitID + `","user":{"login":"Ada","type":"User"}}]`
			reviews := writeTemp(t, "reviews.json", body)
			code, stdout, stderr, _ := runCfg014Args(t, repo, event, "text", "--reviews-file", reviews)
			if code != int(exitcode.Findings) {
				t.Fatalf("commit %s exit %d, want 1\nstderr: %s\nstdout: %s", commitID, code, stderr, stdout)
			}
		}
	})
	t.Run("changes requested after approval does not clear", func(t *testing.T) {
		body := `[
			{"state":"APPROVED","commit_id":"` + head + `","submitted_at":"2026-01-01T00:00:00Z","user":{"login":"Ada","type":"User"}},
			{"state":"CHANGES_REQUESTED","commit_id":"` + head + `","submitted_at":"2026-01-02T00:00:00Z","user":{"login":"Ada","type":"User"}}
		]`
		reviews := writeTemp(t, "reviews.json", body)
		code, stdout, stderr, _ := runCfg014Args(t, repo, event, "text", "--reviews-file", reviews)
		if code != int(exitcode.Findings) {
			t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
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

func TestCfg014PolicyOnBaseDoesNotFailBelowItsThreshold(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	cases := []struct {
		name     string
		body     string
		decision string
	}{
		{name: "audit mode", body: "version: 1\nmode: audit\n", decision: "audit"},
		{name: "fail-on critical", body: "version: 1\nmode: enforce\nfail-on: critical\n", decision: "deny"},
		{name: "extends on base", body: "version: 1\nextends: ./floor.yaml\n", decision: "audit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := initRepo(t)
			files := map[string]string{".tripcord/policy.yaml": tc.body}
			if tc.name == "extends on base" {
				files[".tripcord/floor.yaml"] = "version: 1\nmode: audit\n"
			}
			commitFiles(t, git, repo, "base policy", files)
			base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
			checkoutHooks(t, git, repo)
			head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
			code, stdout, stderr, output := runCfg014(t, repo, "empty-reviews.json", base, head, "json")
			if code != int(exitcode.OK) {
				t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
			}
			assertCfg014Decision(t, stdout, output, tc.decision)
		})
	}
}

func TestCfg014PullRequestPolicyCannotWeakenTheRule(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	cases := []struct {
		name  string
		files map[string]string
	}{
		{name: "audit mode", files: map[string]string{".tripcord/policy.yaml": "version: 1\nmode: audit\n"}},
		{name: "fail-on critical", files: map[string]string{".tripcord/policy.yaml": "version: 1\nmode: enforce\nfail-on: critical\n"}},
		{name: "policy.local.yaml", files: map[string]string{".tripcord/policy.local.yaml": "version: 1\nmode: audit\n"}},
		{name: "extends changed on the pull request", files: map[string]string{".tripcord/floor.yaml": "version: 1\nmode: audit\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := initRepo(t)
			if tc.name == "extends changed on the pull request" {
				commitFiles(t, git, repo, "base floor", map[string]string{
					".tripcord/policy.yaml": "version: 1\nextends: ./floor.yaml\n",
					".tripcord/floor.yaml":  "version: 1\nmode: enforce\nfail-on: high\n",
				})
			}
			base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
			runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
			files := map[string]string{".cursor/hooks.json": "{}\n"}
			for rel, body := range tc.files {
				files[rel] = body
			}
			commitFiles(t, git, repo, "agent change", files)
			head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
			code, stdout, stderr, output := runCfg014(t, repo, "empty-reviews.json", base, head, "json")
			if code != int(exitcode.Findings) {
				t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
			}
			assertCfg014Decision(t, stdout, output, "deny")
		})
	}
}

func TestCfg014AbsentBasePolicyUsesDefaults(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	repo := initRepo(t)
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	effective, err := loadPrContextPolicyFrom(context.Background(), repo, base, "")
	if err != nil {
		t.Fatalf("absent policy: %v", err)
	}
	if effective.Mode != policy.ModeEnforce || effective.FailOn != "high" {
		t.Fatalf("mode=%s fail-on=%s, want enforce/high", effective.Mode, effective.FailOn)
	}
	checkoutHooks(t, git, repo)
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	code, stdout, stderr, output := runCfg014(t, repo, "empty-reviews.json", base, head, "json")
	if code != int(exitcode.Findings) {
		t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	assertCfg014Decision(t, stdout, output, "deny")
}

func TestCfg014OrgLockBeatsBaseAudit(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	repo := initRepo(t)
	commitFiles(t, git, repo, "audit base", map[string]string{
		".tripcord/policy.yaml": "version: 1\nmode: audit\n",
	})
	base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	managed := filepath.Join(t.TempDir(), "managed.yaml")
	if err := os.WriteFile(managed, []byte("version: 1\nmode: enforce\nlocked:\n  mode: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadPrContextPolicyFrom(context.Background(), repo, base, managed)
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("org lock err = %v, want a mode lock", err)
	}
	var pol *policy.Error
	if !errors.As(err, &pol) || pol.ExitCode() != exitcode.Config {
		t.Fatalf("err = %v, want a policy config error", err)
	}
}

func commitFiles(t *testing.T, git, repo, message string, files map[string]string) {
	t.Helper()
	var paths []string
	for rel, body := range files {
		full := filepath.Join(repo, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, rel)
	}
	args := append([]string{"add", "--"}, paths...)
	runGitCmd(t, git, repo, args...)
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", message)
}

func checkoutHooks(t *testing.T, git, repo string) {
	t.Helper()
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
	commitFiles(t, git, repo, "add hooks", map[string]string{".cursor/hooks.json": "{}\n"})
}

func assertCfg014Decision(t *testing.T, stdout, output, decision string) {
	t.Helper()
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
	if got.TCCFG014 != "match" || got.Finding.Severity != "high" || got.Finding.Decision != decision {
		t.Fatalf("decoded = %+v, want decision %s", got, decision)
	}
	if !strings.Contains(output, "tc_cfg_014=match\n") {
		t.Fatalf("GITHUB_OUTPUT = %q", output)
	}
}

func TestCfg014ControlCharacterPaths(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	paths := []string{
		".cursor/hooks.json\n::error::injected",
		".cursor/hooks.json\r::error::injected",
		".cursor/hooks.json\x1b::error::injected",
	}
	for _, rel := range paths {
		t.Run(rel, func(t *testing.T) {
			repo := initRepo(t)
			base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
			runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
			blobFile := filepath.Join(t.TempDir(), "blob")
			if err := os.WriteFile(blobFile, []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			blob := strings.TrimSpace(gitOut(t, git, repo, "hash-object", "-w", blobFile))
			info := "100644 " + blob + " 0\t" + rel + "\x00"
			cmd := exec.Command(git, "update-index", "-z", "--index-info")
			cmd.Dir = repo
			cmd.Stdin = strings.NewReader(info)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("update-index: %v\n%s", err, out)
			}
			runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "odd path")
			head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
			event := writeCfg014Event(t, "empty-reviews.json", base, head)
			for _, format := range []string{"text", "gha"} {
				code, stdout, stderr, _ := runCfg014Args(t, repo, event, format)
				if code != int(exitcode.Config) {
					t.Fatalf("%s exit %d, want 3\nstderr: %s\nstdout: %s", format, code, stderr, stdout)
				}
				if strings.Contains(stdout, "::error::") || strings.Contains(stderr, "::error::") || strings.ContainsRune(stdout, 0x1b) || strings.ContainsRune(stderr, 0x1b) {
					t.Fatalf("%s leaked a workflow command\nstdout: %q\nstderr: %q", format, stdout, stderr)
				}
				if strings.Contains(stdout, "\r") || strings.Contains(stderr, rel) {
					t.Fatalf("%s echoed the path\nstdout: %q\nstderr: %q", format, stdout, stderr)
				}
			}
		})
	}
}

func TestCfg014TextRedactsControlPaths(t *testing.T) {
	for _, path := range []string{"a\n::error::x", "a\r::error::x", "a\x1b::error::x"} {
		out := formatCfg014Text(cfg014.Outcome{Status: cfg014.StatusMatch, Paths: []string{path}})
		if strings.Contains(out, "::error::") || strings.Contains(out, "\r") || strings.ContainsRune(out, 0x1b) || strings.Contains(out, path) {
			t.Fatalf("leaked %q in %q", path, out)
		}
		if !strings.Contains(out, "[path omitted]") {
			t.Fatalf("out = %q", out)
		}
	}
}

func TestCfg014CoveredSymlinks(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)

	t.Run("added symlink at a covered directory matches", func(t *testing.T) {
		repo, base, head := commitAgentChange(t, git, func(repo string) {
			if err := os.Symlink("payload", filepath.Join(repo, ".claude")); err != nil {
				t.Fatal(err)
			}
			runGitCmd(t, git, repo, "add", "--", ".claude")
		})
		code, stdout, stderr, _ := runCfg014(t, repo, "empty-reviews.json", base, head, "text")
		if code != int(exitcode.Findings) || !strings.Contains(stdout, ".claude") {
			t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
	})
	t.Run("symlink outside a covered directory is clear", func(t *testing.T) {
		repo, base, head := commitAgentChange(t, git, func(repo string) {
			if err := os.Symlink("payload", filepath.Join(repo, "notes")); err != nil {
				t.Fatal(err)
			}
			runGitCmd(t, git, repo, "add", "--", "notes")
		})
		code, stdout, stderr, _ := runCfg014(t, repo, "empty-reviews.json", base, head, "text")
		if code != int(exitcode.OK) || strings.Contains(stdout, "tc-cfg-014:") {
			t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
	})
	t.Run("instruction file symlink target matches", func(t *testing.T) {
		repo := initRepo(t)
		if err := os.MkdirAll(filepath.Join(repo, "docs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "docs", "guide.md"), []byte("guide\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("docs/guide.md", filepath.Join(repo, "CLAUDE.md")); err != nil {
			t.Fatal(err)
		}
		runGitCmd(t, git, repo, "add", "--", "docs/guide.md", "CLAUDE.md")
		runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "link claude.md")
		base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
		runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
		if err := os.WriteFile(filepath.Join(repo, "docs", "guide.md"), []byte("edited\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		runGitCmd(t, git, repo, "add", "--", "docs/guide.md")
		runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "edit guide")
		head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
		code, stdout, stderr, _ := runCfg014(t, repo, "empty-reviews.json", base, head, "text")
		if code != int(exitcode.Findings) || !strings.Contains(stdout, "CLAUDE.md") {
			t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
	})
	t.Run("edits under an existing symlink target match", func(t *testing.T) {
		repo := initRepo(t)
		if err := os.MkdirAll(filepath.Join(repo, "payload"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "payload", "keep.txt"), []byte("keep\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("payload", filepath.Join(repo, ".claude")); err != nil {
			t.Fatal(err)
		}
		runGitCmd(t, git, repo, "add", "--", "payload", ".claude")
		runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "link claude")
		base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
		runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
		if err := os.WriteFile(filepath.Join(repo, "payload", "settings.json"), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		runGitCmd(t, git, repo, "add", "--", "payload/settings.json")
		runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "edit target")
		head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
		code, stdout, stderr, _ := runCfg014(t, repo, "empty-reviews.json", base, head, "text")
		if code != int(exitcode.Findings) || !strings.Contains(stdout, ".claude/settings.json") {
			t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
	})
	t.Run("unresolved symlink is incomplete", func(t *testing.T) {
		repo, base, head := commitAgentChange(t, git, func(repo string) {
			if err := os.Symlink("../outside", filepath.Join(repo, ".claude")); err != nil {
				t.Fatal(err)
			}
			runGitCmd(t, git, repo, "add", "--", ".claude")
		})
		// The added symlink is also a hit. Point the base tree at an
		// unresolvable link and change an ordinary file on the branch
		// so the incomplete result comes from resolution, and repeat
		// with the link only to be sure an escaping target does not pass.
		code, stdout, stderr, _ := runCfg014(t, repo, "empty-reviews.json", base, head, "text")
		if code != int(exitcode.Config) || !strings.Contains(stderr, "could not resolve symlink") {
			t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(stdout, "../outside") {
			t.Fatalf("target leaked: %s", stdout)
		}
	})
	t.Run("gitlink at a covered directory matches", func(t *testing.T) {
		repo := initRepo(t)
		base := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
		runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
		sha := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
		cmd := exec.Command(git, "update-index", "-z", "--index-info")
		cmd.Dir = repo
		cmd.Stdin = strings.NewReader("160000 " + sha + " 0\t.cursor\x00")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("update-index: %v\n%s", err, out)
		}
		runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "gitlink")
		head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
		code, stdout, stderr, _ := runCfg014(t, repo, "empty-reviews.json", base, head, "text")
		if code != int(exitcode.Findings) || !strings.Contains(stdout, ".cursor") {
			t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
	})
}

func commitAgentChange(t *testing.T, git string, change func(repo string)) (repo, base, head string) {
	t.Helper()
	repo = initRepo(t)
	base = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
	change(repo)
	runGitCmd(t, git, repo, "-c", "user.email=ada@example.com", "-c", "user.name=Ada Lovelace", "commit", "-q", "-m", "change")
	head = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	return repo, base, head
}

func TestCfg014AnyBotWithoutMarkingTheAgentVerdict(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)

	t.Run("dependabot author", func(t *testing.T) {
		repo, base, head := commitHooks(t, git, "Ada Lovelace", "ada@example.com", "Ada Lovelace", "ada@example.com", "add hooks")
		assertBotMatch(t, repo, base, head, "dependabot[bot]", "Bot", "feature/hooks")
	})
	t.Run("github-actions committer", func(t *testing.T) {
		repo, base, head := commitHooks(t, git, "Ada Lovelace", "ada@example.com", "github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com", "add hooks")
		assertBotMatch(t, repo, base, head, "octocat", "User", "feature/hooks")
	})
	t.Run("dependabot trailer", func(t *testing.T) {
		msg := "add hooks\n\nCo-authored-by: dependabot[bot] <dependabot[bot]@users.noreply.github.com>\n"
		repo, base, head := commitHooks(t, git, "Ada Lovelace", "ada@example.com", "Ada Lovelace", "ada@example.com", msg)
		assertBotMatch(t, repo, base, head, "octocat", "User", "feature/hooks")
	})
}

func commitHooks(t *testing.T, git, author, authorEmail, committer, committerEmail, message string) (repo, base, head string) {
	t.Helper()
	repo = initRepo(t)
	base = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	runGitCmd(t, git, repo, "checkout", "-q", "-b", "feature/hooks")
	if err := os.MkdirAll(filepath.Join(repo, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".cursor", "hooks.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitCmd(t, git, repo, "add", "--", ".cursor/hooks.json")
	cmd := exec.Command(git, "commit", "-q", "-m", message)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME="+author,
		"GIT_AUTHOR_EMAIL="+authorEmail,
		"GIT_COMMITTER_NAME="+committer,
		"GIT_COMMITTER_EMAIL="+committerEmail,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	head = strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	return repo, base, head
}

func assertBotMatch(t *testing.T, repo, base, head, login, authorType, branch string) {
	t.Helper()
	body := `{"pull_request":{"user":{"login":"` + login + `","type":"` + authorType + `"},"head":{"ref":"` + branch + `","sha":"` + head + `"},"base":{"sha":"` + base + `"}},"reviews":[]}`
	event := writeTemp(t, "event.json", body)
	code, stdout, stderr, output := runCfg014Args(t, repo, event, "text")
	if code != int(exitcode.Findings) {
		t.Fatalf("exit %d, want 1\nstderr: %s\nstdout: %s", code, stderr, stdout)
	}
	if !strings.Contains(stdout, "agent: false\n") || !strings.Contains(stdout, "tc-cfg-014: match\n") {
		t.Fatalf("stdout = %s", stdout)
	}
	if !strings.Contains(output, "is_agent=false\n") || strings.Contains(output, "is_agent=true") || !strings.Contains(output, "tc_cfg_014=match\n") {
		t.Fatalf("GITHUB_OUTPUT = %q", output)
	}
}

func TestCfg014MissingBaseIsIncompleteOnlyInScope(t *testing.T) {
	clearPrContextEnv(t)
	git := lookGit(t)
	repo := initRepo(t)
	head := strings.TrimSpace(gitOut(t, git, repo, "rev-parse", "HEAD"))
	missing := "0123456789abcdef0123456789abcdef01234567"

	t.Run("agent author", func(t *testing.T) {
		code, stdout, stderr, output := runMissingBase(t, repo, missing, head, "claude[bot]", "Bot")
		if code != int(exitcode.Config) {
			t.Fatalf("exit %d, want 3\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if !strings.Contains(stderr, "TC-CFG-014 incomplete:") || !strings.Contains(stderr, "changed paths could not be read") {
			t.Fatalf("stderr = %s", stderr)
		}
		if !strings.Contains(output, "is_agent=true\n") || !strings.Contains(output, "tc_cfg_014=incomplete\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
	t.Run("dependabot author", func(t *testing.T) {
		code, stdout, stderr, output := runMissingBase(t, repo, missing, head, "dependabot[bot]", "Bot")
		if code != int(exitcode.Config) || !strings.Contains(stderr, "changed paths could not be read") {
			t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(output, "is_agent=true") || !strings.Contains(output, "is_agent=false\n") || !strings.Contains(output, "tc_cfg_014=incomplete\n") {
			t.Fatalf("GITHUB_OUTPUT = %q", output)
		}
	})
	t.Run("human author", func(t *testing.T) {
		code, stdout, stderr, output := runMissingBase(t, repo, missing, head, "octocat", "User")
		if code != int(exitcode.OK) {
			t.Fatalf("exit %d, want 0\nstderr: %s\nstdout: %s", code, stderr, stdout)
		}
		if strings.Contains(stdout, "tc-cfg-014:") || strings.Contains(output, "tc_cfg_014=") {
			t.Fatalf("human missing base was incomplete\nstdout: %s\noutput: %s", stdout, output)
		}
		if !strings.Contains(stdout, "not in this clone") {
			t.Fatalf("stdout = %s", stdout)
		}
	})
}

func runMissingBase(t *testing.T, repo, base, head, login, authorType string) (int, string, string, string) {
	t.Helper()
	body := `{"pull_request":{"user":{"login":"` + login + `","type":"` + authorType + `"},"head":{"ref":"feature/docs","sha":"` + head + `"},"base":{"sha":"` + base + `"}}}`
	event := writeTemp(t, "event.json", body)
	return runCfg014Args(t, repo, event, "text")
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
