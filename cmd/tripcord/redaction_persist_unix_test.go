//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/model"
)

// TestRedactionCanaryNothingPersisted: scan, the hook run through
// bootstrap.sh, and init write no event or excerpt anywhere. After
// each, no file that is new or changed under the repository, HOME, the
// bootstrap cache, or TMPDIR holds a canary, except a settings file
// init merged into, which keeps the user's own content, and the cache's
// .run directory of private binary copies is empty.
func TestRedactionCanaryNothingPersisted(t *testing.T) {
	e := newEmbedE2E(t)
	raw, err := os.ReadFile(e.bin)
	if err != nil {
		t.Fatal(err)
	}
	e.fillCache(t, raw)
	tmp := t.TempDir()
	t.Setenv("HOME", e.home)
	t.Setenv("XDG_CACHE_HOME", e.cache)
	t.Setenv("TMPDIR", tmp)
	src := canaryRepo(t, encodePlain)
	mcp, err := os.ReadFile(filepath.Join(src, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, e.repo, ".mcp.json", string(mcp))
	writeTestFile(t, e.repo, embedded.PolicyPath, canaryMessagePolicy("enforce", encodePlain))

	roots := map[string]string{"repo": e.repo, "HOME": e.home, "cache": e.cache, "TMPDIR": tmp}
	persisted := func(t *testing.T, step string, run func(), merged ...string) {
		t.Helper()
		before := map[string]map[string]string{}
		for name, dir := range roots {
			before[name] = snapshot(t, dir)
		}
		run()
		for name, dir := range roots {
			for rel, content := range snapshot(t, dir) {
				old, existed := before[name][rel]
				if existed && old == content || !strings.Contains(content, "CNRY") {
					continue
				}
				if name == "repo" && existed && containsAll(old, content) {
					continue
				}
				t.Errorf("%s wrote a canary to %s %s", step, name, rel)
			}
		}
		runs := filepath.Join(e.cache, "tripcord", ".run")
		entries, err := os.ReadDir(runs)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, entry := range entries {
			t.Errorf("%s left %s in %s", step, entry.Name(), runs)
		}
	}

	persisted(t, "scan", func() {
		for _, format := range []string{"json", "jsonl", "sarif", "text", "gha", "md"} {
			code, stdout, stderr := runCLI(t, "scan", "--format", format, e.repo)
			if code != int(exitcode.Findings) {
				t.Errorf("scan %s: exit %d stderr %q", format, code, stderr)
			}
			assertNoCanary(t, "scan "+format, stdout+stderr)
		}
	})

	persisted(t, "hook", func() {
		for _, in := range hookCanaryInputs() {
			if in.event != hook.EventPreTool {
				continue
			}
			command := e.hookCommand(t, in.harness)
			env := map[model.Harness][]string{
				model.HarnessClaude: {"CLAUDE_PROJECT_DIR=" + e.repo},
				model.HarnessCursor: {"CURSOR_PROJECT_DIR=" + e.repo},
			}[in.harness]
			env = append(env, "TMPDIR="+tmp)
			for _, c := range redactionCanaries {
				code, stdout, stderr := e.runHookCommand(t, command, e.repo, env, []byte(in.stdin(jsonString(c.text))))
				if code != int(exitcode.Block) {
					t.Errorf("%s %s: exit %d stderr %q", in.harness, c.class, code, stderr)
				}
				assertHookOutputClean(t, string(in.harness)+" "+c.class, stdout, stderr)
			}
		}
	})

	if _, err := os.Stat(filepath.Join(e.cache, "tripcord", ".run")); err != nil {
		t.Fatalf("the hook did not run through a private copy: %v", err)
	}

	settings := filepath.Join(e.repo, ".claude", "settings.json")
	wired, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, e.repo, ".claude/settings.json", strings.Replace(string(wired), "{\n", "{\n  \"env\": {\"SECRET_KEY\": \"CNRYENVA7Q2W\"},\n", 1))
	persisted(t, "init", func() {
		code, stdout, stderr := runCLI(t, "init", "--embed", "--force", "--version", "0.1.0", "--sha256", e.platform+"="+sha256Hex(raw), e.repo)
		if code != 0 {
			t.Errorf("init: exit %d stderr %q", code, stderr)
		}
		assertNoCanary(t, "init", stdout+stderr)
	})
}

// containsAll reports whether every canary in content was already in
// old: a merge kept the user's text and added none.
func containsAll(old, content string) bool {
	for _, c := range redactionCanaries {
		if strings.Contains(content, c.secret) && !strings.Contains(old, c.secret) {
			return false
		}
	}
	return true
}
