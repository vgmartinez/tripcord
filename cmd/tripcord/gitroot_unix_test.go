//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/model"
)

// TestGitRootCheckAgrees: init --embed and the hook agree on which .git
// makes a repository root, so init never wires a directory the hook
// then cannot find, and the other way round. A worktree's .git file
// counts.
func TestGitRootCheckAgrees(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, git string)
		root bool
	}{
		{"directory", func(t *testing.T, git string) {
			if err := os.Mkdir(git, 0o755); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"worktree file", func(t *testing.T, git string) {
			if err := os.WriteFile(git, []byte("gitdir: /elsewhere/.git/worktrees/w\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"symlink to a directory", func(t *testing.T, git string) {
			real := filepath.Join(t.TempDir(), "real.git")
			if err := os.Mkdir(real, 0o755); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, real, git)
		}, true},
		{"dangling symlink", func(t *testing.T, git string) { mustSymlink(t, filepath.Join(t.TempDir(), "gone"), git) }, false},
		{"fifo", func(t *testing.T, git string) {
			if err := syscall.Mkfifo(git, 0o644); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat("/.git"); err == nil {
				t.Skip("/.git exists, so every directory is in a Git repository")
			}
			initDir, hookDir := outsideGit(t), outsideGit(t)
			tc.make(t, filepath.Join(initDir, ".git"))
			tc.make(t, filepath.Join(hookDir, ".git"))
			writeTestFile(t, hookDir, ".tripcord/policy.yaml", hookTestPolicy)
			if got := repoRoot(hookDir); got != tc.root {
				t.Fatalf("repoRoot = %v, want %v", got, tc.root)
			}
			initCode, _, initErr := runCLI(t, embedArgs("--harness", "claude", initDir)...)
			t.Setenv("CLAUDE_PROJECT_DIR", hookDir)
			hookCode, _, hookErr := runHookCLI(t, bytes.NewReader(adapterFixture(t, model.HarnessClaude, "pre-tool-use-bash-deny.json")), "--harness", "claude", "--event", hook.EventPreTool)
			wantInit, wantHook := int(exitcode.Config), int(exitcode.Config)
			if tc.root {
				wantInit, wantHook = int(exitcode.OK), int(exitcode.Block)
			}
			if initCode != wantInit || hookCode != wantHook {
				t.Fatalf("init exit %d (%s), hook exit %d (%s); want %d and %d", initCode, initErr, hookCode, hookErr, wantInit, wantHook)
			}
		})
	}
}
