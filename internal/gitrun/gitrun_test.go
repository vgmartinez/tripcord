package gitrun

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigArgsMatchTheHardenedSet(t *testing.T) {
	t.Parallel()
	null := os.DevNull
	for _, want := range []string{
		"core.hooksPath=" + null,
		"core.fsmonitor=false",
		"core.attributesFile=" + null,
		"core.askPass=",
		"core.sshCommand=ssh -o BatchMode=yes",
		"credential.helper=",
		"init.templateDir=",
		"protocol.allow=never",
		"protocol.https.allow=always",
		"protocol.ssh.allow=always",
		"protocol.file.allow=always",
		"protocol.ext.allow=never",
		"protocol.git.allow=never",
		"submodule.recurse=false",
		"fetch.recurseSubmodules=false",
		"filter.lfs.smudge=",
		"filter.lfs.clean=",
		"filter.lfs.process=",
		"filter.lfs.required=false",
		"transfer.fsckObjects=true",
	} {
		if !containsPair(ConfigArgs(), want) {
			t.Errorf("ConfigArgs lacks %s", want)
		}
	}
}

func containsEnv(env []string, want string) bool {
	for _, entry := range env {
		if entry == want {
			return true
		}
	}
	return false
}

func containsPair(args []string, value string) bool {
	for i := 0; i+1 < len(args); i += 2 {
		if args[i] == "-c" && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestEnvDropsInheritedGitSettings(t *testing.T) {
	t.Setenv("GIT_CONFIG_PARAMETERS", "'alias.log'='!touch /tmp/x'")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/tmp/hooks")
	t.Setenv("GIT_SSH_COMMAND", "sh -c id")
	t.Setenv("GIT_DIR", "/tmp/not-the-repo")
	t.Setenv("GIT_INDEX_FILE", "/tmp/stray-index.lock")
	t.Setenv("SSH_ASKPASS", "/tmp/ask")
	t.Setenv("GIT_CEILING_DIRECTORIES", "/tmp/ceiling")
	env := Env()
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_SSH_COMMAND", "GIT_DIR", "GIT_INDEX_FILE", "SSH_ASKPASS":
			t.Errorf("Env kept %s", key)
		}
	}
	if !containsEnv(env, "GIT_CEILING_DIRECTORIES=/tmp/ceiling") {
		t.Error("Env dropped GIT_CEILING_DIRECTORIES")
	}
	for _, want := range []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_NO_LAZY_FETCH=1",
	} {
		found := false
		for _, entry := range env {
			if entry == want {
				found = true
			}
		}
		if !found {
			t.Errorf("Env lacks %s", want)
		}
	}
}

// TestRunIgnoresStrayGitIndexFile proves that an ordinary (non-indexed)
// git call made through this package never sees a GIT_INDEX_FILE left
// over in the process environment, even one pointing at a file that does
// not exist: Env must drop it globally, so only RunIndexed/CommandIndexed
// opt a specific call into seeing it (see IndexEnv).
func TestRunIgnoresStrayGitIndexFile(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := initRepo(t)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "does-not-exist.lock"))
	out, err := Run(context.Background(), repo, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		t.Fatalf("Run with a stray GIT_INDEX_FILE failed: %v", err)
	}
	if strings.TrimSpace(string(out)) != "true" {
		t.Fatalf("Run output = %q, want true", out)
	}
}

func TestIndexEnvAddsGitIndexFile(t *testing.T) {
	dir := t.TempDir()
	abs := dir + "/index.lock"
	env := IndexEnv(abs)
	if !containsEnv(env, "GIT_INDEX_FILE="+abs) {
		t.Errorf("IndexEnv did not set an already-absolute GIT_INDEX_FILE: %v", env)
	}
}

func TestIndexEnvResolvesRelativePath(t *testing.T) {
	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	env := IndexEnv(".git/index.lock")
	want := dir + "/.git/index.lock"
	if !containsEnv(env, "GIT_INDEX_FILE="+want) {
		t.Errorf("IndexEnv did not resolve a relative path to %s: %v", want, env)
	}
}

func TestIndexEnvEmptyMatchesEnv(t *testing.T) {
	t.Setenv("GIT_INDEX_FILE", "/tmp/stray-index.lock")
	indexed := IndexEnv("")
	for _, entry := range indexed {
		key, _, _ := strings.Cut(entry, "=")
		if strings.ToUpper(key) == "GIT_INDEX_FILE" {
			t.Errorf("IndexEnv(\"\") set GIT_INDEX_FILE: %s", entry)
		}
	}
}

func TestIndexEnvOverridesStrayGitIndexFile(t *testing.T) {
	t.Setenv("GIT_INDEX_FILE", "/tmp/stray-index.lock")
	dir := t.TempDir()
	want := dir + "/real.lock"
	env := IndexEnv(want)
	if !containsEnv(env, "GIT_INDEX_FILE="+want) {
		t.Errorf("IndexEnv did not override an inherited GIT_INDEX_FILE: %v", env)
	}
}

func initRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "--quiet")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	return repo
}

func TestRunIgnoresGlobalConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	// A global identity must not leak into a command that reads config,
	// and a repo alias must not run.
	repo := t.TempDir()
	out, err := Run(context.Background(), repo, "config", "--global", "--get", "user.name")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || len(out) != 0 {
		t.Fatalf("global config read = %q, %v; want a git failure and no value", out, err)
	}
}
