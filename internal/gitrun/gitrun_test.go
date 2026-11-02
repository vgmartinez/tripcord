package gitrun

import (
	"context"
	"errors"
	"os"
	"os/exec"
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
	t.Setenv("SSH_ASKPASS", "/tmp/ask")
	t.Setenv("GIT_CEILING_DIRECTORIES", "/tmp/ceiling")
	env := Env()
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_SSH_COMMAND", "GIT_DIR", "SSH_ASKPASS":
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
