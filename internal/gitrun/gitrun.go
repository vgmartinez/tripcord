// Package gitrun invokes git with the hardened environment and -c
// overrides used to read or fetch a repository without running anything
// it controls: no hooks, no inherited Git configuration, no credential
// helper, no prompt, and no transport other than https, ssh, and file.
//
// Both pr-context (internal/prcontext) and preopen (internal/preopen)
// build their git invocations on this package, so the hardening lives
// in one place.
package gitrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrNotInstalled reports that git could not be found or started.
var ErrNotInstalled = errors.New("git is not installed")

// ExitError is a git command that ran and failed. Stderr is one bounded line.
type ExitError struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *ExitError) Error() string {
	if e.Stderr != "" {
		return "git " + strings.Join(e.Args, " ") + " failed: " + e.Stderr
	}
	return fmt.Sprintf("git %s failed: %v", strings.Join(e.Args, " "), e.Err)
}

func (e *ExitError) Unwrap() error { return e.Err }

// ConfigArgs is the -c overrides prepended to every git invocation.
// Command-line configuration outranks every config file, and Env already
// keeps the global and system files from being read.
func ConfigArgs() []string {
	null := os.DevNull
	pairs := []string{
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
	}
	args := make([]string, 0, 2*len(pairs))
	for _, p := range pairs {
		args = append(args, "-c", p)
	}
	return args
}

// Env is the environment for git. Every inherited GIT_* variable is
// dropped, as is SSH_ASKPASS, so neither the caller's environment nor its
// config files can add a hook, helper, or filter.
func Env() []string {
	env := make([]string, 0, len(os.Environ())+8)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_") || upper == "SSH_ASKPASS" || upper == "SSH_ASKPASS_REQUIRE" {
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_ALLOW_PROTOCOL=https:ssh:file",
		"GIT_PROTOCOL_FROM_USER=0",
	)
}

// Command builds a git command in repo (or the current directory, when
// repo is empty) with ConfigArgs and Env applied. Stdin is closed.
func Command(ctx context.Context, repo string, args ...string) (*exec.Cmd, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotInstalled, err)
	}
	full := make([]string, 0, len(ConfigArgs())+len(args))
	full = append(full, ConfigArgs()...)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, git, full...)
	if repo != "" {
		cmd.Dir = repo
	}
	cmd.Env = Env()
	cmd.Stdin = nil
	cmd.WaitDelay = 5 * time.Second
	return cmd, nil
}

// Run runs git and returns its stdout.
func Run(ctx context.Context, repo string, args ...string) ([]byte, error) {
	cmd, err := Command(ctx, repo, args...)
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, &ExitError{Args: args, Stderr: Sanitize(stderr.String()), Err: err}
		}
		return nil, fmt.Errorf("%w: %w", ErrNotInstalled, err)
	}
	return out, nil
}

// Sanitize keeps a git diagnostic to one bounded line, for a caller
// building its own ExitError around a command this package did not run
// end to end (for example one using Command for streaming I/O).
func Sanitize(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	s = strings.ReplaceAll(s, "\n", "; ")
	const limit = 1024
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}
