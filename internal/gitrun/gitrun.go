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
	"path/filepath"
	"strings"
	"time"

	"github.com/vgmartinez/tripcord/internal/output"
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
// config files can add a hook, helper, or filter, and a stray
// GIT_INDEX_FILE left over in the process environment (for example from
// a parent git hook invocation) cannot redirect an unrelated index read
// onto that other index.
// GIT_CEILING_DIRECTORIES is kept. It only stops discovery from walking
// above a directory; it does not select config, hooks, or a different
// repository. Tests set it so a temp directory inside a checkout is not
// read as that checkout.
// A caller that must read the index git is building for the commit
// currently in a hook (plain, -a, a pathspec, --only, or --include) uses
// IndexEnv, RunIndexed, or CommandIndexed instead of this function, so
// that only the specific calls which need the proposed commit's content
// see GIT_INDEX_FILE, not every git invocation this package makes.
func Env() []string {
	ceiling := os.Getenv("GIT_CEILING_DIRECTORIES")
	env := make([]string, 0, len(os.Environ())+8)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GIT_") || upper == "SSH_ASKPASS" || upper == "SSH_ASKPASS_REQUIRE" {
			continue
		}
		env = append(env, entry)
	}
	env = append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_ALLOW_PROTOCOL=https:ssh:file",
		"GIT_PROTOCOL_FROM_USER=0",
	)
	if ceiling != "" {
		env = append(env, "GIT_CEILING_DIRECTORIES="+ceiling)
	}
	return env
}

// IndexEnv is Env with indexFile overlaid as GIT_INDEX_FILE, resolved to
// an absolute path against the current working directory. Git sets
// GIT_INDEX_FILE during a commit hook (plain, -a, a pathspec, --only, or
// --include) to the lock file or temporary index that holds the
// proposed commit's content, which is not the same as .git/index until
// the hook succeeds; a caller reading the index during such a hook (for
// example ls-files --stage or diff-index --cached) passes that value
// here so it sees the proposed commit instead of the stale on-disk
// index. An empty indexFile returns Env() unchanged, so a caller with no
// hook index (a plain read of .git/index, or any other git invocation)
// is unaffected by a GIT_INDEX_FILE a caller elsewhere in the process
// might have read, since Env no longer carries it.
func IndexEnv(indexFile string) []string {
	env := Env()
	if indexFile == "" {
		return env
	}
	abs := indexFile
	if resolved, err := filepath.Abs(indexFile); err == nil {
		abs = resolved
	}
	return append(env, "GIT_INDEX_FILE="+abs)
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

// CommandIndexed is Command with IndexEnv(indexFile) applied in place of
// Env, for a caller whose git call must see the index git is building
// for a commit currently in a hook. See IndexEnv.
func CommandIndexed(ctx context.Context, repo, indexFile string, args ...string) (*exec.Cmd, error) {
	cmd, err := Command(ctx, repo, args...)
	if err != nil {
		return nil, err
	}
	cmd.Env = IndexEnv(indexFile)
	return cmd, nil
}

// Run runs git and returns its stdout.
func Run(ctx context.Context, repo string, args ...string) ([]byte, error) {
	cmd, err := Command(ctx, repo, args...)
	if err != nil {
		return nil, err
	}
	return runOutput(cmd, args)
}

// RunIndexed is Run with IndexEnv(indexFile) applied in place of Env. See
// IndexEnv.
func RunIndexed(ctx context.Context, repo, indexFile string, args ...string) ([]byte, error) {
	cmd, err := CommandIndexed(ctx, repo, indexFile, args...)
	if err != nil {
		return nil, err
	}
	return runOutput(cmd, args)
}

func runOutput(cmd *exec.Cmd, args []string) ([]byte, error) {
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
// end to end (for example one using Command for streaming I/O). It
// redacts credentials (git quotes a remote URL with its userinfo)
// before the cap, so a cut cannot leave a credential prefix behind.
func Sanitize(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	s = output.DefaultRedactor(strings.ReplaceAll(s, "\n", "; "))
	const limit = 1024
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}
