// Package preopen fetches a repository into a private temporary directory
// without running anything the repository controls, so it can be scanned
// before anyone opens it in an editor or a coding agent.
//
// The repository is cloned bare (no work tree, so no checkout), and its
// HEAD tree is then written out from the object database with ls-tree
// and cat-file. That path never consults .gitattributes, so no clean,
// smudge, or process filter driver (including Git LFS) can run, never
// checks out a submodule, and never reaches a hook: a bare clone has no
// checkout to trigger post-checkout, and hooks are disabled besides.
// Every Git invocation also gets a sanitized environment and -c
// overrides (see gitEnv and gitConfig) that ignore the user's global and
// system configuration, deny every transport other than https, ssh, and
// file, and disable credential helpers, prompts, templates, and fsmonitor.
package preopen

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Limits bound what a fetched tree may write to disk. A shallow clone is
// already downloaded by the time the tree is known, but a small pack can
// still expand into a very large tree, so materialize stops at these.
const (
	MaxEntries    = 200_000
	MaxTotalBytes = 1 << 30
	// maxPathComponents matches the scan's nesting depth (kit.MaxNesting).
	maxPathComponents = 64
	// maxPathBytes is the longest tree-relative path, in bytes.
	maxPathBytes = 4096
)

// maxEntries and maxTotalBytes are the budgets materialize enforces.
// Tests lower them so a hostile tree can be small.
var (
	maxEntries    = MaxEntries
	maxTotalBytes = int64(MaxTotalBytes)
)

// ErrGitMissing reports that git could not be found or started.
var ErrGitMissing = errors.New("git is not installed")

// TargetError reports a target preopen refuses or cannot fetch: an
// unsupported transport, a path that does not exist, or a failed clone.
type TargetError struct {
	Target string
	Err    error
}

func (e *TargetError) Error() string { return fmt.Sprintf("%q: %v", e.Target, e.Err) }

func (e *TargetError) Unwrap() error { return e.Err }

// Workspace is a fetched repository. Tree holds its HEAD tree; Close
// removes everything Fetch created.
type Workspace struct {
	dir  string
	tree string
}

// Tree is the directory holding the fetched HEAD tree. It contains no
// .git directory.
func (w *Workspace) Tree() string { return w.tree }

// Dir is the temporary directory that holds the clone and the tree.
func (w *Workspace) Dir() string { return w.dir }

// Close removes the workspace. It is safe to call more than once.
func (w *Workspace) Close() error {
	if w == nil || w.dir == "" {
		return nil
	}
	err := removeAll(w.dir)
	if err == nil {
		w.dir = ""
	}
	return err
}

// Fetch clones target into a new directory under os.TempDir and writes
// out its HEAD tree. target is an https, ssh, or file URL, an scp-style
// ssh address (host:path), or a local path, which is cloned through the
// file transport like any other repository rather than read in place.
// On any error, including ctx being cancelled, everything Fetch created
// is removed before it returns.
func Fetch(ctx context.Context, target string) (ws *Workspace, err error) {
	url, err := resolveTarget(target)
	if err != nil {
		return nil, &TargetError{Target: target, Err: err}
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	dir, err := os.MkdirTemp("", "tripcord-preopen-")
	if err != nil {
		return nil, err
	}
	created := &Workspace{dir: dir, tree: filepath.Join(dir, "tree")}
	defer func() {
		if err != nil {
			_ = created.Close()
		}
	}()
	gitDir := filepath.Join(dir, "git")
	if err := clone(ctx, git, url, gitDir); err != nil {
		return nil, wrapGitError(target, err)
	}
	if err := os.Mkdir(created.tree, 0o700); err != nil {
		return nil, err
	}
	if err := materialize(ctx, git, gitDir, created.tree); err != nil {
		// An interrupt kills cat-file, and the write then fails with a
		// broken pipe. Report the interrupt instead of that write error.
		return nil, preferCancel(ctx, wrapTreeError(target, err))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return created, nil
}

// preferCancel reports ctx's error when the context is already done.
// The tree error is returned only when the fetch was not interrupted.
func preferCancel(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

func wrapGitError(target string, err error) error {
	var exitErr *gitExitError
	if errors.As(err, &exitErr) {
		return &TargetError{Target: target, Err: err}
	}
	return err
}

// wrapTreeError reports a tree preopen refuses to write as a TargetError.
// That includes an unsafe path, a tree over the limits, and a path the
// operating system rejects (ENAMETOOLONG). Cancellation and a missing
// git stay as they are.
func wrapTreeError(target string, err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, ErrGitMissing):
		return err
	}
	return &TargetError{Target: target, Err: err}
}

// resolveTarget returns the URL to clone. Every transport other than
// https, ssh, and file is refused here, before git runs, and again by
// gitConfig's protocol.allow settings when it does.
func resolveTarget(target string) (string, error) {
	switch {
	case target == "":
		return "", errors.New("target is empty")
	case strings.HasPrefix(target, "-"):
		return "", errors.New("target must not start with '-'")
	case strings.ContainsAny(target, "\x00\r\n"):
		return "", errors.New("target must not contain a control character")
	}
	if info, err := os.Stat(target); err == nil {
		if !info.IsDir() {
			return "", errors.New("local target is not a directory")
		}
		abs, err := filepath.Abs(target)
		if err != nil {
			return "", err
		}
		p := filepath.ToSlash(abs)
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return "file://" + p, nil
	}
	if scheme, _, ok := strings.Cut(target, "://"); ok {
		switch strings.ToLower(scheme) {
		case "https", "ssh", "file":
			return target, nil
		default:
			return "", fmt.Errorf("transport %q is not allowed; use https, ssh, file, or a local path", scheme)
		}
	}
	if strings.Contains(target, "::") {
		return "", errors.New("remote-helper (transport::address) targets such as ext:: are not allowed")
	}
	if host, _, ok := strings.Cut(target, ":"); ok && host != "" && !strings.Contains(host, "/") && !isDriveLetter(host) {
		return target, nil
	}
	return "", errors.New("not a local directory or an https, ssh, or file URL")
}

func isDriveLetter(s string) bool {
	return runtime.GOOS == "windows" && len(s) == 1 && (s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z')
}

// gitConfig is passed with -c to every git invocation. Command-line
// configuration outranks every config file, and gitEnv already keeps
// the global and system files from being read at all.
func gitConfig() []string {
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

// gitEnv is the environment for git. Every inherited GIT_* variable is
// dropped (GIT_CONFIG_PARAMETERS, GIT_CONFIG_COUNT, GIT_SSH_COMMAND,
// GIT_ASKPASS, GIT_TEMPLATE_DIR, GIT_EXEC_PATH, ...), as is SSH_ASKPASS,
// so neither the caller's environment nor its config files can add a
// hook, helper, or filter. GIT_ALLOW_PROTOCOL repeats the transport
// allowlist in the form older git releases read.
func gitEnv() []string {
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

// gitExitError is a git command that ran and failed.
type gitExitError struct {
	op     string
	detail string
	err    error
}

func (e *gitExitError) Error() string {
	if e.detail != "" {
		return fmt.Sprintf("git %s failed: %s", e.op, e.detail)
	}
	return fmt.Sprintf("git %s failed: %v", e.op, e.err)
}

func (e *gitExitError) Unwrap() error { return e.err }

func command(ctx context.Context, git string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, git, append(gitConfig(), args...)...)
	cmd.Env = gitEnv()
	cmd.Stdin = nil
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func runGit(cmd *exec.Cmd, op string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, &gitExitError{op: op, detail: sanitize(stderr.String()), err: err}
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	return out, nil
}

// sanitize keeps git's diagnostic to one bounded line.
func sanitize(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	s = strings.ReplaceAll(s, "\n", "; ")
	const limit = 1024
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}

// clone makes a shallow, bare, single-branch clone of url in gitDir. A
// bare clone has no work tree, so nothing is checked out: no smudge
// filter, no post-checkout hook, and no submodule.
func clone(ctx context.Context, git, url, gitDir string) error {
	cmd := command(ctx, git, "clone",
		"--bare",
		"--depth", "1",
		"--single-branch",
		"--no-tags",
		"--template=",
		"--quiet",
		"--", url, gitDir)
	if _, err := runGit(cmd, "clone"); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return ctx.Err()
}

type treeEntry struct {
	mode string
	kind string
	oid  string
	path string
}

// materialize writes gitDir's HEAD tree into tree. Blobs come from
// cat-file --batch, which returns raw object content and never applies
// a filter or textconv. Submodules become empty directories, as an
// uninitialized submodule is in a normal checkout.
func materialize(ctx context.Context, git, gitDir, tree string) error {
	if _, err := runGit(command(ctx, git, "--git-dir", gitDir, "rev-parse", "--verify", "--quiet", "HEAD^{tree}"), "rev-parse"); err != nil {
		var exitErr *gitExitError
		if errors.As(err, &exitErr) {
			return nil // empty repository: an empty tree
		}
		return err
	}
	raw, err := runGit(command(ctx, git, "--git-dir", gitDir, "ls-tree", "-r", "-z", "--full-tree", "HEAD"), "ls-tree")
	if err != nil {
		return err
	}
	entries, err := parseLsTree(raw)
	if err != nil {
		return err
	}
	if len(entries) > maxEntries {
		return fmt.Errorf("tree has %d entries, more than the %d preopen writes", len(entries), maxEntries)
	}
	// catCtx is cancelled when writing the tree fails. cat-file --batch
	// writes the whole object before it reads the next request, so leaving
	// an over-budget blob unread blocks it on the stdout pipe and Wait
	// never returns. Cancelling kills the process before Wait.
	catCtx, cancelCat := context.WithCancel(ctx)
	defer cancelCat()
	cat := command(catCtx, git, "--git-dir", gitDir, "cat-file", "--batch")
	stdin, err := cat.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cat.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cat.Stderr = &stderr
	if err := cat.Start(); err != nil {
		return fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	writeErr := writeEntries(ctx, entries, tree, stdin, bufio.NewReader(stdout))
	if writeErr != nil {
		cancelCat()
	}
	_ = stdin.Close()
	waitErr := cat.Wait()
	if writeErr != nil {
		return preferCancel(ctx, writeErr)
	}
	if waitErr != nil {
		return &gitExitError{op: "cat-file", detail: sanitize(stderr.String()), err: waitErr}
	}
	return nil
}

func parseLsTree(raw []byte) ([]treeEntry, error) {
	var entries []treeEntry
	for _, rec := range bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, ok := bytes.Cut(rec, []byte{'\t'})
		if !ok {
			return nil, fmt.Errorf("unexpected ls-tree record %q", rec)
		}
		fields := strings.Fields(string(meta))
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected ls-tree record %q", rec)
		}
		entries = append(entries, treeEntry{mode: fields[0], kind: fields[1], oid: fields[2], path: string(path)})
	}
	return entries, nil
}

func writeEntries(ctx context.Context, entries []treeEntry, tree string, req io.Writer, resp *bufio.Reader) error {
	var total int64
	// used counts file entries and every directory ensureParents creates.
	// ls-tree -r does not list intermediate trees, so a few entries can
	// otherwise expand into hundreds of thousands of directories.
	var used int
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		dest, err := entryPath(tree, e.path)
		if err != nil {
			return err
		}
		if err := ensureParents(tree, dest, &used); err != nil {
			return err
		}
		if err := chargeEntry(&used); err != nil {
			return err
		}
		if e.kind == "commit" {
			if err := os.Mkdir(dest, 0o755); err != nil {
				return fmt.Errorf("tree entry %q: %w", e.path, err)
			}
			continue
		}
		if e.kind != "blob" {
			return fmt.Errorf("tree entry %q: unexpected object type %q", e.path, e.kind)
		}
		data, err := readBlob(req, resp, e.oid, maxTotalBytes-total)
		if err != nil {
			return fmt.Errorf("tree entry %q: %w", e.path, err)
		}
		total += int64(len(data))
		if err := writeEntry(dest, e, data); err != nil {
			return fmt.Errorf("tree entry %q: %w", e.path, err)
		}
	}
	return nil
}

func readBlob(req io.Writer, resp *bufio.Reader, oid string, budget int64) ([]byte, error) {
	if _, err := io.WriteString(req, oid+"\n"); err != nil {
		return nil, err
	}
	header, err := resp.ReadString('\n')
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(header)
	if len(fields) != 3 || fields[0] != oid || fields[1] != "blob" {
		return nil, fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(header))
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return nil, fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(header))
	}
	if size > budget {
		return nil, fmt.Errorf("tree is larger than the %d bytes preopen writes", maxTotalBytes)
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(resp, data); err != nil {
		return nil, err
	}
	if data[size] != '\n' {
		return nil, errors.New("unexpected cat-file framing")
	}
	return data[:size], nil
}

// entryPath maps a tree path to its destination under tree. A path git
// would refuse to check out is refused here too: an empty, ".", or ".."
// component, a .git directory under any spelling a case-insensitive or
// Windows filesystem treats as .git, or a separator Windows would read.
func entryPath(tree, p string) (string, error) {
	if p == "" || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("tree entry %q: unsafe path", p)
	}
	parts := strings.Split(p, "/")
	for _, part := range parts {
		trimmed := strings.TrimRight(part, ". ")
		switch {
		case part == "", part == ".", part == "..":
			return "", fmt.Errorf("tree entry %q: unsafe path", p)
		case strings.EqualFold(trimmed, ".git"), strings.EqualFold(part, "git~1"):
			return "", fmt.Errorf("tree entry %q: unsafe path", p)
		case runtime.GOOS == "windows" && strings.ContainsAny(part, `\:`):
			return "", fmt.Errorf("tree entry %q: unsafe path", p)
		}
	}
	if len(parts) > maxPathComponents {
		return "", fmt.Errorf("tree entry %q: path has %d components, more than %d", p, len(parts), maxPathComponents)
	}
	if len(p) > maxPathBytes {
		return "", fmt.Errorf("tree entry %q: path is %d bytes, more than %d", p, len(p), maxPathBytes)
	}
	return filepath.Join(tree, filepath.FromSlash(p)), nil
}

func chargeEntry(used *int) error {
	if *used+1 > maxEntries {
		return fmt.Errorf("tree has more than the %d entries preopen writes", maxEntries)
	}
	*used++
	return nil
}

// ensureParents creates dest's parent directories under tree. A parent
// that already exists must be a real directory preopen created: a
// symlink or file there means the tree aliases one path onto another
// (a malformed tree, or a case-insensitive filesystem), and writing
// through it could land outside tree.
func ensureParents(tree, dest string, used *int) error {
	rel, err := filepath.Rel(tree, filepath.Dir(dest))
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	cur := tree
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := chargeEntry(used); err != nil {
				return err
			}
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case !info.IsDir():
			return fmt.Errorf("tree entry %q: parent %q is not a directory", dest, part)
		}
	}
	return nil
}

func writeEntry(dest string, e treeEntry, data []byte) error {
	switch e.mode {
	case "120000":
		if bytes.IndexByte(data, 0) >= 0 {
			return errors.New("symlink target contains NUL")
		}
		if err := os.Symlink(string(data), dest); err != nil {
			if runtime.GOOS != "windows" {
				return err
			}
			// Without symlink privilege, write the target as text, as
			// git does with core.symlinks=false.
			return writeFile(dest, data, 0o644)
		}
		return nil
	case "100755":
		return writeFile(dest, data, 0o755)
	case "100644", "100664":
		return writeFile(dest, data, 0o644)
	default:
		return fmt.Errorf("unexpected file mode %s", e.mode)
	}
}

func writeFile(dest string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// removeAll is os.RemoveAll that also clears read-only bits (git writes
// pack files 0444, which Windows will not delete) and retries once.
func removeAll(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink == 0 {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}
