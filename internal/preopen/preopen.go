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
// Every Git invocation also gets the sanitized environment and -c
// overrides in internal/gitrun that ignore the user's global and system
// configuration, deny every transport other than https, ssh, and file,
// and disable credential helpers, prompts, templates, and fsmonitor.
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

	"github.com/vgmartinez/tripcord/internal/gitrun"
)

// Limits bound what a fetched tree may write to disk. The clone uses a
// blob size filter so large binaries are not downloaded, but a small
// pack can still expand into a very large tree of placeholders and
// regular files, so materialize checks the budget before writing and
// stops at these.
const (
	MaxEntries    = 200_000
	MaxTotalBytes = 1 << 30
	// maxPathComponents matches the scan's nesting depth (kit.MaxNesting).
	maxPathComponents = 64
	// maxPathBytes is the longest tree-relative path, in bytes.
	maxPathBytes = 4096
	// blobFilterLimit is the git partial-clone blob limit, and equals
	// adapters.MaxConfigFileBytes. Blobs larger than this are omitted
	// from the clone (--filter=blob:limit=1m) and written as a
	// placeholder of blobFilterLimit+1 bytes so the scan sees them as
	// too large and does not read them.
	blobFilterLimit = 1 << 20
	blobFilterSpec  = "blob:limit=1m"
)

// maxEntries and maxTotalBytes are the budgets materialize enforces.
// Tests lower them so a hostile tree can be small.
var (
	maxEntries    = MaxEntries
	maxTotalBytes = int64(MaxTotalBytes)
)

// ErrGitMissing reports that git could not be found or started. It is
// internal/gitrun's ErrNotInstalled under this package's own name, kept
// so existing callers of this exported var are unaffected.
var ErrGitMissing = gitrun.ErrNotInstalled

// TargetError reports a target preopen refuses or cannot fetch: an
// unsupported transport, a path that does not exist, or a failed clone.
type TargetError struct {
	Target string
	Err    error
}

func (e *TargetError) Error() string { return fmt.Sprintf("%q: %v", e.Target, e.Err) }

func (e *TargetError) Unwrap() error { return e.Err }

// Workspace is a fetched repository. Tree holds its HEAD tree; Close
// removes everything Fetch created. gitDir and index are set for a staged
// workspace so later referenced paths can be added without listing again.
type Workspace struct {
	dir          string
	tree         string
	gitDir       string
	index        map[string]IndexObject
	placeholders int
}

// IndexObject is one git index record. Kind is "blob" or "commit"
// (a gitlink). Target is symlink text when Mode is 120000.
type IndexObject struct {
	Mode   string
	OID    string
	Path   string
	Kind   string
	Target string
	Size   int64
	Sparse int64
}

// Tree is the directory holding the fetched HEAD tree. It contains no
// .git directory.
func (w *Workspace) Tree() string {
	if w == nil {
		return ""
	}
	return w.tree
}

// Index is the staged index remembered for a workspace opened from the
// index. It is nil for a preopen fetch.
func (w *Workspace) Index() map[string]IndexObject {
	if w == nil {
		return nil
	}
	return w.index
}

// Dir is the temporary directory that holds the clone and the tree.
func (w *Workspace) Dir() string { return w.dir }

// Placeholders is the number of blobs Fetch wrote as sized holes
// because they were filtered or larger than the configuration cap.
// Those files are not scanned.
func (w *Workspace) Placeholders() int {
	if w == nil {
		return 0
	}
	return w.placeholders
}

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
func Fetch(ctx context.Context, target string) (*Workspace, error) {
	return FetchWithProgress(ctx, target, nil)
}

// FetchWithProgress is Fetch, and when progress is non-nil it writes
// short status lines ("cloning ...", "writing N files ...").
func FetchWithProgress(ctx context.Context, target string, progress io.Writer) (ws *Workspace, err error) {
	url, err := resolveTarget(target)
	if err != nil {
		return nil, &TargetError{Target: target, Err: err}
	}
	// Checked up front, rather than left to the first gitrun call, so a
	// missing git fails before anything is created under os.TempDir.
	if _, err := exec.LookPath("git"); err != nil {
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
	logProgress(progress, "cloning ...")
	if err := clone(ctx, url, gitDir); err != nil {
		return nil, wrapGitError(target, err)
	}
	if err := os.Mkdir(created.tree, 0o700); err != nil {
		return nil, err
	}
	n, err := materialize(ctx, gitDir, created.tree, progress)
	if err != nil {
		// An interrupt kills cat-file, and the write then fails with a
		// broken pipe. Report the interrupt instead of that write error.
		return nil, preferCancel(ctx, wrapTreeError(target, err))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	created.placeholders = n
	return created, nil
}

func logProgress(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	_, _ = fmt.Fprintf(w, format+"\n", args...)
}

// ListIndex reads the staged index. Blobs are not written. A gitlink is
// kind "commit", the same empty directory a checkout leaves for an
// uninitialized submodule. Unmerged paths are rejected.
// indexFile, when set, is the index git is building for a commit
// currently in a hook (see gitrun.IndexEnv): ls-files then reads that
// proposed commit's content instead of the stale on-disk .git/index. An
// empty indexFile reads .git/index, as a direct, non-hook invocation
// would.
func ListIndex(ctx context.Context, repo, indexFile string) (objs []IndexObject, gitDir string, err error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	raw, err := gitrun.RunIndexed(ctx, repo, indexFile, "--no-optional-locks", "ls-files", "--stage", "-z")
	if err != nil {
		return nil, "", err
	}
	entries, err := parseIndex(raw)
	if err != nil {
		return nil, "", err
	}
	gitDirRaw, err := gitrun.Run(ctx, repo, "--no-optional-locks", "rev-parse", "--git-dir")
	if err != nil {
		return nil, "", err
	}
	gitDir = strings.TrimSpace(string(gitDirRaw))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(repo, gitDir)
	}
	objs = make([]IndexObject, len(entries))
	for i, e := range entries {
		objs[i] = IndexObject{Mode: e.mode, OID: e.oid, Path: e.path, Kind: e.kind}
	}
	return objs, gitDir, nil
}

// StagedChangeSet reports every repository-relative path that differs
// between HEAD (or, on the first commit, the empty tree) and the index
// at indexFile: added, modified, deleted, type-changed (for example a
// symlink retargeted, or a file replaced by a symlink), and
// mode-changed entries alike. `tripcord scan --staged` unions this set
// with any paths the caller passed. pre-commit's default types: [file]
// filter never names a symlink or a staged deletion, and a commit that
// only touches one of those would otherwise be invisible; diff-index
// still lists them. indexFile, when set, is the index git is building
// for a commit currently in a hook (see gitrun.IndexEnv); an empty
// indexFile reads .git/index, as a direct, non-hook invocation would.
func StagedChangeSet(ctx context.Context, repo, indexFile string) (map[string]bool, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	treeish, err := diffBase(ctx, repo, indexFile)
	if err != nil {
		return nil, err
	}
	// --no-optional-locks keeps this read from refreshing the index.
	// Refreshing takes .git/index.lock and rewrites the cache-tree, which
	// races with anything else reading that checkout, including another
	// test process.
	raw, err := gitrun.RunIndexed(ctx, repo, indexFile, "--no-optional-locks", "diff-index", "--cached", "--name-status", "-z", "--no-renames", treeish)
	if err != nil {
		return nil, err
	}
	return parseNameStatus(raw)
}

// RefRangeChangeSet reports every repository-relative path that differs
// between from and to, the way pre-commit 4.7.0 chooses files for
// `pre-commit run --from-ref FROM --to-ref TO` (see
// pre_commit/git.py get_changed_files). That function runs
// `git diff --name-only -z FROM...TO` — the three-dot form, changes on
// TO since the merge base with FROM — and, only when that command
// fails (newer git has no merge base for unrelated histories), falls
// back to `FROM..TO`. This uses the same pair, with --name-status and
// --no-renames so a rename is a deletion plus an addition and the
// deleted path is still in the set. Deletions are included;
// pre-commit's own filename filter drops them because the path no
// longer exists. The diff is of the two trees, not of the index.
func RefRangeChangeSet(ctx context.Context, repo, from, to string) (map[string]bool, error) {
	if err := validRevision(from); err != nil {
		return nil, err
	}
	if err := validRevision(to); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	raw, err := gitrun.Run(ctx, repo, "--no-optional-locks", "diff", "--name-status", "-z", "--no-renames", from+"..."+to, "--")
	if err != nil {
		var exitErr *gitrun.ExitError
		if !errors.As(err, &exitErr) {
			return nil, err
		}
		raw, err = gitrun.Run(ctx, repo, "--no-optional-locks", "diff", "--name-status", "-z", "--no-renames", from+".."+to, "--")
		if err != nil {
			return nil, err
		}
	}
	return parseNameStatus(raw)
}

// validRevision rejects a revision that could be read as a git option
// or that carries a control character. pre-commit passes the caller's
// --from-ref and --to-ref through unchanged; they are still one
// argument each, not a shell string.
func validRevision(rev string) error {
	if rev == "" || strings.HasPrefix(rev, "-") || strings.ContainsAny(rev, "\x00\n\r") {
		return fmt.Errorf("invalid revision %q", rev)
	}
	return nil
}

// diffBase is the tree-ish StagedChangeSet diffs the index against: HEAD,
// or, when the branch has no commit yet, the empty tree. mktree with no
// input reads the empty tree's own OID back from git itself, rather than
// a hardcoded constant, so it works the same under either hash algorithm
// a repository might use. gitrun.Command already leaves a command's
// stdin unset, which os/exec connects to the null device, giving mktree
// no entries to read.
func diffBase(ctx context.Context, repo, indexFile string) (string, error) {
	if _, err := gitrun.RunIndexed(ctx, repo, indexFile, "--no-optional-locks", "rev-parse", "--verify", "--quiet", "HEAD"); err != nil {
		var exitErr *gitrun.ExitError
		if errors.As(err, &exitErr) {
			raw, err := gitrun.Run(ctx, repo, "mktree", "--missing")
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(raw)), nil
		}
		return "", err
	}
	return "HEAD", nil
}

// parseNameStatus parses `git diff-index --name-status -z --no-renames`
// output into the set of changed paths: NUL-terminated status/path
// pairs, one status letter per record since renames and copies are
// disabled. The status letter itself (A, M, D, T, or a mode-only M) is
// not needed: every category StagedChangeSet documents is reported by
// its path alone.
func parseNameStatus(raw []byte) (map[string]bool, error) {
	out := map[string]bool{}
	fields := bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0})
	for i := 0; i < len(fields); {
		if len(fields[i]) == 0 {
			i++
			continue
		}
		status := fields[i]
		i++
		if i >= len(fields) {
			return nil, fmt.Errorf("unexpected diff-index record %q: missing path", status)
		}
		path := fields[i]
		i++
		if len(path) == 0 {
			return nil, fmt.Errorf("unexpected diff-index record %q: empty path", status)
		}
		out[string(path)] = true
	}
	return out, nil
}

// ReadBlobs returns raw object bytes for oids. The objects are not filters.
func ReadBlobs(ctx context.Context, gitDir string, oids []string) (map[string][]byte, error) {
	return catBatch(ctx, gitDir, oids, false)
}

// startCatFileWrites writes each oid to stdin in a goroutine and closes
// stdin when the list is sent. The caller must read stdout concurrently:
// writing the whole list first can fill the pipe and deadlock against
// unread responses.
func startCatFileWrites(ctx context.Context, stdin io.WriteCloser, oids []string) <-chan error {
	done := make(chan error, 1)
	go func() {
		var err error
		for _, oid := range oids {
			if ctx.Err() != nil {
				err = ctx.Err()
				break
			}
			if _, werr := io.WriteString(stdin, oid+"\n"); werr != nil {
				err = werr
				break
			}
		}
		if cerr := stdin.Close(); err == nil {
			err = cerr
		}
		done <- err
	}()
	return done
}

// BlobSizes returns object sizes without reading the bytes.
func BlobSizes(ctx context.Context, gitDir string, oids []string) (map[string]int64, error) {
	if len(oids) == 0 {
		return map[string]int64{}, nil
	}
	catCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cat, err := gitrun.Command(catCtx, "", "--git-dir", gitDir, "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	stdin, err := cat.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cat.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cat.Stderr = &stderr
	if err := cat.Start(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	out := map[string]int64{}
	writeDone := startCatFileWrites(catCtx, stdin, oids)
	resp := bufio.NewReader(stdout)
	var writeErr error
	for _, oid := range oids {
		line, err := resp.ReadString('\n')
		if err != nil {
			writeErr = err
			break
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 3 || fields[0] != oid || fields[1] != "blob" {
			writeErr = fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(line))
			break
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 {
			writeErr = fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(line))
			break
		}
		out[oid] = size
	}
	if writeErr != nil {
		cancel()
	}
	if werr := <-writeDone; writeErr == nil {
		writeErr = werr
	}
	waitErr := cat.Wait()
	if writeErr != nil {
		return nil, preferCancel(ctx, writeErr)
	}
	if waitErr != nil {
		return nil, &gitrun.ExitError{Args: []string{"cat-file"}, Stderr: gitrun.Sanitize(stderr.String()), Err: waitErr}
	}
	return out, nil
}

func catBatch(ctx context.Context, gitDir string, oids []string, _ bool) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(oids) == 0 {
		return out, nil
	}
	catCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cat, err := gitrun.Command(catCtx, "", "--git-dir", gitDir, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	stdin, err := cat.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cat.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cat.Stderr = &stderr
	if err := cat.Start(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	resp := bufio.NewReader(stdout)
	var writeErr error
	for _, oid := range oids {
		if ctx.Err() != nil {
			writeErr = ctx.Err()
			break
		}
		data, err := readBlob(stdin, resp, oid, maxTotalBytes)
		if err != nil {
			writeErr = err
			break
		}
		out[oid] = data
	}
	if writeErr != nil {
		cancel()
	}
	_ = stdin.Close()
	waitErr := cat.Wait()
	if writeErr != nil {
		return nil, preferCancel(ctx, writeErr)
	}
	if waitErr != nil {
		return nil, &gitrun.ExitError{Args: []string{"cat-file"}, Stderr: gitrun.Sanitize(stderr.String()), Err: waitErr}
	}
	return out, nil
}

// NewStagedTree creates an empty private tree and remembers every index
// object so referenced paths can be added later.
func NewStagedTree(objs []IndexObject, gitDir string) (*Workspace, error) {
	dir, err := os.MkdirTemp("", "tripcord-staged-")
	if err != nil {
		return nil, err
	}
	ws := &Workspace{dir: dir, tree: filepath.Join(dir, "tree"), gitDir: gitDir, index: map[string]IndexObject{}}
	if err := os.Mkdir(ws.tree, 0o700); err != nil {
		_ = ws.Close()
		return nil, err
	}
	for _, obj := range objs {
		ws.index[obj.Path] = obj
	}
	return ws, nil
}

// Put writes objs into the tree. Content objects are read from git.
// Sparse objects are sized holes, so a scan sees the real size without
// the bytes. Gitlinks become empty directories.
func (w *Workspace) Put(ctx context.Context, objs []IndexObject) error {
	if w == nil {
		return errors.New("nil workspace")
	}
	entries := make([]treeEntry, len(objs))
	for i, obj := range objs {
		kind := obj.Kind
		if kind == "" {
			kind = "blob"
		}
		if obj.Mode == "160000" {
			kind = "commit"
		}
		entries[i] = treeEntry{mode: obj.Mode, kind: kind, oid: obj.OID, path: obj.Path, sparse: obj.Sparse}
	}
	if err := materializeEntries(ctx, w.gitDir, w.tree, entries); err != nil {
		return preferCancel(ctx, err)
	}
	return ctx.Err()
}

func parseIndex(raw []byte) ([]treeEntry, error) {
	var entries []treeEntry
	for _, rec := range bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, path, ok := bytes.Cut(rec, []byte{'\t'})
		if !ok {
			return nil, fmt.Errorf("unexpected index record %q", rec)
		}
		fields := strings.Fields(string(meta))
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected index record %q", rec)
		}
		if fields[2] != "0" {
			return nil, fmt.Errorf("index has unmerged path %q", path)
		}
		kind := "blob"
		if fields[0] == "160000" {
			kind = "commit"
		}
		entries = append(entries, treeEntry{mode: fields[0], kind: kind, oid: fields[1], path: string(path)})
	}
	return entries, nil
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
	var exitErr *gitrun.ExitError
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
// gitrun.ConfigArgs' protocol.allow settings when it does.
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

// clone makes a shallow, bare, single-branch clone of url in gitDir. A
// bare clone has no work tree, so nothing is checked out: no smudge
// filter, no post-checkout hook, and no submodule. --filter=blob:limit=1m
// omits blobs larger than the configuration cap; GIT_NO_LAZY_FETCH=1
// (set by gitrun) keeps a filtered blob from being fetched later. A
// server that does not honor the filter, such as a file:// source
// without uploadpack.allowFilter, ignores it and the clone falls back
// to fetching every blob. gitrun.Run applies the hardened environment
// and -c overrides shared with pr-context.
func clone(ctx context.Context, url, gitDir string) error {
	if _, err := gitrun.Run(ctx, "", "clone",
		"--bare",
		"--depth", "1",
		"--single-branch",
		"--no-tags",
		"--template=",
		"--filter="+blobFilterSpec,
		"--quiet",
		"--", url, gitDir); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return ctx.Err()
}

type treeEntry struct {
	mode   string
	kind   string
	oid    string
	path   string
	sparse int64
}

// materialize writes gitDir's HEAD tree into tree. Blobs come from
// cat-file --batch, which returns raw object content and never applies
// a filter or textconv. Submodules become empty directories, as an
// uninitialized submodule is in a normal checkout.
func materialize(ctx context.Context, gitDir, tree string, progress io.Writer) (int, error) {
	if _, err := gitrun.Run(ctx, "", "--git-dir", gitDir, "rev-parse", "--verify", "--quiet", "HEAD^{tree}"); err != nil {
		var exitErr *gitrun.ExitError
		if errors.As(err, &exitErr) {
			return 0, nil // empty repository: an empty tree
		}
		return 0, err
	}
	raw, err := gitrun.Run(ctx, "", "--git-dir", gitDir, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
	if err != nil {
		return 0, err
	}
	entries, err := parseLsTree(raw)
	if err != nil {
		return 0, err
	}
	placeholders, err := classifyEntries(ctx, gitDir, entries)
	if err != nil {
		return 0, err
	}
	if placeholders > 0 {
		logProgress(progress, "writing %d files (%d oversized blobs as placeholders) ...", len(entries), placeholders)
	} else {
		logProgress(progress, "writing %d files ...", len(entries))
	}
	if err := materializeEntries(ctx, gitDir, tree, entries); err != nil {
		return 0, err
	}
	return placeholders, nil
}

type blobInfo struct {
	size    int64
	missing bool
}

// classifyEntries marks filtered or over-cap blobs as placeholders of
// blobFilterLimit+1 bytes and fails immediately if the bytes that would
// actually be written exceed the budget.
func classifyEntries(ctx context.Context, gitDir string, entries []treeEntry) (int, error) {
	var oids []string
	seen := make(map[string]bool)
	for _, e := range entries {
		if e.kind == "blob" && e.sparse == 0 && !seen[e.oid] {
			seen[e.oid] = true
			oids = append(oids, e.oid)
		}
	}
	info, err := inspectBlobs(ctx, gitDir, oids)
	if err != nil {
		return 0, err
	}
	var total int64
	var placeholders int
	for i, e := range entries {
		if e.kind != "blob" || e.sparse > 0 {
			continue
		}
		b, ok := info[e.oid]
		if !ok {
			return 0, fmt.Errorf("tree entry %q: missing cat-file result for %s", e.path, e.oid)
		}
		var n int64
		if b.missing || b.size > blobFilterLimit {
			entries[i].sparse = blobFilterLimit + 1
			placeholders++
			n = blobFilterLimit + 1
		} else {
			n = b.size
		}
		if total+n > maxTotalBytes {
			return 0, fmt.Errorf("tree is larger than the %d bytes preopen writes", maxTotalBytes)
		}
		total += n
	}
	return placeholders, nil
}

// inspectBlobs reports each oid's size, or that it is missing (a
// filtered blob under GIT_NO_LAZY_FETCH=1).
func inspectBlobs(ctx context.Context, gitDir string, oids []string) (map[string]blobInfo, error) {
	out := map[string]blobInfo{}
	if len(oids) == 0 {
		return out, nil
	}
	catCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cat, err := gitrun.Command(catCtx, "", "--git-dir", gitDir, "cat-file", "--batch-check")
	if err != nil {
		return nil, err
	}
	stdin, err := cat.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cat.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cat.Stderr = &stderr
	if err := cat.Start(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGitMissing, err)
	}
	writeDone := startCatFileWrites(catCtx, stdin, oids)
	resp := bufio.NewReader(stdout)
	var writeErr error
	for _, oid := range oids {
		line, err := resp.ReadString('\n')
		if err != nil {
			writeErr = err
			break
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && fields[0] == oid && fields[1] == "missing" {
			out[oid] = blobInfo{missing: true}
			continue
		}
		if len(fields) != 3 || fields[0] != oid || fields[1] != "blob" {
			writeErr = fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(line))
			break
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 {
			writeErr = fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(line))
			break
		}
		out[oid] = blobInfo{size: size}
	}
	if writeErr != nil {
		cancel()
	}
	if werr := <-writeDone; writeErr == nil {
		writeErr = werr
	}
	waitErr := cat.Wait()
	if writeErr != nil {
		return nil, preferCancel(ctx, writeErr)
	}
	if waitErr != nil {
		return nil, &gitrun.ExitError{Args: []string{"cat-file"}, Stderr: gitrun.Sanitize(stderr.String()), Err: waitErr}
	}
	return out, nil
}

func materializeEntries(ctx context.Context, gitDir, tree string, entries []treeEntry) error {
	if len(entries) > maxEntries {
		return fmt.Errorf("tree has %d entries, more than the %d preopen writes", len(entries), maxEntries)
	}
	// catCtx is cancelled when writing the tree fails. cat-file --batch
	// writes the whole object before it reads the next request, so leaving
	// an over-budget blob unread blocks it on the stdout pipe and Wait
	// never returns. Cancelling kills the process before Wait.
	catCtx, cancelCat := context.WithCancel(ctx)
	defer cancelCat()
	cat, err := gitrun.Command(catCtx, "", "--git-dir", gitDir, "cat-file", "--batch")
	if err != nil {
		return err
	}
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
		return &gitrun.ExitError{Args: []string{"cat-file"}, Stderr: gitrun.Sanitize(stderr.String()), Err: waitErr}
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
		if e.kind == "commit" || e.mode == "160000" {
			if err := os.Mkdir(dest, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("tree entry %q: %w", e.path, err)
			}
			continue
		}
		if e.sparse > 0 {
			if e.sparse > maxTotalBytes-total {
				return fmt.Errorf("tree is larger than the %d bytes preopen writes", maxTotalBytes)
			}
			if err := sparseFile(dest, e.sparse); err != nil {
				return fmt.Errorf("tree entry %q: %w", e.path, err)
			}
			total += e.sparse
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
	case "160000":
		return os.Mkdir(dest, 0o755)
	default:
		return fmt.Errorf("unexpected file mode %s", e.mode)
	}
}

func sparseFile(dest string, size int64) error {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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
