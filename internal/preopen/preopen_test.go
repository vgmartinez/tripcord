package preopen

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/gitrun"
	"github.com/vgmartinez/tripcord/internal/preopen/preopentest"
)

// privateTemp points os.TempDir at a fresh directory and returns it, so
// a test can check that Fetch leaves nothing behind.
func privateTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	return dir
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("%s is not empty: %v", dir, names)
	}
}

// TestArmedFixtureTripsNaiveClone is the control: an ordinary clone of
// the fixture, under the same environment, runs every payload. Without
// it, TestFetchRunsNothing could pass because the fixture is inert.
func TestArmedFixtureTripsNaiveClone(t *testing.T) {
	git := preopentest.RequireTools(t)
	a := preopentest.NewArmed(t, git)
	a.Arm(t)
	dst := filepath.Join(t.TempDir(), "naive")
	cmd := exec.Command(git, "clone", "-q", "--recurse-submodules", "file://"+filepath.ToSlash(a.Src), dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("naive clone: %v\n%s", err, out)
	}
	if got := a.Tripped(); !slices.Equal(got, preopentest.Sentinels) {
		t.Fatalf("naive clone tripped %v, want all of %v", got, preopentest.Sentinels)
	}
}

func TestFetchRunsNothing(t *testing.T) {
	git := preopentest.RequireTools(t)
	a := preopentest.NewArmed(t, git)
	tmp := privateTemp(t)
	a.Arm(t)
	for _, target := range []string{a.Src, "file://" + filepath.ToSlash(a.Src)} {
		ws, err := Fetch(context.Background(), target)
		if err != nil {
			t.Fatalf("Fetch(%q): %v", target, err)
		}
		if got := a.Tripped(); len(got) != 0 {
			t.Fatalf("Fetch(%q) ran %v", target, got)
		}
		tree := ws.Tree()
		for path, want := range map[string]string{
			"a.txt":                 "plain text\n",
			"big.bin":               preopentest.LFSPointer,
			".claude/settings.json": preopentest.ClaudeSettings,
		} {
			got, err := os.ReadFile(filepath.Join(tree, filepath.FromSlash(path)))
			if err != nil || string(got) != want {
				t.Errorf("%s = %q, %v; want the committed bytes %q", path, got, err, want)
			}
		}
		if entries, err := os.ReadDir(filepath.Join(tree, "sub")); err != nil || len(entries) != 0 {
			t.Errorf("submodule sub = %v, %v; want an empty, uninitialized directory", entries, err)
		}
		if _, err := os.Lstat(filepath.Join(tree, ".git")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("tree has a .git: %v", err)
		}
		if err := ws.Close(); err != nil {
			t.Fatal(err)
		}
		assertEmpty(t, tmp)
	}
}

func TestFetchRejectsTransports(t *testing.T) {
	preopentest.RequireTools(t)
	tmp := privateTemp(t)
	sentinel := filepath.Join(t.TempDir(), "ext")
	ext := "ext::sh -c touch% " + filepath.ToSlash(sentinel)
	for _, target := range []string{ext, "git://127.0.0.1:9/repo", "http://127.0.0.1:9/repo", "fd::3", "-uhelp", "ssh://h/x\n"} {
		ws, err := Fetch(context.Background(), target)
		var targetErr *TargetError
		if !errors.As(err, &targetErr) {
			_ = ws.Close()
			t.Fatalf("Fetch(%q) = %v, want a TargetError", target, err)
		}
	}
	assertEmpty(t, tmp)

	// The protocol settings refuse ext:: and git:// even when the target
	// check is bypassed.
	for _, url := range []string{ext, "git://127.0.0.1:9/repo"} {
		err := clone(context.Background(), url, filepath.Join(t.TempDir(), "c"))
		var exitErr *gitrun.ExitError
		if !errors.As(err, &exitErr) || !strings.Contains(exitErr.Stderr, "not allowed") {
			t.Errorf("clone(%q) = %v, want git to refuse the transport", url, err)
		}
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("ext:: command ran")
	}
}

func TestFetchCleansUpOnError(t *testing.T) {
	git := preopentest.RequireTools(t)
	tmp := privateTemp(t)
	if _, err := Fetch(context.Background(), "file://"+filepath.ToSlash(filepath.Join(t.TempDir(), "missing"))); err == nil {
		t.Fatal("cloned a missing repository")
	}
	assertEmpty(t, tmp)

	a := preopentest.NewArmed(t, git)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Fetch(ctx, a.Src); !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch with a cancelled context = %v", err)
	}
	assertEmpty(t, tmp)
}

// TestFetchOversizeBlobDoesNotHang is the hostile case: a blob larger
// than the byte budget. readBlob rejects it without consuming the body.
// cat-file is then blocked writing the rest, and Wait must not hang.
func TestFetchOversizeBlobDoesNotHang(t *testing.T) {
	prev := maxTotalBytes
	maxTotalBytes = 64 << 10
	t.Cleanup(func() { maxTotalBytes = prev })

	git := preopentest.RequireTools(t)
	repo := filepath.Join(t.TempDir(), "repo")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "repo")
	blob := make([]byte, 1<<20)
	if err := os.WriteFile(filepath.Join(repo, "a"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	preopentest.Git(t, git, repo, "add", "-A")
	preopentest.Git(t, git, repo, "commit", "-q", "-m", "oversize")

	// The deadline is a backstop so a regression fails the test instead
	// of wedging CI. A fixed run returns as soon as the blob is refused.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	_, err := Fetch(ctx, repo)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Fetch took %s; cat-file was still writing the rejected blob", elapsed)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Fetch hung until the deadline")
	}
	var targetErr *TargetError
	if !errors.As(err, &targetErr) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("Fetch = %v, want a TargetError refusing the blob", err)
	}
}

func TestBlobFilterLimitMatchesConfigCap(t *testing.T) {
	if blobFilterLimit != adapters.MaxConfigFileBytes {
		t.Fatalf("blobFilterLimit = %d, want adapters.MaxConfigFileBytes %d", blobFilterLimit, adapters.MaxConfigFileBytes)
	}
}

// TestFetchFilteredOversizedBlobsArePlaceholders is the case a repository
// of large binaries used to fail: several 2 MiB blobs against a 4 MiB
// budget. With the blob filter and placeholders, Fetch succeeds, the
// config file is written in full, and the large blobs are holes that
// were never downloaded.
func TestFetchFilteredOversizedBlobsArePlaceholders(t *testing.T) {
	prev := maxTotalBytes
	maxTotalBytes = 4 << 20
	t.Cleanup(func() { maxTotalBytes = prev })

	git := preopentest.RequireTools(t)
	repo := filepath.Join(t.TempDir(), "repo")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "repo")
	preopentest.Git(t, git, repo, "config", "uploadpack.allowFilter", "true")
	preopentest.WriteFile(t, filepath.Join(repo, ".claude", "settings.json"), preopentest.ClaudeSettings, 0o644)
	blobs := []string{"a.bin", "b.bin", "c.bin"}
	oids := map[string]string{}
	for _, name := range blobs {
		data := make([]byte, 2<<20)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	preopentest.Git(t, git, repo, "add", "-A")
	preopentest.Git(t, git, repo, "commit", "-q", "-m", "fixture")
	for _, name := range blobs {
		oids[name] = gitOutput(t, git, repo, "", "rev-parse", "HEAD:"+name)
	}

	ws, err := Fetch(context.Background(), repo)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer func() { _ = ws.Close() }()

	got, err := os.ReadFile(filepath.Join(ws.Tree(), ".claude", "settings.json"))
	if err != nil || string(got) != preopentest.ClaudeSettings {
		t.Fatalf(".claude/settings.json = %q, %v; want the committed bytes", got, err)
	}
	for _, name := range blobs {
		info, err := os.Stat(filepath.Join(ws.Tree(), name))
		wantSize := adapters.MaxConfigFileBytes + 1
		if err != nil || info.Size() != wantSize {
			t.Fatalf("%s size = %v, %v; want %d", name, sizeOf(info), err, wantSize)
		}
		if objectExists(t, git, filepath.Join(ws.Dir(), "git"), oids[name]) {
			t.Fatalf("%s oid %s is present in the clone; the blob was downloaded", name, oids[name])
		}
	}
}

func sizeOf(info os.FileInfo) int64 {
	if info == nil {
		return -1
	}
	return info.Size()
}

func objectExists(t *testing.T, git, gitDir, oid string) bool {
	t.Helper()
	cmd := exec.Command(git, "--git-dir", gitDir, "cat-file", "-e", oid)
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "GIT_") {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_NO_LAZY_FETCH=1",
	)
	return cmd.Run() == nil
}

// gitOutput runs git and returns its stdout. stdin may be empty.
func gitOutput(t *testing.T, git, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "GIT_") {
			env = append(env, entry)
		}
	}
	cmd.Env = append(env,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
	)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		detail := ""
		if errors.As(err, &exitErr) {
			detail = string(exitErr.Stderr)
		}
		t.Fatalf("git %v: %v\n%s", args, err, detail)
	}
	return strings.TrimSpace(string(out))
}

// TestFetchLongNameIsTargetError builds a tree whose one name is past
// NAME_MAX without putting that name on disk in the source repository.
// Writing it out returns ENAMETOOLONG, which is a refused tree.
func TestFetchLongNameIsTargetError(t *testing.T) {
	git := preopentest.RequireTools(t)
	repo := filepath.Join(t.TempDir(), "repo.git")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "--bare", "repo.git")
	blob := gitOutput(t, git, repo, "x\n", "hash-object", "-w", "--stdin")
	name := strings.Repeat("n", 300)
	tree := gitOutput(t, git, repo, fmt.Sprintf("100644 blob %s\t%s\x00", blob, name), "mktree", "-z")
	commit := gitOutput(t, git, repo, "", "commit-tree", tree, "-m", "long")
	preopentest.Git(t, git, repo, "update-ref", "HEAD", commit)

	_, err := Fetch(context.Background(), repo)
	var targetErr *TargetError
	if !errors.As(err, &targetErr) || !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Fatalf("Fetch = %v, want a TargetError wrapping ENAMETOOLONG", err)
	}
}

func TestPreferCancelHidesBrokenPipe(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := preferCancel(ctx, errors.New("write: broken pipe"))
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("preferCancel = %v, want context.Canceled", err)
	}
	want := errors.New("tree")
	if got := preferCancel(context.Background(), want); got != want {
		t.Fatalf("preferCancel = %v, want the tree error", got)
	}
}

func TestFetchEmptyRepository(t *testing.T) {
	git := preopentest.RequireTools(t)
	tmp := privateTemp(t)
	src := filepath.Join(t.TempDir(), "empty")
	preopentest.Git(t, git, filepath.Dir(src), "init", "-q", "empty")
	ws, err := Fetch(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	assertEmpty(t, ws.Tree())
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	assertEmpty(t, tmp)
}

func TestResolveTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	preopentest.WriteFile(t, file, "", 0o644)
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"https://example.invalid/r.git", "https://example.invalid/r.git", true},
		{"ssh://git@example.invalid/r.git", "ssh://git@example.invalid/r.git", true},
		{"git@example.invalid:o/r.git", "git@example.invalid:o/r.git", true},
		{"file:///srv/r.git", "file:///srv/r.git", true},
		{"ext::sh -c id", "", false},
		{"fd::3", "", false},
		{"git://example.invalid/r", "", false},
		{"http://example.invalid/r", "", false},
		{"-upload-pack=id", "", false},
		{"", "", false},
		{"no/such/dir", "", false},
		{file, "", false},
	} {
		got, err := resolveTarget(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("resolveTarget(%q) = %q, %v; want %q, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
	got, err := resolveTarget(dir)
	if err != nil || !strings.HasPrefix(got, "file://") || !strings.HasSuffix(got, filepath.ToSlash(dir)) {
		t.Errorf("resolveTarget(local dir) = %q, %v; want a file:// URL", got, err)
	}
}

func TestEntryPathRejectsUnsafePaths(t *testing.T) {
	t.Parallel()
	tree := t.TempDir()
	for _, p := range []string{"", "/etc/passwd", "../x", "a/../../x", "a//b", "./a", ".git/config", "a/.GIT/hooks/x", "a/.git./x", "git~1/config"} {
		if _, err := entryPath(tree, p); err == nil {
			t.Errorf("entryPath(%q) accepted", p)
		}
	}
	for _, p := range []string{"a", ".github/hooks/x.json", "a.git", ".gitattributes", ".gitmodules"} {
		if _, err := entryPath(tree, p); err != nil {
			t.Errorf("entryPath(%q) = %v", p, err)
		}
	}
}

func TestEntryPathRejectsDeepAndLongPaths(t *testing.T) {
	t.Parallel()
	tree := t.TempDir()
	deep := strings.Repeat("d/", maxPathComponents-1) + "f"
	if _, err := entryPath(tree, deep); err != nil {
		t.Fatalf("entryPath(%d components) = %v", maxPathComponents, err)
	}
	deeper := deep + "/g"
	if _, err := entryPath(tree, deeper); err == nil {
		t.Fatalf("entryPath(%d components) accepted", maxPathComponents+1)
	}
	long := strings.Repeat("a", maxPathBytes)
	if _, err := entryPath(tree, long); err != nil {
		t.Fatalf("entryPath(%d bytes) = %v", maxPathBytes, err)
	}
	if _, err := entryPath(tree, long+"b"); err == nil {
		t.Fatalf("entryPath(%d bytes) accepted", maxPathBytes+1)
	}
}

func TestEnsureParentsCountsDirectories(t *testing.T) {
	tree := t.TempDir()
	prev := maxEntries
	maxEntries = 2
	t.Cleanup(func() { maxEntries = prev })
	dest, err := entryPath(tree, "a/b/c/f")
	if err != nil {
		t.Fatal(err)
	}
	used := 0
	if err := ensureParents(tree, dest, &used); err == nil {
		t.Fatal("created a/b/c under a limit of 2")
	}
	if _, err := os.Lstat(filepath.Join(tree, "a", "b", "c")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory past the limit was created: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(tree, "a", "b")); err != nil {
		t.Fatalf("directories within the limit: %v", err)
	}
}

func TestFetchRejectsInodeBomb(t *testing.T) {
	prev := maxEntries
	maxEntries = 4
	t.Cleanup(func() { maxEntries = prev })
	git := preopentest.RequireTools(t)
	repo := filepath.Join(t.TempDir(), "repo")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "repo")
	// Three files, each with its own three-directory chain. The chains
	// share no directory, so writing them creates nine directories from
	// three blobs. The same shape as a root of many links to one deep
	// tree, at a size that stays cheap.
	for i := 0; i < 3; i++ {
		preopentest.WriteFile(t, filepath.Join(repo, "w"+string(rune('0'+i)), "x", "y", "z"), "x\n", 0o644)
	}
	preopentest.Git(t, git, repo, "add", "-A")
	preopentest.Git(t, git, repo, "commit", "-q", "-m", "wide")
	_, err := Fetch(context.Background(), repo)
	var targetErr *TargetError
	if !errors.As(err, &targetErr) || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("Fetch = %v, want a TargetError for the directory limit", err)
	}

	deep := strings.Repeat("d/", maxPathComponents) + "f"
	repo = filepath.Join(t.TempDir(), "deep")
	preopentest.Git(t, git, filepath.Dir(repo), "init", "-q", "deep")
	preopentest.WriteFile(t, filepath.Join(repo, filepath.FromSlash(deep)), "x\n", 0o644)
	preopentest.Git(t, git, repo, "add", "-A")
	preopentest.Git(t, git, repo, "commit", "-q", "-m", "deep")
	_, err = Fetch(context.Background(), repo)
	if !errors.As(err, &targetErr) || !strings.Contains(err.Error(), "components") {
		t.Fatalf("Fetch(deep) = %v, want a TargetError for the component cap", err)
	}
}

func TestEnsureParentsRefusesSymlinkedParent(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	tree := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(tree, "a")); err != nil {
		t.Fatal(err)
	}
	dest, err := entryPath(tree, "a/b")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureParents(tree, dest, new(int)); err == nil {
		t.Fatal("wrote through a symlinked parent")
	}
	assertEmpty(t, outside)
}

// The hardened environment and -c overrides git runs with are now
// internal/gitrun's; see TestEnvDropsInheritedGitSettings and
// TestConfigArgsMatchTheHardenedSet there. TestArmedFixtureTripsNaiveClone,
// TestFetchRunsNothing, and TestFetchRejectsTransports below exercise this
// package's own use of gitrun end to end, with a real git invocation.
