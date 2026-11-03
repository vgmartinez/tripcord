package rules

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const noSymlinksHelp = "the repository must not track symlinks: GitHub's action download fails on any of them. " +
	"Remove it and add the case to fixtureSymlinks in internal/rules/fixture_symlinks_test.go, " +
	"which corePackWithSymlinks creates with os.Symlink in t.TempDir"

// TestNoTrackedSymlinks fails on any mode 120000 entry in the index.
func TestNoTrackedSymlinks(t *testing.T) {
	root := repoRoot(t)
	index := copyIndex(t, root)
	for _, line := range strings.Split(gitOutput(t, root, index, "--no-optional-locks", "ls-files", "-s"), "\n") {
		meta, path, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		if fields := strings.Fields(meta); len(fields) == 3 && fields[0] == "120000" {
			t.Errorf("tracked symlink %s: %s", path, noSymlinksHelp)
		}
	}
}

// TestGitArchiveExtractsAction archives the index and extracts it the
// way an action download does. The archive must hold the composite
// action and only directories and regular files.
func TestGitArchiveExtractsAction(t *testing.T) {
	root := repoRoot(t)
	// write-tree locks .git/index and rewrites its cache-tree. Other
	// packages' tests run in parallel and must not have to wait on, or
	// lose to, that lock, so this uses a private copy of the index.
	index := copyIndex(t, root)
	tree := strings.TrimSpace(gitOutput(t, root, index, "--no-optional-locks", "write-tree"))
	archive := gitStdout(t, root, index, "--no-optional-locks", "archive", "--format=tar", tree)
	dest := t.TempDir()
	tr := tar.NewReader(bytes.NewReader(archive))
	sawAction := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Clean(hdr.Name)
		if name == "." {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			t.Fatalf("archive entry %q escapes the extract directory", hdr.Name)
		}
		target := filepath.Join(dest, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if name == filepath.Join(".github", "actions", "tripcord", "action.yml") {
				sawAction = true
			}
		case tar.TypeSymlink:
			t.Fatalf("archive symlink %s -> %q: %s", hdr.Name, hdr.Linkname, noSymlinksHelp)
		default:
			t.Fatalf("archive entry %s has type %q", hdr.Name, hdr.Typeflag)
		}
	}
	if !sawAction {
		t.Fatal("archive does not contain .github/actions/tripcord/action.yml")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

// copyIndex is a private copy of root's index. GIT_INDEX_FILE pointing
// at it makes read-only git commands, and write-tree, lock this file
// instead of the checkout's .git/index, which other test processes may
// be reading at the same time.
func copyIndex(t *testing.T, root string) string {
	t.Helper()
	src := strings.TrimSpace(gitOutput(t, root, "", "--no-optional-locks", "rev-parse", "--git-path", "index"))
	if !filepath.IsAbs(src) {
		src = filepath.Join(root, src)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "index")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func gitOutput(t *testing.T, root, index string, args ...string) string {
	t.Helper()
	return string(gitStdout(t, root, index, args...))
}

func gitStdout(t *testing.T, root, index string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	if index != "" {
		cmd.Env = append(os.Environ(), "GIT_INDEX_FILE="+index)
	}
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			stderr = strings.TrimSpace(string(exit.Stderr))
		}
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return out
}
