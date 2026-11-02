package rules

import (
	"archive/tar"
	"bytes"
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
	for _, line := range strings.Split(gitOutput(t, root, "ls-files", "-s"), "\n") {
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
	tree := strings.TrimSpace(gitOutput(t, root, "write-tree"))
	archive := gitStdout(t, root, "archive", "--format=tar", tree)
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

func gitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()
	return string(gitStdout(t, root, args...))
}

func gitStdout(t *testing.T, root string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return out
}
