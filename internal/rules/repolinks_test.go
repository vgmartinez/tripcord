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

// TestTrackedSymlinksStayInRepo fails when a committed symlink uses an
// absolute target or a relative target that leaves the repository.
// GitHub's action download follows such a link while extracting the
// repository tarball.
func TestTrackedSymlinksStayInRepo(t *testing.T) {
	root := repoRoot(t)
	for path, target := range trackedSymlinks(t, root) {
		if symlinkEscapes(root, path, target) {
			t.Errorf("tracked symlink %s -> %q leaves the repository", path, target)
		}
	}
}

// TestGitArchiveExtractsAction archives the index and extracts it the
// way an action download does. A symlink that leaves the tree fails the
// test, and the composite action must be in the archive.
func TestGitArchiveExtractsAction(t *testing.T) {
	root := repoRoot(t)
	tree := gitOutput(t, root, "write-tree")
	archive := gitStdout(t, root, "archive", "--format=tar", strings.TrimSpace(tree))
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
			if symlinkEscapes(dest, target, hdr.Linkname) {
				t.Fatalf("archive symlink %s -> %q leaves the extract directory", hdr.Name, hdr.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("archive entry %s has type %q", hdr.Name, hdr.Typeflag)
		}
	}
	if !sawAction {
		t.Fatal("archive does not contain .github/actions/tripcord/action.yml")
	}
}

func trackedSymlinks(t *testing.T, root string) map[string]string {
	t.Helper()
	lines := strings.Split(gitOutput(t, root, "ls-files", "-s"), "\n")
	out := map[string]string{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		meta, path, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("index line %q", line)
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 || fields[0] != "120000" {
			continue
		}
		target := strings.TrimRight(gitOutput(t, root, "cat-file", "-p", fields[1]), "\n")
		out[path] = target
	}
	return out
}

func symlinkEscapes(root, linkPath, target string) bool {
	if filepath.IsAbs(target) {
		return true
	}
	absLink := linkPath
	if !filepath.IsAbs(absLink) {
		absLink = filepath.Join(root, filepath.FromSlash(linkPath))
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(absLink), filepath.FromSlash(target)))
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return true
	}
	return false
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
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
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
