package rules

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const maxSymlinkHops = 40

var driveLetterTarget = regexp.MustCompile(`^[A-Za-z]:`)

// TestTrackedSymlinksStayInRepo fails when a committed symlink uses an
// absolute target or resolves outside the repository.
// GitHub's action download follows such a link while extracting the
// repository tarball.
func TestTrackedSymlinksStayInRepo(t *testing.T) {
	root := repoRoot(t)
	links := trackedSymlinks(t, root)
	for path := range links {
		if err := symlinkEscapes(root, links, path); err != nil {
			t.Errorf("tracked symlink %s: %v", path, err)
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
	links := map[string]string{}
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
			links[name] = hdr.Linkname
		default:
			t.Fatalf("archive entry %s has type %q", hdr.Name, hdr.Typeflag)
		}
	}
	for path, target := range links {
		if err := symlinkEscapes(dest, links, path); err != nil {
			t.Fatalf("archive symlink %s -> %q: %v", path, target, err)
		}
		linkPath := filepath.Join(dest, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, linkPath); err != nil {
			t.Fatal(err)
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

func TestSymlinkEscapesChainedLinks(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{
		"zz/up":  "..",
		"zz/esc": "up/..",
	}
	if err := symlinkEscapes(root, links, "zz/esc"); err == nil {
		t.Fatal("chained symlinks zz/up -> .. and zz/esc -> up/.. escape the root")
	}
}

func TestSymlinkEscapesLoop(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{
		"one": "two",
		"two": "one",
	}
	if err := symlinkEscapes(root, links, "one"); err == nil {
		t.Fatal("symlink loop was accepted")
	}
}

func TestSymlinkAllowsRepeatedLink(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{
		"entry": "one/one",
		"one":   ".",
	}
	if err := symlinkEscapes(root, links, "entry"); err != nil {
		t.Fatalf("repeated safe link was rejected: %v", err)
	}
}

func TestSymlinkRejectsTooManyHops(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{"entry": "link-0"}
	for i := 0; i < maxSymlinkHops; i++ {
		name := fmt.Sprintf("link-%d", i)
		target := "target"
		if i+1 < maxSymlinkHops {
			target = fmt.Sprintf("link-%d", i+1)
		}
		links[name] = target
	}
	if err := symlinkEscapes(root, links, "entry"); err == nil {
		t.Fatalf("more than %d symlink hops were accepted", maxSymlinkHops)
	}
}

func TestSymlinkEscapesAbsoluteTargets(t *testing.T) {
	root := t.TempDir()
	for _, target := range []string{"/tmp", `C:\temp`, `C:temp`, `\\server\share`, `child\target`} {
		t.Run(target, func(t *testing.T) {
			links := map[string]string{"link": target}
			if err := symlinkEscapes(root, links, "link"); err == nil {
				t.Fatalf("target %q was accepted", target)
			}
		})
	}
}

// symlinkEscapes resolves tracked links without following the filesystem.
// It rejects targets that GitHub's tar extractor could follow outside root.
func symlinkEscapes(root string, links map[string]string, linkPath string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	link, err := pathInsideRoot(root, linkPath)
	if err != nil {
		return err
	}
	target, ok := links[link]
	if !ok {
		return os.ErrNotExist
	}
	if unsafeTarget(target) {
		return os.ErrPermission
	}
	parts := cleanPathParts(filepath.Dir(link))
	pending := splitPath(target)
	hops := 1
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(parts) == 0 {
				return os.ErrPermission
			}
			parts = parts[:len(parts)-1]
			continue
		}
		parts = append(parts, part)
		path := strings.Join(parts, "/")
		target, ok = links[path]
		if !ok {
			continue
		}
		if unsafeTarget(target) {
			return os.ErrPermission
		}
		hops++
		if hops > maxSymlinkHops {
			return os.ErrInvalid
		}
		parts = parts[:len(parts)-1]
		pending = append(splitPath(target), pending...)
	}
	return nil
}

func pathInsideRoot(root, path string) (string, error) {
	if filepath.IsAbs(path) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return "", err
		}
		path = rel
	}
	parts := []string{}
	for _, part := range splitPath(filepath.ToSlash(path)) {
		switch part {
		case "", ".":
		case "..":
			if len(parts) == 0 {
				return "", os.ErrPermission
			}
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "/"), nil
}

func splitPath(path string) []string {
	return strings.FieldsFunc(filepath.ToSlash(path), func(r rune) bool {
		return r == '/'
	})
}

func cleanPathParts(path string) []string {
	parts := []string{}
	for _, part := range splitPath(path) {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	return parts
}

func unsafeTarget(target string) bool {
	return filepath.IsAbs(target) ||
		strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, `\\`) ||
		strings.Contains(target, `\`) ||
		driveLetterTarget.MatchString(target)
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
