package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// TestStagedHuntFindsEveryFixtureDependency is the automated hunt the
// researcher ran by hand over the rule fixture corpus
// (rules/*.test/{positivos,negativos}/*, 751 directories): for every
// file in every fixture, it compares a scan of the intact fixture
// against a scan with that one file removed. A file whose removal
// changes the finding set is a dependency: either the finding needs
// the file's content (a referenced script, a plugin manifest, a
// symlink target) and disappears without it, or the finding is a gap
// that the file was covering (a checksum file, a referenced hook
// script) and appears only once the file is gone.
//
// Every dependency found this way is then replayed as a real,
// subprocess `--staged` commit: stage only that file's addition (for
// an add-dependency) or only its deletion (for a remove-dependency),
// with no path arguments, and require the dependent finding to appear
// — the same shape of commit a pre-commit hook sees. This is how the
// hunt caught the N1 symlink miss, the 6 N2 plugin-convention misses,
// and the 50 deletion misses.
//
// The outer comparison is in-process and reuses the cached rule pack
// (see cachedRules in TestMain), so it stays fast even over the full
// corpus; only the dependencies it finds pay for a real git commit and
// a subprocess scan.
func TestStagedHuntFindsEveryFixtureDependency(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	start := time.Now()
	root := moduleRoot(t)
	dirs := huntFixtureDirs(t, root)
	if len(dirs) == 0 {
		t.Fatal("no fixture directories found under rules/*.test/{positivos,negativos}/*")
	}

	bin := buildStagedBinary(t)

	fileCases := 0
	var deps []huntDependency
	for _, dir := range dirs {
		files := huntFixtureFiles(t, dir)
		full := huntScanFingerprints(t, files)
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fileCases++
			reduced := maps.Clone(files)
			delete(reduced, name)
			removed := huntScanFingerprints(t, reduced)

			var onAdd, onRemove []parityHit
			for fp, hit := range full {
				if _, ok := removed[fp]; !ok {
					onAdd = append(onAdd, hit)
				}
			}
			for fp, hit := range removed {
				if _, ok := full[fp]; !ok {
					onRemove = append(onRemove, hit)
				}
			}
			if len(onAdd) == 0 && len(onRemove) == 0 {
				continue
			}
			deps = append(deps, huntDependency{dir: dir, file: name, onAdd: onAdd, onRemove: onRemove})
		}
	}

	elapsed := time.Since(start)
	t.Logf("hunt: %d fixture directories, %d file-removal cases, %d dependencies found, %s elapsed", len(dirs), fileCases, len(deps), elapsed)

	if len(deps) == 0 {
		t.Fatal("hunt found no file dependencies across the whole corpus: the comparison is likely broken")
	}

	for _, dep := range deps {
		rel, err := filepath.Rel(root, dep.dir)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.ToSlash(rel) + "/" + dep.file
		t.Run(name, func(t *testing.T) {
			files := huntFixtureFiles(t, dep.dir)
			if len(dep.onAdd) > 0 {
				t.Run("staged addition alone surfaces it", func(t *testing.T) {
					assertHuntDependency(t, bin, files, dep.file, true, dep.onAdd)
				})
			}
			if len(dep.onRemove) > 0 {
				t.Run("staged deletion alone surfaces it", func(t *testing.T) {
					assertHuntDependency(t, bin, files, dep.file, false, dep.onRemove)
				})
			}
		})
	}
}

type huntDependency struct {
	dir      string
	file     string
	onAdd    []parityHit
	onRemove []parityHit
}

// huntFixtureDirs lists every positive and negative fixture directory
// under root/rules.
func huntFixtureDirs(t *testing.T, root string) []string {
	t.Helper()
	var dirs []string
	for _, bucket := range []string{"positivos", "negativos"} {
		matches, err := filepath.Glob(filepath.Join(root, "rules", "*.test", bucket, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				t.Fatal(err)
			}
			if info.IsDir() {
				dirs = append(dirs, m)
			}
		}
	}
	sort.Strings(dirs)
	return dirs
}

// huntFixtureFiles reads every regular file under dir into a
// repo-relative path -> content map, suitable for writeRepo. The
// corpus carries no symlinks; a fixture that grows one should fail
// loudly here rather than silently lose its symlink-ness through
// os.ReadFile.
func huntFixtureFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: non-regular fixture file (%v) is not supported by the hunt test", path, d.Type())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// huntScanFingerprints runs an ordinary, non-staged in-process scan
// over files and returns its findings keyed by fingerprint. A normal
// scan never applies a staged source-set filter, so this is the ground
// truth the staged scan's source set must reproduce.
func huntScanFingerprints(t *testing.T, files map[string]string) map[string]parityHit {
	t.Helper()
	root := writeRepo(t, files)
	var stdout, stderr bytes.Buffer
	code := runScan([]string{"--format", "json", root}, &stdout, &stderr)
	if code == int(exitcode.Internal) {
		t.Fatalf("internal error scanning a hunt fixture:\n%s%s", stdout.String(), stderr.String())
	}
	hits := parseFindings(t, stdout.Bytes())
	byFP := make(map[string]parityHit, len(hits))
	for _, h := range hits {
		byFP[h.Fingerprint] = h
	}
	return byFP
}

// assertHuntDependency replays one file dependency as a real `--staged`
// commit with no path arguments: for an add-dependency, the base commit
// has every file except file, and only file's addition is staged; for
// a remove-dependency, the base commit has every file, and only file's
// deletion is staged. Every finding in want must appear in that staged
// scan's output.
func assertHuntDependency(t *testing.T, bin string, files map[string]string, file string, adding bool, want []parityHit) {
	t.Helper()
	repo := t.TempDir()
	stagedGit(t, repo, "init", "-q")
	stagedGit(t, repo, "config", "user.name", "Tripcord Test")
	stagedGit(t, repo, "config", "user.email", "test@example.invalid")

	committed := maps.Clone(files)
	if adding {
		delete(committed, file)
	}
	for rel, content := range committed {
		stagedWrite(t, repo, rel, content)
	}
	if len(committed) > 0 {
		stagedGit(t, repo, "add", ".")
		stagedGit(t, repo, "commit", "-qm", "base")
	}

	if adding {
		stagedWrite(t, repo, file, files[file])
		stagedGit(t, repo, "add", "--", file)
	} else {
		if err := os.Remove(filepath.Join(repo, filepath.FromSlash(file))); err != nil {
			t.Fatal(err)
		}
		stagedGit(t, repo, "add", "-A", "--", file)
	}

	cmd := exec.Command(bin, "scan", "--format", "json", "--staged")
	cmd.Dir = repo
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()
	got := parseFindings(t, stdout.Bytes())
	gotFP := make(map[string]bool, len(got))
	for _, h := range got {
		gotFP[h.Fingerprint] = true
	}
	action := "deleting"
	if adding {
		action = "adding"
	}
	for _, w := range want {
		if !gotFP[w.Fingerprint] {
			t.Fatalf("%s %s alone did not surface %s at %s in a --staged scan with no path arguments\nstaged scan output:\n%s%s", action, file, w.Rule, w.Path, stdout.String(), stderr.String())
		}
	}
}
