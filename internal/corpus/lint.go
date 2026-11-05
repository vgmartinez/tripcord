// Package corpus lints fixture trees. Check walks the roots it is given.
// The corpus test passes corpus/, which must be clean, and the rules/
// and adapter testdata fixture trees, whose remaining findings are
// listed in allowlist.tsv.
package corpus

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/corpus/benign"
	"github.com/vgmartinez/tripcord/internal/txtar"
)

// Finding kinds.
const (
	KindExec    = "exec"
	KindSymlink = "symlink"
	KindSpecial = "special"
	KindShebang = "shebang"
	KindHost    = "host"
	KindEntropy = "entropy"
	KindSize    = "size"
	KindTxtar   = "txtar-path"
	KindIOC     = "ioc"
	KindSecret  = "secret"
	KindConfig  = "config-path"
	KindFetch   = "fetch-exec"
	KindIndex   = "index"
)

// maxFileBytes is the largest fixture file that passes the size check.
const maxFileBytes = 16 << 10

// maxScanBytes is the largest file whose content Check reads. A file
// over maxFileBytes is still read up to here, so a size finding never
// hides what the file holds.
const maxScanBytes = 1 << 20

// Finding is one lint failure. Path is slash-separated and relative to Root.
type Finding struct {
	Root   string
	Path   string
	Kind   string
	Detail string
}

// Root is one tree for CheckRoots. Defs, when set, reports whether the
// file at rel, slash-separated, is a definition or a doc rather than
// fixture content. Such a file gets every check except the host, IOC,
// and entropy checks: a rule names real hosts and long patterns on
// purpose.
type Root struct {
	Dir  string
	Defs func(rel string) bool
}

// PackDefs is Root.Defs for a rule pack such as rules/: every file
// outside an <ID>.test/ directory (rule YAML, pack.yaml, REGISTRY,
// ADVISORIES.json, README.md, embed.go), and any README file.
func PackDefs(rel string) bool {
	first, _, _ := strings.Cut(rel, "/")
	if !strings.HasSuffix(first, ".test") || first == rel {
		return true
	}
	return strings.HasPrefix(path.Base(rel), "README")
}

// Check walks each root as fixture content throughout. See CheckRoots.
func Check(roots ...string) ([]Finding, error) {
	rs := make([]Root, len(roots))
	for i, r := range roots {
		rs[i] = Root{Dir: r}
	}
	return CheckRoots(rs...)
}

// CheckRoots walks each root and returns every violation. roots are
// independent trees, not a single repository. A missing root is an
// error. Violations are not.
func CheckRoots(roots ...Root) ([]Finding, error) {
	var out []Finding
	for _, r := range roots {
		root := r.Dir
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(abs)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%s: not a real directory", root)
		}
		err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if p == abs {
				return nil
			}
			rel, err := filepath.Rel(abs, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			info, err := d.Info()
			if err != nil {
				return err
			}
			// repos.lock and triage.tsv under a corpus root are indexes,
			// not fixtures. The size cap and the generic host and
			// entropy checks stay off there, because a lock of 1,000
			// repositories is larger than a fixture and a repository
			// name can look like a host. The strict index validator
			// still runs on those two files. The same relative path
			// under any other root is an ordinary fixture.
			index := corpusBenignIndex(abs, rel)
			content := (r.Defs == nil || !r.Defs(rel)) && !index
			out = append(out, inspect(root, rel, info, p, content, index)...)
			if info.IsDir() && info.Mode()&os.ModeSymlink != 0 {
				return fs.SkipDir
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b Finding) int {
		if c := strings.Compare(a.Root, b.Root); c != 0 {
			return c
		}
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Detail, b.Detail)
	})
	return out, nil
}

// corpusBenignIndex reports the benign-corpus indexes when the walk
// root itself is named corpus. Symlinks and executables are still
// rejected. A copy under another root, including an adapter fixture
// tree, is not an index.
func corpusBenignIndex(rootAbs, rel string) bool {
	if filepath.Base(rootAbs) != "corpus" {
		return false
	}
	switch rel {
	case "benign/repos.lock", "benign/triage.tsv":
		return true
	default:
		return false
	}
}

func inspect(root, rel string, info fs.FileInfo, p string, content, index bool) []Finding {
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return []Finding{{Root: root, Path: rel, Kind: KindSymlink, Detail: "symlink"}}
	}
	if info.IsDir() {
		return nil
	}
	if !mode.IsRegular() {
		return []Finding{{Root: root, Path: rel, Kind: KindSpecial, Detail: mode.String()}}
	}
	var out []Finding
	if mode&0o111 != 0 {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindExec, Detail: mode.Perm().String()})
	}
	if loadable(rel) {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindConfig, Detail: rel})
	}
	if info.Size() > maxFileBytes && !index {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindSize, Detail: fmt.Sprintf("%d bytes", info.Size())})
	}
	if info.Size() > maxScanBytes {
		if index {
			out = append(out, Finding{Root: root, Path: rel, Kind: KindIndex, Detail: "file is too large to validate"})
		}
		return out
	}
	data, err := os.ReadFile(p)
	if err != nil {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindSpecial, Detail: err.Error()})
		return out
	}
	out = append(out, scanBytes(root, rel, data, content)...)
	if index {
		out = append(out, validateBenignIndex(root, rel, p, data)...)
	}
	return out
}

// validateBenignIndex runs the row validator. An index exemption never
// skips it. An empty triage file does not need the lock or the registry.
func validateBenignIndex(root, rel, path string, data []byte) []Finding {
	var err error
	switch rel {
	case "benign/repos.lock":
		var repos []benign.Repo
		repos, err = benign.LoadLock(data)
		if err == nil {
			err = benign.Validate(repos, nil, nil)
		}
	case "benign/triage.tsv":
		var rows []benign.Triage
		rows, err = benign.ParseTriage(data)
		if err == nil && len(rows) > 0 {
			err = validateTriageRows(path, rows)
		}
	default:
		err = fmt.Errorf("unhandled index %s", rel)
	}
	if err != nil {
		return []Finding{{Root: root, Path: rel, Kind: KindIndex, Detail: err.Error()}}
	}
	return nil
}

func validateTriageRows(triagePath string, rows []benign.Triage) error {
	lockRaw, err := os.ReadFile(filepath.Join(filepath.Dir(triagePath), "repos.lock"))
	if err != nil {
		return fmt.Errorf("repos.lock: %w", err)
	}
	repos, err := benign.LoadLock(lockRaw)
	if err != nil {
		return err
	}
	// triage.tsv lives at <corpus>/benign/triage.tsv. rules/REGISTRY is
	// the sibling of that corpus directory.
	corpusDir := filepath.Dir(filepath.Dir(triagePath))
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(corpusDir), "rules", "REGISTRY"))
	if err != nil {
		return fmt.Errorf("rules/REGISTRY: %w", err)
	}
	rules, err := benign.ParseRegistry(raw)
	if err != nil {
		return err
	}
	return benign.Validate(repos, rows, rules)
}

func scanBytes(root, rel string, data []byte, content bool) []Finding {
	var out []Finding
	if bytesHasShebang(data) {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindShebang, Detail: "first line"})
	}
	out = append(out, scanText(root, rel, string(data), content)...)
	arc := txtar.Parse(data)
	seen := map[string]struct{}{}
	for _, f := range arc.Files {
		cleaned, err := txtar.Rel(f.Name)
		if err != nil {
			out = append(out, Finding{Root: root, Path: rel, Kind: KindTxtar, Detail: f.Name + ": " + err.Error()})
			continue
		}
		if _, ok := seen[cleaned]; ok {
			out = append(out, Finding{Root: root, Path: rel, Kind: KindTxtar, Detail: f.Name + ": " + txtar.ErrDuplicate.Error()})
			continue
		}
		seen[cleaned] = struct{}{}
		if bytesHasShebang(f.Data) {
			out = append(out, Finding{Root: root, Path: rel, Kind: KindShebang, Detail: f.Name})
		}
	}
	return out
}

func bytesHasShebang(data []byte) bool {
	return len(data) >= 2 && data[0] == '#' && data[1] == '!'
}
