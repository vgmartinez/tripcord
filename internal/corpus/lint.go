// Package corpus lints fixture trees. Check walks the roots it is given;
// the corpus test passes corpus/ only. A later test can pass rules/ and
// adapter testdata the same way.
package corpus

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
)

// maxFileBytes is the largest fixture file Check reads.
const maxFileBytes = 16 << 10

// Finding is one lint failure. Path is slash-separated and relative to Root.
type Finding struct {
	Root   string
	Path   string
	Kind   string
	Detail string
}

// Check walks each root and returns every violation. roots are independent
// trees, not a single repository. A missing root is an error. Violations
// are not.
func Check(roots ...string) ([]Finding, error) {
	var out []Finding
	for _, root := range roots {
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
			out = append(out, inspect(root, rel, info, p)...)
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

func inspect(root, rel string, info fs.FileInfo, p string) []Finding {
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
	if info.Size() > maxFileBytes {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindSize, Detail: fmt.Sprintf("%d bytes", info.Size())})
		return out
	}
	data, err := os.ReadFile(p)
	if err != nil {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindSpecial, Detail: err.Error()})
		return out
	}
	out = append(out, scanBytes(root, rel, data)...)
	return out
}

func scanBytes(root, rel string, data []byte) []Finding {
	var out []Finding
	if bytesHasShebang(data) {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindShebang, Detail: "first line"})
	}
	out = append(out, scanText(root, rel, string(data))...)
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
