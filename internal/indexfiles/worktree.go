package indexfiles

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
)

// WorktreeSources is the source-set map (see Plan.Sources) for the
// files currently in the working tree at root, read from disk rather
// than from the Git index. `tripcord scan --staged` uses it when
// PRE_COMMIT_FROM_REF and PRE_COMMIT_TO_REF are set: pre-commit has
// checked out TO, and that checkout — not the index — is the content
// the hook is reviewing. The returned notes are the same walk-limit
// diagnostics a staged plan would report.
func WorktreeSources(root string) (map[string][]string, []adapters.Diagnostic, error) {
	var entries []Entry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "\\") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			entries = append(entries, Entry{Mode: "120000", Path: rel, Target: target, Size: int64(len(target))})
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		entries = append(entries, Entry{Mode: "100644", OID: p, Path: rel, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	plan, err := Choose(entries, os.ReadFile)
	if err != nil {
		return nil, nil, err
	}
	return plan.Sources, plan.Notes, nil
}
