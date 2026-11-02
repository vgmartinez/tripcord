package prcontext

import (
	"bytes"
	"context"
	"path"
	"strings"
)

// maxTreeListBytes bounds one git ls-tree listing used to find symlinks.
// A larger listing is reported as truncated so the caller can treat the
// symlink set as unresolved instead of as empty.
const maxTreeListBytes = 32 << 20

// Symlink is a mode-120000 entry in one tree whose path is a covered
// directory or sits under one. Unresolved means the target cannot be
// mapped back into the repository, so a caller must not treat the diff
// as complete.
type Symlink struct {
	Path       string
	Target     string
	Unresolved bool
}

// TreeSymlinks lists symlinks in rev. A symlink is included when its
// path is a covered directory (covered names such as ".claude") or
// classifies reports that the path itself is agent config, such as
// CLAUDE.md. classifies may be nil. truncated is true when the listing
// exceeded maxTreeListBytes. A missing revision is returned as an error
// from git; the caller decides whether that is fatal.
func TreeSymlinks(ctx context.Context, repo, rev string, covered []string, classifies func(rel string) bool) ([]Symlink, bool, error) {
	if err := ValidateRev("rev", rev); err != nil {
		return nil, false, err
	}
	raw, err := git(ctx, repo, "ls-tree", "-r", "-z", "--end-of-options", rev)
	if err != nil {
		return nil, false, err
	}
	if len(raw) > maxTreeListBytes {
		return nil, true, nil
	}
	var links []Symlink
	for _, rec := range bytes.Split(raw, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, relBytes, ok := bytes.Cut(rec, []byte{'\t'})
		if !ok {
			return nil, false, &InputError{Msg: "git ls-tree: record has no path"}
		}
		rel := string(relBytes)
		if pathHasControl(rel) {
			return nil, false, &InputError{Msg: "changed path contains a control character"}
		}
		fields := strings.Fields(string(meta))
		if len(fields) < 3 {
			return nil, false, &InputError{Msg: "git ls-tree: malformed record"}
		}
		if fields[0] != ModeSymlink || (!coversDir(rel, covered) && !classifiesRel(classifies, rel)) {
			continue
		}
		target, unresolved := symlinkTarget(ctx, repo, fields[2], rel)
		links = append(links, Symlink{Path: rel, Target: target, Unresolved: unresolved})
	}
	return links, false, nil
}

func classifiesRel(classifies func(string) bool, rel string) bool {
	return classifies != nil && classifies(rel)
}

func coversDir(rel string, covered []string) bool {
	for _, seg := range strings.Split(rel, "/") {
		for _, dir := range covered {
			if seg == dir {
				return true
			}
		}
	}
	return false
}

// symlinkTarget reads the blob sha and returns a repository-relative
// target. Absolute paths, empty targets, control characters, and
// targets that escape the repository are unresolved.
func symlinkTarget(ctx context.Context, repo, sha, rel string) (string, bool) {
	if err := ValidateRev("symlink", sha); err != nil {
		return "", true
	}
	blob, err := git(ctx, repo, "cat-file", "blob", "--end-of-options", sha)
	if err != nil {
		return "", true
	}
	target := string(blob)
	if pathHasControl(target) {
		return "", true
	}
	target = strings.TrimSuffix(target, "/")
	if target == "" || strings.HasPrefix(target, "/") || isAbsDrive(target) {
		return "", true
	}
	cleaned := path.Clean(path.Join(path.Dir(rel), target))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", true
	}
	return cleaned, false
}

func isAbsDrive(target string) bool {
	return len(target) >= 2 && target[1] == ':' && ((target[0] >= 'A' && target[0] <= 'Z') || (target[0] >= 'a' && target[0] <= 'z'))
}
