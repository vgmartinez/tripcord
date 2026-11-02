package prcontext

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

// maxChangedPaths bounds one name-status diff. A larger diff is truncated
// and Diff.Truncated is set so a caller cannot treat the prefix as the
// whole pull request.
const maxChangedPaths = 20000

// Diff is the paths git diff reports between base and head. Paths are
// repository-relative and include both sides of a rename or copy.
// Missing is true when base or head is not in this clone. Truncated is
// true when more paths existed than maxChangedPaths.
type Diff struct {
	Paths     []string
	Missing   bool
	Truncated bool
}

// ChangedPaths lists paths that differ between the merge-base of base
// and head, and head. That is the pull request's file diff
// (base...head), not the two-dot diff of the two trees. A missing
// revision sets Diff.Missing and returns no error. err is set when git
// is missing, the repository is unusable, or git fails for another reason.
func ChangedPaths(ctx context.Context, repo, base, head string) (Diff, error) {
	if err := ValidateRev("base", base); err != nil {
		return Diff{}, err
	}
	if err := ValidateRev("head", head); err != nil {
		return Diff{}, err
	}
	rangeSpec := base + "..." + head
	raw, err := git(ctx, repo, "diff", "--name-status", "-z", "--end-of-options", rangeSpec)
	if err != nil {
		warning, fatal := revisionWarning(err, rangeSpec)
		if fatal != nil {
			return Diff{}, fatal
		}
		_ = warning
		return Diff{Missing: true}, nil
	}
	paths, truncated, err := parseNameStatus(raw, maxChangedPaths)
	if err != nil {
		return Diff{}, err
	}
	return Diff{Paths: paths, Truncated: truncated}, nil
}

// parseNameStatus reads a NUL-delimited git diff --name-status. A rename
// or copy status is followed by the old path and the new path. Every
// other status is followed by one path.
func parseNameStatus(raw []byte, limit int) ([]string, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	parts := bytes.Split(raw, []byte{0})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	var paths []string
	truncated := false
	for i := 0; i < len(parts); {
		status := string(parts[i])
		i++
		if status == "" {
			return nil, false, fmt.Errorf("git diff --name-status: empty status")
		}
		n := 1
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			n = 2
		}
		if i+n-1 >= len(parts) {
			return nil, false, fmt.Errorf("git diff --name-status: status %s is missing a path", status)
		}
		for range n {
			if len(paths) >= limit {
				truncated = true
				return paths, truncated, nil
			}
			path := string(parts[i])
			if pathHasControl(path) {
				return nil, false, &InputError{Msg: "changed path contains a control character"}
			}
			paths = append(paths, path)
			i++
		}
	}
	return paths, truncated, nil
}

// pathHasControl reports whether path contains a byte that must not be
// copied into text or GitHub Actions output. Newline, CR, and ESC would
// otherwise let a filename emit a workflow command.
func pathHasControl(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return true
		}
	}
	return false
}
