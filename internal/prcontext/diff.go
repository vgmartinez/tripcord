package prcontext

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

// maxChangedPaths bounds one diff. A larger diff is truncated and
// Diff.Truncated is set so a caller cannot treat the prefix as the
// whole pull request.
const maxChangedPaths = 20000

// Symlink and gitlink modes from git diff --raw. A symlink or submodule
// added at a covered directory is agent config even when the path itself
// is not a file an adapter classifies.
const (
	ModeSymlink = "120000"
	ModeGitlink = "160000"
)

// Change is one path from git diff --raw. Path is the new path, or the
// only path. OldPath is set for a rename or copy. Modes are the raw
// octal strings, including 120000 and 160000.
type Change struct {
	Status  string
	OldMode string
	NewMode string
	Path    string
	OldPath string
}

// Diff is the paths git diff reports between base and head. Paths are
// repository-relative and include both sides of a rename or copy.
// Missing is true when base or head is not in this clone. Truncated is
// true when more paths existed than maxChangedPaths.
type Diff struct {
	Paths     []string
	Changes   []Change
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
	raw, err := git(ctx, repo, "diff", "-z", "--raw", "--end-of-options", rangeSpec)
	if err != nil {
		warning, fatal := revisionWarning(err, rangeSpec)
		if fatal != nil {
			return Diff{}, fatal
		}
		_ = warning
		return Diff{Missing: true}, nil
	}
	changes, truncated, err := parseRawDiff(raw, maxChangedPaths)
	if err != nil {
		return Diff{}, err
	}
	return Diff{Paths: pathsOf(changes), Changes: changes, Truncated: truncated}, nil
}

// parseRawDiff reads a NUL-delimited git diff --raw. A rename or copy is
// followed by the old path and the new path. Every other status is
// followed by one path. A path containing a control character is an
// InputError and is not returned.
func parseRawDiff(raw []byte, limit int) ([]Change, bool, error) {
	if len(raw) == 0 {
		return nil, false, nil
	}
	parts := bytes.Split(raw, []byte{0})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	var changes []Change
	npaths := 0
	truncated := false
	for i := 0; i < len(parts); {
		header := string(parts[i])
		i++
		fields := strings.Fields(header)
		if len(fields) < 5 || !strings.HasPrefix(fields[0], ":") {
			return nil, false, fmt.Errorf("git diff --raw: malformed header")
		}
		status := fields[len(fields)-1]
		n := 1
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			n = 2
		}
		if i+n-1 >= len(parts) {
			return nil, false, fmt.Errorf("git diff --raw: status %s is missing a path", status)
		}
		got := make([]string, n)
		for j := range n {
			got[j] = string(parts[i])
			i++
			if pathHasControl(got[j]) {
				return nil, false, &InputError{Msg: "changed path contains a control character"}
			}
		}
		if npaths >= limit {
			truncated = true
			return changes, truncated, nil
		}
		ch := Change{
			Status:  status,
			OldMode: strings.TrimPrefix(fields[0], ":"),
			NewMode: fields[1],
			Path:    got[0],
		}
		npaths++
		if n == 2 {
			ch.OldPath = got[0]
			ch.Path = got[1]
			npaths++
		}
		changes = append(changes, ch)
	}
	return changes, truncated, nil
}

func pathsOf(changes []Change) []string {
	var paths []string
	for _, ch := range changes {
		if ch.OldPath != "" {
			paths = append(paths, ch.OldPath)
		}
		if ch.Path != "" {
			paths = append(paths, ch.Path)
		}
	}
	return paths
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
