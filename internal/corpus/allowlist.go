package corpus

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// allowable are the finding kinds an allowlist entry may name. A secret
// or a fetch-and-exec line is never allowlisted: it is fixed in the
// fixture. Exec bits, symlinks, special files, loadable config paths,
// and escaping txtar names are fixed too.
var allowable = map[string]bool{
	KindHost:    true,
	KindShebang: true,
	KindEntropy: true,
	KindIOC:     true,
	KindSize:    true,
}

// Entry is one allowlisted finding: the file, relative to the module
// root, the check, the finding's detail, and why it stays.
type Entry struct {
	Line   int
	Path   string
	Kind   string
	Detail string
	Reason string
}

type entryKey struct{ path, kind, detail string }

// Allowlist is a parsed allowlist file.
type Allowlist struct {
	Entries []Entry
}

// ParseAllowlist reads tab-separated lines of path, check, detail, and
// reason. Blank lines and lines starting with # are skipped. A line
// that names a check outside allowable, a path that is not a clean
// relative file path, an empty field, or a duplicate is an error.
func ParseAllowlist(data []byte) (*Allowlist, error) {
	a := &Allowlist{}
	seen := map[entryKey]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, fmt.Errorf("line %d: want 4 tab-separated fields (path, check, detail, reason), got %d", n, len(fields))
		}
		e := Entry{Line: n, Path: fields[0], Kind: fields[1], Detail: fields[2], Reason: fields[3]}
		for _, f := range fields {
			if strings.TrimSpace(f) != f || f == "" {
				return nil, fmt.Errorf("line %d: empty field or surrounding space", n)
			}
		}
		switch {
		case e.Kind == KindSecret || e.Kind == KindFetch:
			return nil, fmt.Errorf("line %d: a %s finding can never be allowlisted; fix the fixture", n, e.Kind)
		case !allowable[e.Kind]:
			return nil, fmt.Errorf("line %d: check %q cannot be allowlisted", n, e.Kind)
		}
		if err := filePath(e.Path); err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", n, e.Path, err)
		}
		k := entryKey{e.Path, e.Kind, e.Detail}
		if prev, ok := seen[k]; ok {
			return nil, fmt.Errorf("line %d: duplicates line %d", n, prev)
		}
		seen[k] = n
		a.Entries = append(a.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return a, nil
}

// filePath accepts one clean, slash-separated, relative file path: no
// glob, no directory, nothing that could cover more than one file.
func filePath(p string) error {
	switch {
	case strings.ContainsAny(p, "*?[]\\"):
		return fmt.Errorf("not a single file: no globs or backslashes")
	case strings.HasSuffix(p, "/") || path.IsAbs(p) || path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../"):
		return fmt.Errorf("not a clean relative file path")
	}
	return nil
}

// Apply matches findings against the allowlist. base is the directory
// entry paths are relative to. It returns the findings no entry covers
// and the entries that cover no finding.
func (a *Allowlist) Apply(base string, findings []Finding) (unlisted []Finding, stale []Entry, err error) {
	used := map[entryKey]bool{}
	byKey := map[entryKey]bool{}
	for _, e := range a.Entries {
		byKey[entryKey{e.Path, e.Kind, e.Detail}] = true
	}
	for _, f := range findings {
		rel, err := RelPath(base, f)
		if err != nil {
			return nil, nil, err
		}
		k := entryKey{rel, f.Kind, f.Detail}
		if !allowable[f.Kind] || !byKey[k] {
			unlisted = append(unlisted, f)
			continue
		}
		used[k] = true
	}
	for _, e := range a.Entries {
		if !used[entryKey{e.Path, e.Kind, e.Detail}] {
			stale = append(stale, e)
		}
	}
	return unlisted, stale, nil
}

// RelPath is f's file relative to base, slash-separated.
func RelPath(base string, f Finding) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(f.Root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absBase, filepath.Join(absRoot, filepath.FromSlash(f.Path)))
	if err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}
