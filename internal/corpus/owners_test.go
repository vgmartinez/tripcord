package corpus

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// placeholderOwner matches the fictional owners and npm scopes that
// fixtures and docs used before they were normalized to vgmartinez:
// a whole "acme" or "evil" path segment followed by a slash. Names that
// only start with them (acme-plugin/, evil.sh, ACME-CFG-001) and the
// reserved evil.example hosts do not match.
var placeholderOwner = regexp.MustCompile(`(?i)\b(?:acme|evil)/`)

// placeholderOwnerAllow lists repo-relative paths that may keep a
// placeholder owner, each with the reason. Every entry must still
// match, so the list cannot go stale.
var placeholderOwnerAllow = map[string]string{}

// skipOwnerDirs are untracked build outputs and git metadata.
var skipOwnerDirs = map[string]bool{".git": true, "bin": true, "dist": true}

func TestPlaceholderOwnerPattern(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"github.com/" + "acme" + "/tools",
		"npx -y @" + "acme" + "/search-mcp",
		"uses: " + "Evil" + "/action@v1",
		"../" + "evil" + "/repo",
	} {
		if !placeholderOwner.MatchString(s) {
			t.Errorf("placeholderOwner misses %q", s)
		}
	}
	for _, s := range []string{
		"tools/acme-plugin/hooks/hooks.json",
		"ACME-CFG-001",
		"https://evil.example.invalid/x",
		"scripts/evil.sh",
		"vgmartinez/tools",
	} {
		if placeholderOwner.MatchString(s) {
			t.Errorf("placeholderOwner matches %q", s)
		}
	}
}

// TestNoPlaceholderOwners keeps fixtures, goldens, tests, and docs on
// the vgmartinez owner and reserved hosts. It reads the working tree
// only; no network.
func TestNoPlaceholderOwners(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipOwnerDirs[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		loc := placeholderOwner.FindIndex(data)
		if loc == nil {
			return nil
		}
		if _, ok := placeholderOwnerAllow[rel]; ok {
			seen[rel] = true
			return nil
		}
		line := 1 + bytes.Count(data[:loc[0]], []byte("\n"))
		t.Errorf("%s:%d: placeholder owner %q; use vgmartinez", rel, line, data[loc[0]:loc[1]])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range placeholderOwnerAllow {
		if !seen[rel] {
			t.Errorf("placeholderOwnerAllow: %s no longer matches; remove it", rel)
		}
	}
}
