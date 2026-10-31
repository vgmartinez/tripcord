package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	errPathEmpty       = errors.New("path: empty")
	errPathNotRelative = errors.New("path: repo scope requires a repo-relative path")
	errPathDotDot      = errors.New(`path: repo scope rejects a ".." segment`)
	errPathNotUserHome = errors.New("path: user scope requires a path rooted at ~/")
	errPathNotAbsolute = errors.New("path: managed scope requires an absolute path")
	errPathScope       = errors.New("path: unknown scope")
)

// windowsDriveLetter matches a leading Windows drive once "\" has already
// been normalized to "/", such as "C:/" or "c:/".
var windowsDriveLetter = regexp.MustCompile(`^[a-zA-Z]:/`)

// normalizeScopedPath normalizes path and checks its shape against scope.
// ConfigItem.ID and the fingerprint's location.path both call this, so a
// path is validated and hashed the same way wherever it names a config
// entry.
//
// Normalization, in order:
//
//  1. Trim space.
//  2. Replace "\" with "/".
//  3. Collapse repeated "/" into one "/".
//  4. Strip a trailing "/" unless the result is "/" or "~".
//  5. If the path is now a Windows drive path, case-fold it: lowercase
//     the whole path, then uppercase just the drive letter. Windows
//     paths are case-insensitive, so "C:\ProgramData\x" and
//     "c:/programdata/x" must normalize to the same ConfigItem.ID and
//     fingerprint location.path ("C:/programdata/x"); this project does
//     not fold case anywhere else.
//
// Scope rules, checked after that normalization:
//
//   - Repo scope (and an empty scope, which defaults to repo) requires a
//     repo-relative path: no leading "/", no leading "~", and no Windows
//     drive letter. A machine-specific absolute path (such as
//     /home/runner/work/... from a CI checkout, or C:\Users\...) does not
//     name a stable config entry, so it is rejected. A leading "./" is
//     stripped (repeatedly); a ".." path segment anywhere is rejected,
//     since a repo-relative path must stay inside the repo it names and
//     must not depend on where the scanner's working directory happens
//     to sit.
//   - User scope requires a path rooted at the user's home: it must be
//     "~" or start with "~/".
//   - Managed scope requires an absolute path: a leading "/", or a
//     Windows drive letter. The managed config files in the spec's
//     adapter table are fixed absolute system paths, such as
//     /etc/cursor/hooks.json. Requiring an absolute shape here, on top
//     of the repo-relative and "~/"-rooted shapes above, keeps the three
//     scopes' path shapes mutually exclusive: the same literal path text
//     can no longer name a repo-scope and a managed-scope entry at once.
func normalizeScopedPath(scope Scope, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errPathEmpty
	}
	path = strings.ReplaceAll(path, `\`, "/")
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	if windowsDriveLetter.MatchString(path) {
		path = canonicalWindowsDrivePath(path)
	}

	switch scope {
	case ScopeUser:
		if path != "~" && !strings.HasPrefix(path, "~/") {
			return "", fmt.Errorf("%w: %q", errPathNotUserHome, path)
		}
	case ScopeManaged:
		if !strings.HasPrefix(path, "/") && !windowsDriveLetter.MatchString(path) {
			return "", fmt.Errorf("%w: %q", errPathNotAbsolute, path)
		}
	case ScopeRepo, "":
		if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "~") || windowsDriveLetter.MatchString(path) {
			return "", fmt.Errorf("%w: %q", errPathNotRelative, path)
		}
		for strings.HasPrefix(path, "./") {
			path = strings.TrimPrefix(path, "./")
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == ".." {
				return "", fmt.Errorf("%w: %q", errPathDotDot, path)
			}
		}
	default:
		return "", fmt.Errorf("%w: %q", errPathScope, scope)
	}
	return path, nil
}

// canonicalWindowsDrivePath case-folds an already slash-normalized
// Windows drive path to one canonical spelling: the whole path
// lowercased, then the drive letter uppercased.
func canonicalWindowsDrivePath(path string) string {
	lower := strings.ToLower(path)
	return strings.ToUpper(lower[:1]) + lower[1:]
}
