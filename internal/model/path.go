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
	errPathNotUserHome = errors.New("path: user scope requires a path rooted at ~/")
	errPathScope       = errors.New("path: unknown scope")
)

// windowsDriveLetter matches a leading Windows drive, such as "C:\" or "C:/".
var windowsDriveLetter = regexp.MustCompile(`(?i)^[a-z]:[\\/]`)

// normalizeScopedPath normalizes path and checks its shape against scope.
// ConfigItem.ID and the fingerprint's location.path both call this, so a
// path is validated the same way wherever it names a config entry.
//
// Normalization: trim space, replace "\" with "/", collapse repeated "/"
// into one "/", and strip a trailing "/" unless the result is "/" or "~".
// Dot segments ("." or "..") are not resolved.
//
// Scope rules, checked after normalization:
//
//   - Repo scope (and an empty scope, which defaults to repo) requires a
//     repo-relative path: no leading "/", no leading "~", and no Windows
//     drive letter. A machine-specific absolute path (such as
//     /home/runner/work/... from a CI checkout, or C:\Users\...) does not
//     name a stable config entry, so it is rejected.
//   - User scope requires a path rooted at the user's home: it must be
//     "~" or start with "~/".
//   - Managed scope is not restricted beyond normalization: the managed
//     config files in the spec's adapter table are fixed absolute system
//     paths, such as /etc/cursor/hooks.json.
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

	switch scope {
	case ScopeUser:
		if path != "~" && !strings.HasPrefix(path, "~/") {
			return "", fmt.Errorf("%w: %q", errPathNotUserHome, path)
		}
	case ScopeManaged:
		// No restriction.
	case ScopeRepo, "":
		if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "~") || windowsDriveLetter.MatchString(path) {
			return "", fmt.Errorf("%w: %q", errPathNotRelative, path)
		}
	default:
		return "", fmt.Errorf("%w: %q", errPathScope, scope)
	}
	return path, nil
}
