package model

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var (
	errPathEmpty         = errors.New("path: empty")
	errPathNotRelative   = errors.New("path: repo scope requires a repo-relative path")
	errPathDotDot        = errors.New(`path: rejects a ".." segment`)
	errPathNotUserHome   = errors.New("path: user scope requires a path rooted at ~/")
	errPathNotAbsolute   = errors.New("path: managed scope requires an absolute path")
	errPathScope         = errors.New("path: unknown scope")
	errPathNotNormalized = errors.New("path: not normalized")
)

// windowsDriveLetter matches a leading Windows drive once "\" has already
// been normalized to "/". A drive is a letter, a colon, and then either
// the end of the path ("C:") or a slash ("C:/..."). A colon followed by
// more text ("a:b.json", and the same shape "C:foo") is not a drive.
// See docs/fingerprint.md.
var windowsDriveLetter = regexp.MustCompile(`^[a-zA-Z]:($|/)`)

// normalizeScopedPath normalizes path and checks its shape against scope.
// ConfigItem.ID and Fingerprint call it and use the canonical result.
// Finding.Validate calls it and requires location.path to already be
// that result.
//
// Normalization, in order:
//
//  1. Trim space.
//  2. Unicode NFC, so a decomposed and a composed spelling of the same
//     path hash to one fingerprint. ASCII paths are unchanged.
//  3. Replace "\" with "/".
//  4. Reject any ".." segment, in every scope, before path.Clean. A
//     segment Clean could otherwise resolve ("a/../b" would become "b")
//     is rejected the same way a segment that escapes the path is
//     ("../../etc/passwd"). This matches the finding schema, which
//     rejects a raw ".." segment.
//  5. path.Clean, which removes "." segments (so "a/./b" is "a/b"),
//     collapses repeated "/", and strips a trailing "/" other than the
//     root.
//  6. If the path is now a Windows drive path, case-fold it: lowercase
//     the whole path, then uppercase just the drive letter. Windows
//     paths are case-insensitive, so "C:\ProgramData\x" and
//     "c:/programdata/x" must normalize to the same ConfigItem.ID and
//     fingerprint location.path ("C:/programdata/x"); this project does
//     not fold case anywhere else. "a:b.json" is not a drive path, so
//     it is left unchanged.
//
// Scope rules, checked after that normalization. A drive-letter path is
// absolute in every scope.
//
//   - Repo scope (and an empty scope, which defaults to repo) requires a
//     repo-relative path: no leading "/", no leading "~", and no Windows
//     drive letter. A machine-specific absolute path (such as
//     /home/runner/work/... from a CI checkout, C:\Users\..., or a UNC
//     path) does not name a stable config entry, so it is rejected.
//   - User scope requires a path rooted at the user's home: it must be
//     "~" or start with "~/".
//   - Managed scope requires an absolute path: a leading "/", or a
//     Windows drive letter. The managed config files in the spec's
//     adapter table are fixed absolute system paths, such as
//     /etc/cursor/hooks.json. Requiring an absolute shape here, on top
//     of the repo-relative and "~/"-rooted shapes above, keeps the three
//     scopes' path shapes mutually exclusive: the same literal path text
//     can no longer name a repo-scope and a managed-scope entry at once.
func normalizeScopedPath(scope Scope, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errPathEmpty
	}
	p = norm.NFC.String(p)
	p = strings.ReplaceAll(p, `\`, "/")
	if pathHasDotDot(p) {
		return "", fmt.Errorf("%w: %q", errPathDotDot, p)
	}
	p = path.Clean(p)
	if windowsDriveLetter.MatchString(p) {
		p = canonicalWindowsDrivePath(p)
	}

	switch scope {
	case ScopeUser:
		if p != "~" && !strings.HasPrefix(p, "~/") {
			return "", fmt.Errorf("%w: %q", errPathNotUserHome, p)
		}
	case ScopeManaged:
		if !pathIsAbsolute(p) {
			return "", fmt.Errorf("%w: %q", errPathNotAbsolute, p)
		}
	case ScopeRepo, "":
		if pathIsAbsolute(p) || strings.HasPrefix(p, "~") {
			return "", fmt.Errorf("%w: %q", errPathNotRelative, p)
		}
	default:
		return "", fmt.Errorf("%w: %q", errPathScope, scope)
	}
	return p, nil
}

func pathIsAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") || windowsDriveLetter.MatchString(p)
}

func pathHasDotDot(p string) bool {
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

// canonicalWindowsDrivePath case-folds an already slash-normalized
// Windows drive path to one canonical spelling: the whole path
// lowercased, then the drive letter uppercased.
func canonicalWindowsDrivePath(path string) string {
	lower := strings.ToLower(path)
	return strings.ToUpper(lower[:1]) + lower[1:]
}
