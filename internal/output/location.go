package output

import (
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// URI base ids for findings outside the repository. They are declared in
// run.originalUriBaseIds with a description and no absolute URI, so a SARIF
// document does not record a machine path.
const (
	URIBaseUserHome = "USERHOME"
	URIBaseManaged  = "MANAGED"
)

// windowsDrive matches a drive-letter path after backslashes become "/".
// "C:", "c:x.json", and "C:/..." are all absolute.
var windowsDrive = regexp.MustCompile(`^[A-Za-z]:`)

type locationKind int

const (
	locNone locationKind = iota
	locRepo
	locUser
	locManaged
)

// locationRef is the only form of a location a sink may publish.
// path is the normalized path for messages and properties: repo-relative,
// rooted at "~", or a managed system path. uri is a relative URI reference.
type locationRef struct {
	kind   locationKind
	scope  string
	path   string
	uri    string
	baseID string
	line   *int
}

// locate normalizes a finding location so no machine path can leak.
// Repository paths must be relative, or absolute and inside root; any
// other absolute path, a "~" path, or one that climbs out with ".." is
// omitted. User paths must stay under "~". Managed paths are system paths
// by definition and are kept. A managed path under a home directory is
// displayed as "~/..." (see managedDisplayPath); that rewrite is
// presentation only and does not change the stored finding or its
// fingerprint.
func locate(location model.Location, root string) locationRef {
	p := normalizeDisplayPath(location.Path)
	if p == "" {
		return locationRef{}
	}
	scope := location.Scope
	if scope == "" {
		scope = model.ScopeRepo
	}
	ref := locationRef{scope: string(scope), line: location.Line}
	switch scope {
	case model.ScopeUser:
		clean, ok := userPath(p)
		if !ok {
			return locationRef{}
		}
		ref.kind = locUser
		ref.path = clean
		ref.uri = relativeUserURI(clean)
		ref.baseID = URIBaseUserHome
	case model.ScopeManaged:
		clean := path.Clean(p)
		display := managedDisplayPath(clean)
		ref.kind = locManaged
		ref.path = display
		ref.uri = managedURI(display, clean)
		// A home path is relative to USERHOME. MANAGED is only for a
		// path that is not under a home directory.
		if display == "~" || strings.HasPrefix(display, "~/") {
			ref.baseID = URIBaseUserHome
		} else {
			ref.baseID = URIBaseManaged
		}
	case model.ScopeRepo:
		rel, ok := repoRelative(p, root)
		if !ok {
			return locationRef{}
		}
		ref.kind = locRepo
		ref.path = rel
		ref.uri = relativeURI(rel)
	default:
		return locationRef{}
	}
	return ref
}

// display is the path with its line, for human-readable sinks.
func (ref locationRef) display() string {
	if ref.line == nil {
		return ref.path
	}
	return ref.path + ":" + strconv.Itoa(*ref.line)
}

// normalizeDisplayPath matches the path normalization used for config ids:
// trim, use forward slashes, collapse repeated slashes, and drop a trailing
// slash.
func normalizeDisplayPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `\`, "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func isAbsolutePath(p string) bool {
	return strings.HasPrefix(p, "/") || windowsDrive.MatchString(p)
}

func repoRelative(p, root string) (string, bool) {
	if strings.HasPrefix(p, "~") {
		return "", false
	}
	if isAbsolutePath(p) {
		base := normalizeDisplayPath(root)
		if base == "" || !isAbsolutePath(base) {
			return "", false
		}
		base = path.Clean(base)
		p = path.Clean(p)
		prefix := base + "/"
		if base == "/" {
			prefix = "/"
		}
		if len(p) <= len(prefix) {
			return "", false
		}
		head := p[:len(prefix)]
		inside := head == prefix
		if windowsDrive.MatchString(base) {
			inside = strings.EqualFold(head, prefix)
		}
		if !inside {
			return "", false
		}
		p = p[len(prefix):]
	}
	rel := path.Clean(p)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || isAbsolutePath(rel) {
		return "", false
	}
	return rel, true
}

// presentConfigID rewrites the path inside a config id the same way
// managedDisplayPath rewrites a managed location. The id is
// harness:scope:path; only the first two colons separate, so a Windows
// drive colon stays in the path. Other scopes are returned unchanged.
// This is presentation only: the stored id and the fingerprint stay.
func presentConfigID(id string) string {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 || parts[1] != string(model.ScopeManaged) || parts[2] == "" {
		return id
	}
	display := managedDisplayPath(path.Clean(normalizeDisplayPath(parts[2])))
	if display == parts[2] {
		return id
	}
	return parts[0] + ":" + parts[1] + ":" + display
}

// managedDisplayPath rewrites a cleaned managed path for display.
// /Users/<name>/, /home/<name>/, and <drive>:/Users/<name>/ (any case,
// after backslashes have become "/") are shown as ~/... so a username
// never reaches a sink. Any other managed path is returned unchanged.
func managedDisplayPath(clean string) string {
	rest, ok := homeRemainder(clean)
	if !ok {
		return clean
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 || slash == len(rest)-1 {
		return "~"
	}
	return "~/" + rest[slash+1:]
}

// homeRemainder returns the path after a home-directory prefix, starting
// at the username segment. clean uses forward slashes.
func homeRemainder(clean string) (string, bool) {
	lower := strings.ToLower(clean)
	for _, prefix := range []string{"/users/", "/home/"} {
		if strings.HasPrefix(lower, prefix) {
			return clean[len(prefix):], true
		}
	}
	// A home path is "<drive>:/Users/...", not the drive-relative "c:x.json".
	if len(clean) > 3 && clean[1] == ':' && clean[2] == '/' {
		rest := clean[3:]
		const users = "Users/"
		if len(rest) >= len(users) && strings.EqualFold(rest[:len(users)], users) {
			return rest[len(users):], true
		}
	}
	return "", false
}

// managedURI is a relative URI for a managed path. A home path uses the
// rewritten display form, so the username is not part of the URI either.
func managedURI(display, clean string) string {
	switch {
	case display == "~":
		return "."
	case strings.HasPrefix(display, "~/"):
		return relativeURI(strings.TrimPrefix(display, "~/"))
	default:
		return relativeURI(strings.TrimPrefix(clean, "/"))
	}
}

func userPath(p string) (string, bool) {
	if p == "~" {
		return p, true
	}
	if !strings.HasPrefix(p, "~/") {
		return "", false
	}
	rest := path.Clean(strings.TrimPrefix(p, "~/"))
	switch {
	case rest == ".":
		return "~", true
	case rest == "..", strings.HasPrefix(rest, "../"):
		return "", false
	default:
		return "~/" + rest, true
	}
}

// relativeUserURI drops "~/" because USERHOME already names the home directory.
func relativeUserURI(p string) string {
	if p == "~" {
		return "."
	}
	return relativeURI(strings.TrimPrefix(p, "~/"))
}

// relativeURI percent-encodes p as a relative URI reference. ":" is always
// encoded, so a drive letter or a first segment cannot read as a scheme.
func relativeURI(p string) string {
	if p == "" || p == "." {
		return "."
	}
	escaped := (&url.URL{Path: p}).EscapedPath()
	if escaped == "" {
		return "."
	}
	return strings.ReplaceAll(escaped, ":", "%3A")
}
