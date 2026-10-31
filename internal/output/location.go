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
var windowsDrive = regexp.MustCompile(`(?i)^[a-z]:/`)

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
// by definition and are kept.
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
		ref.kind = locManaged
		ref.path = clean
		ref.uri = relativeURI(strings.TrimPrefix(clean, "/"))
		ref.baseID = URIBaseManaged
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
