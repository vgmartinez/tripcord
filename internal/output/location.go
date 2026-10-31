package output

import (
	"net/url"
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

type locationKind int

const (
	locNone locationKind = iota
	locRepo
	locUser
	locManaged
)

// locationRef is the location a sink can publish without copying a machine path.
// path is the normalized path stored in messages and properties. uri is the
// relative SARIF URI. For a repository path, both are repository-relative.
type locationRef struct {
	kind   locationKind
	scope  string
	path   string
	uri    string
	baseID string
	line   *int
}

// locate normalizes a finding location. User and managed paths are kept.
// An absolute repository path is made repository-relative when it is inside
// root; otherwise it is omitted so a checkout path cannot leak.
func locate(location model.Location, root string) locationRef {
	path := normalizeDisplayPath(location.Path)
	if path == "" {
		return locationRef{}
	}
	scope := location.Scope
	if scope == "" {
		scope = model.ScopeRepo
	}
	ref := locationRef{scope: string(scope), line: location.Line}
	switch scope {
	case model.ScopeUser:
		ref.kind = locUser
		ref.path = path
		ref.uri = relativeUserURI(path)
		ref.baseID = URIBaseUserHome
	case model.ScopeManaged:
		ref.kind = locManaged
		ref.path = path
		ref.uri = relativeManagedURI(path)
		ref.baseID = URIBaseManaged
	case model.ScopeRepo:
		uri, ok := repoRelativeURI(model.Location{Scope: model.ScopeRepo, Path: path}, root)
		if !ok {
			return locationRef{}
		}
		ref.kind = locRepo
		ref.path = uri
		ref.uri = uri
	default:
		return locationRef{}
	}
	return ref
}

// normalizeDisplayPath matches the path normalization used for config ids:
// trim, use forward slashes, collapse repeated slashes, and drop a trailing
// slash. Dot segments stay in place.
func normalizeDisplayPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.ReplaceAll(path, `\`, "/")
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return path
}

func relativeUserURI(path string) string {
	// USERHOME is the home directory, so the ~/ prefix is not part of the relative URI.
	switch {
	case path == "~":
		return "."
	case strings.HasPrefix(path, "~/"):
		return relativeURI(strings.TrimPrefix(path, "~/"))
	default:
		return relativeURI(strings.TrimLeft(path, "/"))
	}
}

func relativeManagedURI(path string) string {
	// SARIF applies uriBaseId only when uri is relative. Drop one leading
	// slash so an absolute managed path does not become an absolute URI.
	// The normalized path remains in the message and properties.tripcord.path.
	return relativeURI(strings.TrimPrefix(path, "/"))
}

func relativeURI(path string) string {
	if path == "" || path == "." {
		return "."
	}
	escaped := (&url.URL{Path: path}).EscapedPath()
	if escaped == "" {
		return "."
	}
	return escaped
}
