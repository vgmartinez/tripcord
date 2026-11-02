package mcppkg

import (
	"regexp"
	"strings"

	"github.com/vgmartinez/tripcord/internal/advisory"
)

var distTag = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)
var versionTag = regexp.MustCompile(`^v?\d+(\.\d+)*$`)

func parseNPMSpec(spec string) advisory.PackageRef {
	ref := advisory.PackageRef{Ecosystem: advisory.EcoNPM, Spec: spec}
	if strings.Contains(spec, advisory.Redacted) {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	switch {
	case strings.HasPrefix(spec, "git+"), strings.HasPrefix(spec, "github:"),
		strings.HasPrefix(spec, "gitlab:"), strings.HasPrefix(spec, "bitbucket:"),
		strings.HasPrefix(spec, "gist:"):
		return parseGitSpec(spec)
	case strings.HasPrefix(spec, "file:"), strings.HasPrefix(spec, "npm:"),
		strings.HasPrefix(spec, "http:"), strings.HasPrefix(spec, "https:"),
		strings.HasPrefix(spec, "."), strings.HasPrefix(spec, "/"),
		strings.Contains(spec, ".tgz"), strings.Contains(spec, ".tar"):
		ref.Kind = advisory.KindOpaque
		return ref
	}
	name, ver, ok := splitNPMVersion(spec)
	if !ok || name == "" {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	ref.Name = name
	return versioned(ref, ver, true)
}

func splitNPMVersion(spec string) (name, ver string, ok bool) {
	if strings.HasPrefix(spec, "@") {
		slash := strings.Index(spec, "/")
		if slash < 0 {
			return "", "", false
		}
		rest := spec[slash+1:]
		if i := strings.LastIndex(rest, "@"); i >= 0 {
			return strings.ToLower(spec[:slash+1+i]), rest[i+1:], true
		}
		return strings.ToLower(spec), "", true
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return strings.ToLower(spec[:i]), spec[i+1:], true
	}
	return strings.ToLower(spec), "", true
}

func parsePySpec(spec string) advisory.PackageRef {
	ref := advisory.PackageRef{Ecosystem: advisory.EcoPyPI, Spec: spec, Kind: advisory.KindOpaque}
	if strings.Contains(spec, advisory.Redacted) {
		return ref
	}
	if strings.HasPrefix(spec, "git+") || strings.HasPrefix(spec, "github:") || strings.Contains(spec, "://") {
		return parseGitSpec(spec)
	}
	body := stripExtras(spec)
	name, ver, mode := splitPy(body)
	if name == "" {
		return ref
	}
	ref.Name = advisory.NormalizeName(advisory.EcoPyPI, name)
	switch mode {
	case "bare":
		ref.Kind = advisory.KindUnpinned
	case "at":
		ref = versioned(ref, ver, false)
	case "constraint":
		ref = pyConstraint(ref, ver)
	}
	return ref
}

func stripExtras(spec string) string {
	i := strings.Index(spec, "[")
	if i < 0 {
		return spec
	}
	end := strings.Index(spec[i:], "]")
	if end < 0 {
		return spec
	}
	return spec[:i] + spec[i+end+1:]
}

// splitPy splits at the first operator character in the text, so the
// name never keeps part of a later clause.
func splitPy(spec string) (name, ver, mode string) {
	spec = strings.TrimSpace(spec)
	if i := strings.IndexAny(spec, "=<>!~ "); i > 0 {
		return spec[:i], strings.TrimSpace(spec[i:]), "constraint"
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return spec[:i], spec[i+1:], "at"
	}
	return spec, "", "bare"
}

func pyConstraint(ref advisory.PackageRef, constraint string) advisory.PackageRef {
	if !advisory.SpecWithinLimits(constraint) {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	op, ver, ok := splitPyOpLocal(constraint)
	if !ok {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	if (op == "==" || op == "===") && !strings.Contains(ver, "*") && !strings.Contains(constraint, ",") {
		if canon, ok := advisory.CanonicalPEP(ver); ok {
			ref.Kind = advisory.KindExact
			ref.Version = canon
			return ref
		}
		ref.Kind = advisory.KindOpaque
		return ref
	}
	if strings.Contains(constraint, "$") || strings.Contains(constraint, advisory.Redacted) || !advisory.PyRangeOK(constraint) {
		ref.Kind = advisory.KindOpaque
		ref.Version = constraint
		return ref
	}
	ref.Kind = advisory.KindRange
	ref.Version = constraint
	return ref
}

func splitPyOpLocal(s string) (string, string, bool) {
	for _, op := range []string{"===", "==", "~=", "!=", ">=", "<=", ">", "<"} {
		if strings.HasPrefix(s, op) {
			return op, strings.TrimSpace(s[len(op):]), true
		}
	}
	return "", "", false
}

func versioned(ref advisory.PackageRef, ver string, npm bool) advisory.PackageRef {
	ver = strings.TrimSpace(ver)
	if ver == "" || ver == "latest" || ver == "*" {
		ref.Kind = advisory.KindUnpinned
		return ref
	}
	if !advisory.SpecWithinLimits(ver) {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	if strings.Contains(ver, "$") || strings.Contains(ver, advisory.Redacted) {
		ref.Kind = advisory.KindOpaque
		ref.Version = ver
		return ref
	}
	if npm {
		if canon, ok := advisory.CanonicalSemver(ver); ok {
			ref.Kind = advisory.KindExact
			ref.Version = canon
			return ref
		}
		if advisory.NPMRangeOK(ver) {
			ref.Kind = advisory.KindRange
			ref.Version = ver
			return ref
		}
		if distTag.MatchString(ver) {
			ref.Kind = advisory.KindUnpinned
			ref.Version = ver
			return ref
		}
		ref.Kind = advisory.KindOpaque
		ref.Version = ver
		return ref
	}
	if canon, ok := advisory.CanonicalPEP(ver); ok {
		ref.Kind = advisory.KindExact
		ref.Version = canon
		return ref
	}
	if distTag.MatchString(ver) {
		ref.Kind = advisory.KindUnpinned
		ref.Version = ver
		return ref
	}
	ref.Kind = advisory.KindOpaque
	ref.Version = ver
	return ref
}

func parseGitSpec(spec string) advisory.PackageRef {
	ref := advisory.PackageRef{Ecosystem: advisory.EcoGit, Spec: spec, Kind: advisory.KindOpaque}
	if strings.Contains(spec, advisory.Redacted) {
		return ref
	}
	repo, rev := splitGitRef(spec)
	norm, opaque := advisory.NormalizeRepo(repo)
	if opaque {
		return ref
	}
	ref.Repo = norm
	ref.Name = strings.TrimPrefix(strings.TrimPrefix(norm, "https://"), "http://")
	switch gitRefKind(rev) {
	case advisory.KindExact:
		ref.Kind = advisory.KindExact
		ref.Version = rev
		if isHex(rev) {
			ref.Version = strings.ToLower(rev)
		}
	default:
		ref.Kind = advisory.KindUnpinned
	}
	return ref
}

func splitGitRef(spec string) (repo, rev string) {
	if rest, ok := strings.CutPrefix(spec, "github:"); ok {
		if i := strings.LastIndex(rest, "#"); i >= 0 {
			return "github:" + rest[:i], rest[i+1:]
		}
		return spec, ""
	}
	body := strings.TrimPrefix(spec, "git+")
	if i := strings.LastIndex(body, "#"); i >= 0 {
		return body[:i], body[i+1:]
	}
	if i := strings.LastIndex(body, "@"); i >= 0 && atIsRef(body, i) {
		return body[:i], body[i+1:]
	}
	return body, ""
}

func atIsRef(body string, at int) bool {
	scheme := strings.Index(body, "://")
	if scheme < 0 {
		return true
	}
	slash := strings.Index(body[scheme+3:], "/")
	if slash < 0 {
		return false
	}
	return at > scheme+3+slash
}

// gitRefKind treats a commit and a version tag as explicit refs. Any
// other name is a branch, which is unpinned.
func gitRefKind(rev string) string {
	if rev == "" {
		return advisory.KindUnpinned
	}
	if len(rev) >= 7 && len(rev) <= 40 && isHex(rev) {
		return advisory.KindExact
	}
	if versionTag.MatchString(rev) {
		return advisory.KindExact
	}
	return advisory.KindUnpinned
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func parseImage(spec string) advisory.PackageRef {
	ref := advisory.PackageRef{Ecosystem: advisory.EcoDocker, Spec: spec}
	if strings.Contains(spec, advisory.Redacted) {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	nameTag, digest, hasDigest := strings.Cut(spec, "@")
	if !hasDigest {
		// Cut returns the whole string as nameTag when there is no @.
		nameTag = spec
	} else if !strings.HasPrefix(digest, "sha256:") {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	name, tag := splitDockerTag(nameTag)
	if name == "" {
		ref.Kind = advisory.KindOpaque
		return ref
	}
	ref.Name = advisory.NormalizeDocker(name)
	switch {
	case tag == "" && hasDigest:
		ref.Kind = advisory.KindDigest
	case tag == "" || tag == "latest":
		ref.Kind = advisory.KindUnpinned
		ref.Version = tag
	default:
		if canon, ok := advisory.CanonicalSemver(tag); ok {
			ref.Kind = advisory.KindExact
			ref.Version = canon
			return ref
		}
		ref.Kind = advisory.KindUnpinned
		ref.Version = tag
	}
	return ref
}

func splitDockerTag(nameTag string) (name, tag string) {
	slash := strings.LastIndex(nameTag, "/")
	colon := strings.LastIndex(nameTag, ":")
	if colon > slash {
		return nameTag[:colon], nameTag[colon+1:]
	}
	return nameTag, ""
}
