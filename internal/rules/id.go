package rules

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// idPattern accepts TC-CFG-001, TC-SEC-017, and policy ids such as
// ACME-001: upper-case dash-separated words ending in at least three digits.
var idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z][A-Z0-9]*)*-[0-9]{3,}$`)

// ValidID reports whether id has the rule id shape.
func ValidID(id string) bool {
	return len(id) <= 64 && idPattern.MatchString(id)
}

// packNamePattern is <namespace>/<name>, lower case.
var packNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*$`)

// packVersionPattern is calendar versioning: YYYY.MM with an optional
// .N patch, as in tripcord/core@2026.11.
var packVersionPattern = regexp.MustCompile(`^[0-9]{4}\.(0[1-9]|1[0-2])(\.(0|[1-9][0-9]*))?$`)

// ParsePackName parses a pack name, <namespace>/<name>, with no version.
// A rule file names its pack; the version lives only in pack.yaml.
func ParsePackName(s string) (string, error) {
	if strings.Contains(s, "@") {
		return "", fmt.Errorf("pack %q: a rule names the pack only; the version lives in pack.yaml", s)
	}
	if !packNamePattern.MatchString(s) {
		return "", fmt.Errorf("pack %q: want <namespace>/<name> in lower case", s)
	}
	return s, nil
}

// PackRef names a versioned rule pack, such as tripcord/core@2026.11.
// The version comes from the pack manifest. Rule files do not carry it.
type PackRef struct {
	Name    string
	Version string
}

// ParsePackRef parses <namespace>/<name>@<YYYY.MM[.N]>.
func ParsePackRef(s string) (PackRef, error) {
	name, version, ok := strings.Cut(s, "@")
	if !ok {
		return PackRef{}, fmt.Errorf("pack %q: want <namespace>/<name>@<YYYY.MM>", s)
	}
	if !packNamePattern.MatchString(name) {
		return PackRef{}, fmt.Errorf("pack %q: name must be <namespace>/<name> in lower case", s)
	}
	if !packVersionPattern.MatchString(version) {
		return PackRef{}, fmt.Errorf("pack %q: version must be YYYY.MM or YYYY.MM.N", s)
	}
	return PackRef{Name: name, Version: version}, nil
}

// String returns name@version.
func (p PackRef) String() string { return p.Name + "@" + p.Version }

// CompareVersions compares two pack versions that match YYYY.MM[.N]
// and returns -1, 0, or +1. A missing patch is .0.
func CompareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := range pa {
		if c := cmp.Compare(pa[i], pb[i]); c != 0 {
			return c
		}
	}
	return 0
}

func versionParts(v string) [3]int {
	var p [3]int
	for i, s := range strings.SplitN(v, ".", 3) {
		p[i], _ = strconv.Atoi(s)
	}
	return p
}
