// Package advisory is the offline package-advisory list and the version
// arithmetic TC-CFG-023 uses to decide whether a pinned spec can only
// resolve to affected versions.
//
// There is no network lookup. Two comparisons are implemented: npm
// semver (with the usual range operators) and a subset of PEP 440
// (release, pre, post, and dev; no epoch and no local version). Docker
// tags that parse as semver use the semver order. Git commit order is
// not computable offline, so git advisories match an explicit commit
// list or, when the advisory has no fixed version, an unpinned ref.
package advisory

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Ecosystems named in ADVISORIES.json.
const (
	EcoNPM    = "npm"
	EcoPyPI   = "pypi"
	EcoDocker = "docker"
	EcoGit    = "git"
	EcoModule = "module"
)

// Kinds of a parsed package spec. digest and opaque never match.
const (
	KindExact    = "exact"
	KindRange    = "range"
	KindUnpinned = "unpinned"
	KindDigest   = "digest"
	KindOpaque   = "opaque"
)

// semver is an npm or docker version. pre empty means a release.
type semver struct {
	major, minor, patch int
	pre                 []preID
}

type preID struct {
	num     int
	text    string
	numeric bool
}

func cmpSemver(a, b semver) int {
	if c := cmp.Compare(a.major, b.major); c != 0 {
		return c
	}
	if c := cmp.Compare(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmp.Compare(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	n := min(len(a.pre), len(b.pre))
	for i := 0; i < n; i++ {
		if c := cmpPre(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a.pre), len(b.pre))
}

func cmpPre(a, b preID) int {
	switch {
	case a.numeric && b.numeric:
		return cmp.Compare(a.num, b.num)
	case a.numeric:
		return -1
	case b.numeric:
		return 1
	default:
		return strings.Compare(a.text, b.text)
	}
}

var semverExact = regexp.MustCompile(`^(?:v|=)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// parseSemver parses a semver, including an optional v or = prefix.
// Partial versions (1.2) are rejected; callers that want npm's partial
// wildcard use the range parser.
func parseSemver(s string) (semver, bool) {
	m := semverExact.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	v := semver{major: atoi(m[1]), minor: atoi(m[2]), patch: atoi(m[3])}
	if m[4] != "" {
		for _, p := range strings.Split(m[4], ".") {
			if p == "" {
				return semver{}, false
			}
			id := preID{text: p}
			if n, err := strconv.Atoi(p); err == nil {
				id.num = n
				id.numeric = true
			}
			v.pre = append(v.pre, id)
		}
	}
	return v, true
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// pepver is a PEP 440 version without an epoch or a local segment.
type pepver struct {
	release []int
	preKind int // -1 none, 0 a, 1 b, 2 rc
	preNum  int
	hasPost bool
	post    int
	hasDev  bool
	dev     int
}

type infKey struct {
	kind int // -1 negInf, 0 value, 1 posInf
	a, b int
}

func cmpPep(a, b pepver) int {
	if c := cmpRelease(a.release, b.release); c != 0 {
		return c
	}
	if c := cmpInf(a.preKey(), b.preKey()); c != 0 {
		return c
	}
	if c := cmpInf(a.postKey(), b.postKey()); c != 0 {
		return c
	}
	return cmpInf(a.devKey(), b.devKey())
}

func cmpRelease(a, b []int) int {
	a, b = trimZeros(a), trimZeros(b)
	n := max(len(a), len(b))
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if c := cmp.Compare(av, bv); c != 0 {
			return c
		}
	}
	return 0
}

func trimZeros(v []int) []int {
	i := len(v)
	for i > 0 && v[i-1] == 0 {
		i--
	}
	if i == 0 {
		return nil
	}
	return v[:i]
}

func (p pepver) preKey() infKey {
	// A dev release with no pre or post sorts before every pre-release.
	// A final release sorts after every pre-release.
	if p.preKind < 0 && !p.hasPost && p.hasDev {
		return infKey{kind: -1}
	}
	if p.preKind < 0 {
		return infKey{kind: 1}
	}
	return infKey{a: p.preKind, b: p.preNum}
}

func (p pepver) postKey() infKey {
	if !p.hasPost {
		return infKey{kind: -1}
	}
	return infKey{a: p.post}
}

func (p pepver) devKey() infKey {
	if !p.hasDev {
		return infKey{kind: 1}
	}
	return infKey{a: p.dev}
}

func cmpInf(a, b infKey) int {
	if c := cmp.Compare(a.kind, b.kind); c != 0 {
		return c
	}
	if a.kind != 0 {
		return 0
	}
	if c := cmp.Compare(a.a, b.a); c != 0 {
		return c
	}
	return cmp.Compare(a.b, b.b)
}

var pepRe = regexp.MustCompile(`^(?i)v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:(a|alpha|b|beta|rc|c|preview)(\d*))?(?:(?:\.post|post|-)(\d+))?(?:\.dev(\d+))?$`)

func parsePep(s string) (pepver, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "+") {
		return pepver{}, false
	}
	m := pepRe.FindStringSubmatch(s)
	if m == nil || m[1] != "" {
		return pepver{}, false
	}
	var rel []int
	for _, p := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return pepver{}, false
		}
		rel = append(rel, n)
	}
	v := pepver{release: rel, preKind: -1}
	if m[3] != "" {
		v.preKind = preKind(m[3])
		if m[4] != "" {
			v.preNum = atoi(m[4])
		}
	}
	if m[5] != "" {
		v.hasPost = true
		v.post = atoi(m[5])
	}
	if m[6] != "" {
		v.hasDev = true
		v.dev = atoi(m[6])
	}
	return v, true
}

func preKind(s string) int {
	switch strings.ToLower(s) {
	case "a", "alpha":
		return 0
	case "b", "beta":
		return 1
	default:
		return 2
	}
}

// dev0 is the smallest version of a release prefix: its pre key is
// negative infinity, so every other build of that release sorts after it.
func pepDev0(release []int) pepver {
	return pepver{release: append([]int(nil), release...), preKind: -1, hasDev: true}
}

// iv is a half-open-capable version interval. loOK/hiOK false means
// that side is unbounded.
type iv[T any] struct {
	lo, hi     T
	loOK, hiOK bool
	loInc      bool
	hiInc      bool
}

func (i iv[T]) contains(v T, cmp func(T, T) int) bool {
	if i.loOK {
		c := cmp(v, i.lo)
		if c < 0 || (c == 0 && !i.loInc) {
			return false
		}
	}
	if i.hiOK {
		c := cmp(v, i.hi)
		if c > 0 || (c == 0 && !i.hiInc) {
			return false
		}
	}
	return true
}

func (a iv[T]) subset(b iv[T], cmp func(T, T) int) bool {
	if b.loOK {
		if !a.loOK {
			return false
		}
		c := cmp(a.lo, b.lo)
		if c < 0 || (c == 0 && a.loInc && !b.loInc) {
			return false
		}
	}
	if b.hiOK {
		if !a.hiOK {
			return false
		}
		c := cmp(a.hi, b.hi)
		if c > 0 || (c == 0 && a.hiInc && !b.hiInc) {
			return false
		}
	}
	return true
}

func intersect[T any](a, b iv[T], cmp func(T, T) int) (iv[T], bool) {
	out := a
	if b.loOK && (!a.loOK || cmp(b.lo, a.lo) > 0 || (cmp(b.lo, a.lo) == 0 && !b.loInc)) {
		out.lo, out.loOK, out.loInc = b.lo, true, b.loInc
	}
	if b.hiOK && (!a.hiOK || cmp(b.hi, a.hi) < 0 || (cmp(b.hi, a.hi) == 0 && !b.hiInc)) {
		out.hi, out.hiOK, out.hiInc = b.hi, true, b.hiInc
	}
	if out.loOK && out.hiOK {
		c := cmp(out.lo, out.hi)
		if c > 0 || (c == 0 && (!out.loInc || !out.hiInc)) {
			return iv[T]{}, false
		}
	}
	return out, true
}

func overlaps[T any](a, b iv[T], cmp func(T, T) int) bool {
	// a is to the left of b, or they touch on an included boundary.
	if a.hiOK && b.loOK {
		c := cmp(a.hi, b.lo)
		if c < 0 || (c == 0 && !a.hiInc && !b.loInc) {
			return false
		}
	}
	if b.hiOK && a.loOK {
		c := cmp(b.hi, a.lo)
		if c < 0 || (c == 0 && !b.hiInc && !a.loInc) {
			return false
		}
	}
	return true
}

func merge[T any](in []iv[T], cmp func(T, T) int) []iv[T] {
	if len(in) == 0 {
		return nil
	}
	out := append([]iv[T](nil), in...)
	// Insertion sort: a handful of ranges per advisory.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && lessLo(out[j], out[j-1], cmp) {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
	merged := []iv[T]{out[0]}
	for _, cur := range out[1:] {
		last := &merged[len(merged)-1]
		if !overlaps(*last, cur, cmp) {
			merged = append(merged, cur)
			continue
		}
		if cur.hiOK && last.hiOK {
			c := cmp(cur.hi, last.hi)
			if c > 0 || (c == 0 && cur.hiInc) {
				last.hi, last.hiInc = cur.hi, cur.hiInc
			}
		} else if !cur.hiOK {
			last.hiOK = false
		}
		if !cur.loOK {
			last.loOK = false
		}
	}
	return merged
}

func lessLo[T any](a, b iv[T], cmp func(T, T) int) bool {
	if !a.loOK {
		return b.loOK
	}
	if !b.loOK {
		return false
	}
	c := cmp(a.lo, b.lo)
	if c != 0 {
		return c < 0
	}
	return a.loInc && !b.loInc
}

func covered[T any](specs, affected []iv[T], cmp func(T, T) int) bool {
	if len(specs) == 0 {
		return false
	}
	merged := merge(affected, cmp)
	for _, s := range specs {
		ok := false
		for _, a := range merged {
			if s.subset(a, cmp) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// point is the inclusive singleton [v, v].
func point[T any](v T) iv[T] {
	return iv[T]{lo: v, hi: v, loOK: true, hiOK: true, loInc: true, hiInc: true}
}

func semverAffected(r Range) (iv[semver], error) {
	return affected(r, parseSemver, cmpSemver)
}

func pepAffected(r Range) (iv[pepver], error) {
	return affected(r, parsePep, cmpPep)
}

func affected[T any](r Range, parse func(string) (T, bool), cmp func(T, T) int) (iv[T], error) {
	var out iv[T]
	if r.Introduced != "" {
		v, ok := parse(r.Introduced)
		if !ok {
			return iv[T]{}, fmt.Errorf("introduced %q", r.Introduced)
		}
		out.lo, out.loOK, out.loInc = v, true, true
	}
	switch {
	case r.Fixed != "" && r.LastAffected != "":
		return iv[T]{}, fmt.Errorf("fixed and last_affected are both set")
	case r.Fixed != "":
		v, ok := parse(r.Fixed)
		if !ok {
			return iv[T]{}, fmt.Errorf("fixed %q", r.Fixed)
		}
		out.hi, out.hiOK, out.hiInc = v, true, false
	case r.LastAffected != "":
		v, ok := parse(r.LastAffected)
		if !ok {
			return iv[T]{}, fmt.Errorf("last_affected %q", r.LastAffected)
		}
		out.hi, out.hiOK, out.hiInc = v, true, true
	}
	if !out.loOK && !out.hiOK {
		return iv[T]{}, fmt.Errorf("range has no bound")
	}
	// introduced is below an exclusive fixed version, and at or below an
	// inclusive last_affected version.
	if out.loOK && out.hiOK {
		c := cmp(out.lo, out.hi)
		if c > 0 || (c == 0 && !out.hiInc) {
			return iv[T]{}, fmt.Errorf("introduced %q is not below the upper bound", r.Introduced)
		}
	}
	return out, nil
}

// versionIn reports whether v falls in any affected range of eco.
func versionIn(eco, v string, ranges []Range) (bool, error) {
	switch eco {
	case EcoNPM, EcoDocker:
		got, ok := parseSemver(v)
		if !ok {
			return false, fmt.Errorf("version %q", v)
		}
		for _, r := range ranges {
			iv, err := semverAffected(r)
			if err != nil {
				return false, err
			}
			if iv.contains(got, cmpSemver) {
				return true, nil
			}
		}
		return false, nil
	case EcoPyPI:
		got, ok := parsePep(v)
		if !ok {
			return false, fmt.Errorf("version %q", v)
		}
		for _, r := range ranges {
			iv, err := pepAffected(r)
			if err != nil {
				return false, err
			}
			if iv.contains(got, cmpPep) {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("ecosystem %q has no version order", eco)
	}
}

// rangeCovered reports whether every version the constraint admits is
// inside the union of ranges. A constraint that can resolve to a fixed
// version is not covered.
func rangeCovered(eco, constraint string, ranges []Range) (bool, error) {
	switch eco {
	case EcoNPM, EcoDocker:
		specs, err := parseNPMRanges(constraint)
		if err != nil {
			return false, err
		}
		var aff []iv[semver]
		for _, r := range ranges {
			iv, err := semverAffected(r)
			if err != nil {
				return false, err
			}
			aff = append(aff, iv)
		}
		return covered(specs, aff, cmpSemver), nil
	case EcoPyPI:
		specs, err := parsePyRanges(constraint)
		if err != nil {
			return false, err
		}
		var aff []iv[pepver]
		for _, r := range ranges {
			iv, err := pepAffected(r)
			if err != nil {
				return false, err
			}
			aff = append(aff, iv)
		}
		return covered(specs, aff, cmpPep), nil
	default:
		return false, fmt.Errorf("ecosystem %q has no version order", eco)
	}
}

// cmpVersion orders two versions in eco. It is false when either does
// not parse.
func cmpVersion(eco, a, b string) (int, bool) {
	switch eco {
	case EcoNPM, EcoDocker:
		av, aok := parseSemver(a)
		bv, bok := parseSemver(b)
		if !aok || !bok {
			return 0, false
		}
		return cmpSemver(av, bv), true
	case EcoPyPI:
		av, aok := parsePep(a)
		bv, bok := parsePep(b)
		if !aok || !bok {
			return 0, false
		}
		return cmpPep(av, bv), true
	default:
		return 0, false
	}
}

func formatSemver(v semver) string {
	s := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
	if len(v.pre) == 0 {
		return s
	}
	parts := make([]string, len(v.pre))
	for i, p := range v.pre {
		if p.numeric {
			parts[i] = strconv.Itoa(p.num)
		} else {
			parts[i] = p.text
		}
	}
	return s + "-" + strings.Join(parts, ".")
}

func formatPep(v pepver) string {
	parts := make([]string, len(v.release))
	for i, n := range v.release {
		parts[i] = strconv.Itoa(n)
	}
	s := strings.Join(parts, ".")
	if v.preKind >= 0 {
		s += []string{"a", "b", "rc"}[v.preKind] + strconv.Itoa(v.preNum)
	}
	if v.hasPost {
		s += ".post" + strconv.Itoa(v.post)
	}
	if v.hasDev {
		s += ".dev" + strconv.Itoa(v.dev)
	}
	return s
}

// CanonicalSemver returns s without a v or = prefix. The bool is false
// when s is not a full major.minor.patch semver.
func CanonicalSemver(s string) (string, bool) {
	v, ok := parseSemver(s)
	if !ok {
		return "", false
	}
	return formatSemver(v), true
}

// CanonicalPEP returns the canonical spelling of a PEP 440 version.
// The bool is false when s is outside the subset this package parses.
func CanonicalPEP(s string) (string, bool) {
	v, ok := parsePep(s)
	if !ok {
		return "", false
	}
	return formatPep(v), true
}
