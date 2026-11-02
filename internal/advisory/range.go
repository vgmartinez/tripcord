package advisory

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MaxSpecBytes and MaxSpecClauses bound one version specifier. != splits
// intervals, so work grows with the square of the clause count; a spec
// over either bound is opaque rather than evaluated.
const (
	MaxSpecBytes   = 256
	MaxSpecClauses = 32
)

// SpecWithinLimits reports whether a version specifier is small enough
// to evaluate. Clauses are PEP 440 comma parts and npm comparators
// across || alternatives.
func SpecWithinLimits(s string) bool {
	if len(s) > MaxSpecBytes {
		return false
	}
	return strings.Count(s, ",")+1 <= MaxSpecClauses && npmClauses(s) <= MaxSpecClauses
}

func npmClauses(s string) int {
	n := 0
	for _, part := range strings.Split(s, "||") {
		n += max(1, len(strings.Fields(part)))
	}
	return n
}

// parseNPMRanges parses an npm version constraint into the union of
// intervals it admits. Wildcards, ^, ~, hyphen ranges, and || are
// included. A constraint that does not parse is an error, which the
// caller treats as an opaque spec.
func parseNPMRanges(s string) ([]iv[semver], error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty npm range")
	}
	if !SpecWithinLimits(s) {
		return nil, fmt.Errorf("npm range exceeds %d bytes or %d clauses", MaxSpecBytes, MaxSpecClauses)
	}
	var out []iv[semver]
	for _, part := range strings.Split(s, "||") {
		iv, err := parseNPMAnd(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		out = append(out, iv)
	}
	return out, nil
}

var hyphenRange = regexp.MustCompile(`^([^\s]+)\s+-\s+([^\s]+)$`)

func parseNPMAnd(s string) (iv[semver], error) {
	if m := hyphenRange.FindStringSubmatch(s); m != nil && !strings.ContainsAny(m[1], "><=^~") && !strings.ContainsAny(m[2], "><=^~") {
		lo, err := npmPartial(m[1], true)
		if err != nil {
			return iv[semver]{}, err
		}
		hi, err := npmPartial(m[2], false)
		if err != nil {
			return iv[semver]{}, err
		}
		// The upper partial of a hyphen range is inclusive when it is a
		// full triple and exclusive at the next omitted component.
		out, ok := intersect(lo, hi, cmpSemver)
		if !ok {
			return iv[semver]{}, fmt.Errorf("npm range %q is empty", s)
		}
		return out, nil
	}
	toks, err := scanNPM(s)
	if err != nil {
		return iv[semver]{}, err
	}
	cur := iv[semver]{}
	for _, t := range toks {
		next, err := npmComparator(t)
		if err != nil {
			return iv[semver]{}, err
		}
		var ok bool
		cur, ok = intersect(cur, next, cmpSemver)
		if !ok {
			return iv[semver]{}, fmt.Errorf("npm range %q is empty", s)
		}
	}
	return cur, nil
}

type npmTok struct {
	op    string
	text  string
	major string
	minor string
	patch string
	pre   string
	parts int
	any   bool
}

var npmTokRe = regexp.MustCompile(`^(>=|<=|>|<|=|\^|~)?\s*(v)?(\d+|x|\*)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$`)

func scanNPM(s string) ([]npmTok, error) {
	var toks []npmTok
	rest := strings.TrimSpace(s)
	if rest == "" {
		return nil, fmt.Errorf("empty npm comparator")
	}
	for rest != "" {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		// A comparator runs until whitespace.
		field := rest
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			field, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		tok, err := parseNPMTok(field)
		if err != nil {
			return nil, err
		}
		toks = append(toks, tok)
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("npm range %q", s)
	}
	return toks, nil
}

func parseNPMTok(field string) (npmTok, error) {
	if field == "*" || field == "x" || field == "X" {
		return npmTok{any: true, parts: 0}, nil
	}
	m := npmTokRe.FindStringSubmatch(field)
	if m == nil {
		return npmTok{}, fmt.Errorf("npm comparator %q", field)
	}
	tok := npmTok{op: m[1], text: field, major: m[3], pre: m[6]}
	tok.parts = 1
	if m[4] != "" {
		tok.minor = m[4]
		tok.parts = 2
	}
	if m[5] != "" {
		tok.patch = m[5]
		tok.parts = 3
	}
	if wild(tok.major) || wild(tok.minor) || wild(tok.patch) {
		tok.any = tok.parts == 1 && wild(tok.major)
	}
	return tok, nil
}

func wild(s string) bool {
	return s == "x" || s == "X" || s == "*"
}

func npmNum(s string) (int, bool) {
	if s == "" || wild(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// npmPartial is one side of a hyphen range. lower uses the zero-filled
// version; upper uses an exclusive bound at the next omitted component.
func npmPartial(s string, lower bool) (iv[semver], error) {
	tok, err := parseNPMTok(s)
	if err != nil {
		return iv[semver]{}, err
	}
	if lower {
		v, err := tok.floor()
		if err != nil {
			return iv[semver]{}, err
		}
		return iv[semver]{lo: v, loOK: true, loInc: true}, nil
	}
	return tok.upper(), nil
}

func (t npmTok) floor() (semver, error) {
	if t.major == "" || wild(t.major) {
		return semver{}, nil
	}
	maj, ok := npmNum(t.major)
	if !ok {
		return semver{}, fmt.Errorf("npm version %q", t.text)
	}
	v := semver{major: maj}
	if t.parts >= 2 && !wild(t.minor) {
		v.minor, ok = npmNum(t.minor)
		if !ok {
			return semver{}, fmt.Errorf("npm version %q", t.text)
		}
	}
	if t.parts >= 3 && !wild(t.patch) {
		v.patch, ok = npmNum(t.patch)
		if !ok {
			return semver{}, fmt.Errorf("npm version %q", t.text)
		}
	}
	if t.pre != "" {
		parsed, ok := parseSemver(fmt.Sprintf("%d.%d.%d-%s", v.major, v.minor, v.patch, t.pre))
		if !ok {
			return semver{}, fmt.Errorf("npm prerelease %q", t.text)
		}
		v.pre = parsed.pre
	}
	return v, nil
}

// upper is the exclusive end of a partial or wildcard version.
func (t npmTok) upper() iv[semver] {
	if t.major == "" || wild(t.major) {
		return iv[semver]{}
	}
	v, err := t.floor()
	if err != nil {
		return iv[semver]{}
	}
	// A full triple with no wildcard is inclusive of itself.
	full := t.parts == 3 && !wild(t.minor) && !wild(t.patch)
	if full {
		return iv[semver]{hi: v, hiOK: true, hiInc: true}
	}
	switch {
	case t.parts <= 1 || wild(t.minor):
		v.minor, v.patch, v.pre = 0, 0, nil
		v.major++
	default:
		v.patch, v.pre = 0, nil
		v.minor++
	}
	return iv[semver]{hi: v, hiOK: true, hiInc: false}
}

func npmComparator(t npmTok) (iv[semver], error) {
	if t.op == "" && (t.any || wild(t.major)) {
		return iv[semver]{}, nil
	}
	v, err := t.floor()
	if err != nil {
		return iv[semver]{}, err
	}
	wildcard := t.any || wild(t.major) || wild(t.minor) || wild(t.patch) || (t.op == "" && t.parts < 3) || (t.op == "=" && t.parts < 3)
	switch t.op {
	case "", "=":
		if wildcard || t.parts < 3 {
			lo := iv[semver]{lo: v, loOK: true, loInc: true}
			hi := t.upper()
			out, ok := intersect(lo, hi, cmpSemver)
			if !ok {
				return iv[semver]{}, fmt.Errorf("npm range %q is empty", t.text)
			}
			return out, nil
		}
		return point(v), nil
	case ">=":
		return iv[semver]{lo: v, loOK: true, loInc: true}, nil
	case ">":
		return iv[semver]{lo: v, loOK: true, loInc: false}, nil
	case "<=":
		return iv[semver]{hi: v, hiOK: true, hiInc: true}, nil
	case "<":
		return iv[semver]{hi: v, hiOK: true, hiInc: false}, nil
	case "^":
		return caret(v), nil
	case "~":
		return tilde(v, t.parts), nil
	default:
		return iv[semver]{}, fmt.Errorf("npm operator %q", t.op)
	}
}

func caret(v semver) iv[semver] {
	hi := semver{}
	switch {
	case v.major > 0:
		hi.major = v.major + 1
	case v.minor > 0:
		hi.minor = v.minor + 1
	default:
		hi.patch = v.patch + 1
	}
	return iv[semver]{lo: v, loOK: true, loInc: true, hi: hi, hiOK: true, hiInc: false}
}

func tilde(v semver, parts int) iv[semver] {
	hi := semver{major: v.major}
	if parts <= 1 {
		hi.major = v.major + 1
	} else {
		hi.minor = v.minor + 1
	}
	return iv[semver]{lo: v, loOK: true, loInc: true, hi: hi, hiOK: true, hiInc: false}
}

// parsePyRanges parses a PEP 440 specifier set (comma-separated AND;
// there is no OR). != splits an interval in two.
func parsePyRanges(s string) ([]iv[pepver], error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty version specifier")
	}
	if !SpecWithinLimits(s) {
		return nil, fmt.Errorf("version specifier exceeds %d bytes or %d clauses", MaxSpecBytes, MaxSpecClauses)
	}
	parts := strings.Split(s, ",")
	cur := []iv[pepver]{{}}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty version specifier clause")
		}
		next, exclude, err := pyClause(part)
		if err != nil {
			return nil, err
		}
		var out []iv[pepver]
		for _, iv := range cur {
			if exclude {
				out = append(out, excludePoint(iv, next)...)
				continue
			}
			got, ok := intersect(iv, next, cmpPep)
			if ok {
				out = append(out, got)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("version specifier %q is empty", s)
		}
		cur = out
	}
	return cur, nil
}

// pyClause parses one comparator. exclude is set for !=, and the
// returned interval is then the singleton to remove.
func pyClause(s string) (iv[pepver], bool, error) {
	op, ver, ok := splitPyOp(s)
	if !ok {
		return iv[pepver]{}, false, fmt.Errorf("version specifier %q", s)
	}
	if op == "!=" {
		v, err := pyExact(ver)
		if err != nil {
			return iv[pepver]{}, false, err
		}
		return point(v), true, nil
	}
	if op == "~=" {
		got, err := pyCompatible(ver)
		if err != nil {
			return iv[pepver]{}, false, err
		}
		return got, false, nil
	}
	if op == "==" || op == "===" {
		if strings.HasSuffix(ver, ".*") {
			got, err := pyWildcard(strings.TrimSuffix(ver, ".*"))
			if err != nil {
				return iv[pepver]{}, false, err
			}
			return got, false, nil
		}
		v, err := pyExact(ver)
		if err != nil {
			return iv[pepver]{}, false, err
		}
		return point(v), false, nil
	}
	v, err := pyExact(ver)
	if err != nil {
		return iv[pepver]{}, false, err
	}
	switch op {
	case ">=":
		return iv[pepver]{lo: v, loOK: true, loInc: true}, false, nil
	case ">":
		return iv[pepver]{lo: v, loOK: true, loInc: false}, false, nil
	case "<=":
		return iv[pepver]{hi: v, hiOK: true, hiInc: true}, false, nil
	case "<":
		return iv[pepver]{hi: v, hiOK: true, hiInc: false}, false, nil
	default:
		return iv[pepver]{}, false, fmt.Errorf("version operator %q", op)
	}
}

func splitPyOp(s string) (op, ver string, ok bool) {
	for _, op := range []string{"===", "==", "~=", "!=", ">=", "<=", ">", "<"} {
		if strings.HasPrefix(s, op) {
			return op, strings.TrimSpace(s[len(op):]), true
		}
	}
	return "", "", false
}

func pyExact(s string) (pepver, error) {
	v, ok := parsePep(s)
	if !ok {
		return pepver{}, fmt.Errorf("version %q", s)
	}
	return v, nil
}

// pyWildcard is ==1.2.* : everything from the first dev of that prefix
// up to, but not including, the first dev of the next prefix.
func pyWildcard(prefix string) (iv[pepver], error) {
	if prefix == "" || strings.Contains(prefix, "*") {
		return iv[pepver]{}, fmt.Errorf("version wildcard %q", prefix)
	}
	base, err := pyExact(prefix)
	if err != nil {
		return iv[pepver]{}, err
	}
	if base.preKind >= 0 || base.hasPost || base.hasDev {
		return iv[pepver]{}, fmt.Errorf("version wildcard %q", prefix)
	}
	rel := append([]int(nil), base.release...)
	hiRel := append([]int(nil), rel...)
	hiRel[len(hiRel)-1]++
	return iv[pepver]{
		lo: pepDev0(rel), loOK: true, loInc: true,
		hi: pepDev0(hiRel), hiOK: true, hiInc: false,
	}, nil
}

// pyCompatible is ~=1.4.2, which is >=1.4.2 combined with ==1.4.*.
func pyCompatible(s string) (iv[pepver], error) {
	v, err := pyExact(s)
	if err != nil {
		return iv[pepver]{}, err
	}
	rel := trimZeros(v.release)
	if len(rel) < 2 || v.preKind >= 0 || v.hasDev {
		return iv[pepver]{}, fmt.Errorf("compatible release %q", s)
	}
	prefix := rel[:len(rel)-1]
	hiRel := append([]int(nil), prefix...)
	hiRel[len(hiRel)-1]++
	return iv[pepver]{
		lo: v, loOK: true, loInc: true,
		hi: pepDev0(hiRel), hiOK: true, hiInc: false,
	}, nil
}

func excludePoint(in iv[pepver], drop iv[pepver]) []iv[pepver] {
	if !drop.loOK || !drop.hiOK || cmpPep(drop.lo, drop.hi) != 0 {
		return []iv[pepver]{in}
	}
	pt := drop.lo
	if !in.contains(pt, cmpPep) {
		return []iv[pepver]{in}
	}
	var out []iv[pepver]
	left := in
	left.hi, left.hiOK, left.hiInc = pt, true, false
	if intervalOK(left, cmpPep) {
		out = append(out, left)
	}
	right := in
	right.lo, right.loOK, right.loInc = pt, true, false
	if intervalOK(right, cmpPep) {
		out = append(out, right)
	}
	return out
}

// NPMRangeOK reports whether s is an npm version range this package can
// compare. Callers treat a false result as an opaque spec.
func NPMRangeOK(s string) bool {
	_, err := parseNPMRanges(s)
	return err == nil
}

// PyRangeOK reports whether s is a PEP 440 specifier set this package
// can compare.
func PyRangeOK(s string) bool {
	_, err := parsePyRanges(s)
	return err == nil
}

func intervalOK[T any](i iv[T], cmp func(T, T) int) bool {
	if !i.loOK || !i.hiOK {
		return true
	}
	c := cmp(i.lo, i.hi)
	return c < 0 || (c == 0 && i.loInc && i.hiInc)
}
