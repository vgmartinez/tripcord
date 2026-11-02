package advisory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// AdvisoryFile is the name of the embedded list beside a pack's rules.
const AdvisoryFile = "ADVISORIES.json"

// Redacted is the marker a sanitized argument uses in place of a secret.
// A spec that contains it is opaque and never matches.
const Redacted = "[REDACTED]"

const advisoryFormat = 1

var (
	advisoryIDPattern = regexp.MustCompile(`^TCA-[0-9]{4}-[0-9]{4}$`)
	packAddedPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*@[0-9]{4}\.(0[1-9]|1[0-2])(\.(0|[1-9][0-9]*))?$`)
	hexCommit         = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	pep503Sep         = regexp.MustCompile(`[-_.]+`)
)

// Range is one affected interval. introduced is inclusive and omitted
// means every version before the upper bound. fixed is exclusive.
// last_affected is inclusive. fixed and last_affected are mutually
// exclusive.
type Range struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// Signature is a module or path that identifies an unpackaged server.
type Signature struct {
	Module     string `json:"module,omitempty"`
	PathSuffix string `json:"path_suffix,omitempty"`
}

// Affected is one ecosystem entry of an advisory.
type Affected struct {
	Ecosystem       string      `json:"ecosystem"`
	Name            string      `json:"name,omitempty"`
	Repo            string      `json:"repo,omitempty"`
	Ranges          []Range     `json:"ranges,omitempty"`
	AffectedCommits []string    `json:"affected_commits,omitempty"`
	Signatures      []Signature `json:"signatures,omitempty"`
}

// Advisory is one embedded advisory. Withdrawn is set instead of
// deleting the id.
type Advisory struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Summary   string     `json:"summary"`
	Severity  string     `json:"severity"`
	Affected  []Affected `json:"affected"`
	Refs      []string   `json:"refs"`
	Added     string     `json:"added"`
	Reviewed  string     `json:"reviewed"`
	Withdrawn string     `json:"withdrawn,omitempty"`
}

type advisoryDocument struct {
	Format     int        `json:"format"`
	Advisories []Advisory `json:"advisories"`
}

// PackageRef is one package a launcher argv names.
type PackageRef struct {
	Ecosystem string
	Name      string
	Spec      string
	Kind      string
	Version   string
	Repo      string
}

// Hit is one advisory that matches a package ref. Severity is the
// advisory's own severity, not the finding severity.
type Hit struct {
	ID        string
	Aliases   []string
	Severity  string
	Ecosystem string
	Name      string
	Spec      string
	Kind      string
	Version   string
	Fixed     string
	PURL      string
	Refs      []string
	Repo      string
}

// DB is an offline advisory list. A nil DB matches nothing.
type DB struct {
	advisories []Advisory
	byID       map[string]Advisory
	byPkg      map[string][]int
	git        map[string][]int
	modules    []int
}

// Parse decodes and validates an ADVISORIES.json document. An empty
// document is an empty list. Unknown fields are rejected.
func Parse(data []byte) (*DB, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return &DB{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc advisoryDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("advisories: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("advisories: trailing data")
	}
	if doc.Format != advisoryFormat {
		return nil, fmt.Errorf("advisories: format %d, want %d", doc.Format, advisoryFormat)
	}
	db := &DB{
		byID:  map[string]Advisory{},
		byPkg: map[string][]int{},
		git:   map[string][]int{},
	}
	for i := range doc.Advisories {
		a := doc.Advisories[i]
		if err := validateAdvisory(&a); err != nil {
			return nil, fmt.Errorf("advisories: %s: %w", advisoryLabel(a, i), err)
		}
		if _, ok := db.byID[a.ID]; ok {
			return nil, fmt.Errorf("advisories: %s is listed twice", a.ID)
		}
		db.byID[a.ID] = a
		idx := len(db.advisories)
		db.advisories = append(db.advisories, a)
		db.index(idx, a)
	}
	return db, nil
}

func advisoryLabel(a Advisory, i int) string {
	if a.ID != "" {
		return a.ID
	}
	return fmt.Sprintf("entry %d", i)
}

func (db *DB) index(idx int, a Advisory) {
	for _, aff := range a.Affected {
		switch aff.Ecosystem {
		case EcoGit:
			repo, opaque := NormalizeRepo(aff.Repo)
			if !opaque {
				db.git[repo] = append(db.git[repo], idx)
			}
		case EcoModule:
			db.modules = append(db.modules, idx)
		default:
			name := NormalizeName(aff.Ecosystem, aff.Name)
			key := aff.Ecosystem + "\x00" + name
			db.byPkg[key] = append(db.byPkg[key], idx)
		}
	}
}

// Len is the number of advisories, withdrawn ones included.
func (db *DB) Len() int {
	if db == nil {
		return 0
	}
	return len(db.advisories)
}

// Count is the number of advisories that have not been withdrawn.
func (db *DB) Count() int {
	if db == nil {
		return 0
	}
	n := 0
	for _, a := range db.advisories {
		if a.Withdrawn == "" {
			n++
		}
	}
	return n
}

// LatestReview is the newest reviewed date, or "" when the list is empty.
func (db *DB) LatestReview() string {
	if db == nil {
		return ""
	}
	latest := ""
	for _, a := range db.advisories {
		if a.Reviewed > latest {
			latest = a.Reviewed
		}
	}
	return latest
}

// Current returns the advisories that have not been withdrawn, in file order.
func (db *DB) Current() []Advisory {
	if db == nil {
		return nil
	}
	var out []Advisory
	for _, a := range db.advisories {
		if a.Withdrawn == "" {
			out = append(out, a)
		}
	}
	return out
}

// CheckEvolution reports an id that disappeared or a withdrawn date that
// was cleared. Field corrections and newly withdrawn ids are allowed.
// old may be nil or empty.
func CheckEvolution(old, next *DB) error {
	if next == nil {
		next = &DB{}
	}
	if old == nil {
		return nil
	}
	var errs []error
	for _, prev := range old.advisories {
		cur, ok := next.byID[prev.ID]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s: removed from ADVISORIES.json; set withdrawn instead of deleting it", prev.ID))
		case prev.Withdrawn != "" && cur.Withdrawn == "":
			errs = append(errs, fmt.Errorf("%s: withdrawn %s was cleared", prev.ID, prev.Withdrawn))
		}
	}
	return errors.Join(errs...)
}

func validateAdvisory(a *Advisory) error {
	if !advisoryIDPattern.MatchString(a.ID) {
		return fmt.Errorf("id %q: want TCA-YYYY-NNNN", a.ID)
	}
	if strings.TrimSpace(a.Summary) == "" {
		return errors.New("summary is required")
	}
	switch a.Severity {
	case "critical", "high", "moderate", "low":
	default:
		return fmt.Errorf("severity %q: want critical, high, moderate, or low", a.Severity)
	}
	if !packAddedPattern.MatchString(a.Added) {
		return fmt.Errorf("added %q: want <namespace>/<name>@YYYY.MM[.N]", a.Added)
	}
	if _, err := time.Parse("2006-01-02", a.Reviewed); err != nil {
		return fmt.Errorf("reviewed %q: want YYYY-MM-DD", a.Reviewed)
	}
	if a.Withdrawn != "" {
		if _, err := time.Parse("2006-01-02", a.Withdrawn); err != nil {
			return fmt.Errorf("withdrawn %q: want YYYY-MM-DD", a.Withdrawn)
		}
	}
	if len(a.Affected) == 0 {
		return errors.New("affected needs at least one entry")
	}
	if len(a.Refs) == 0 {
		return errors.New("refs needs at least one https URL")
	}
	for _, ref := range a.Refs {
		if err := validateHTTPS(ref); err != nil {
			return err
		}
	}
	if a.Aliases == nil {
		a.Aliases = []string{}
	}
	for _, aff := range a.Affected {
		if err := validateAffected(aff); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPS(ref string) error {
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("refs: %q must be an https URL", ref)
	}
	return nil
}

func validateAffected(aff Affected) error {
	switch aff.Ecosystem {
	case EcoNPM, EcoPyPI, EcoDocker:
		if strings.TrimSpace(aff.Name) == "" {
			return fmt.Errorf("%s: name is required", aff.Ecosystem)
		}
		if len(aff.Ranges) == 0 {
			return fmt.Errorf("%s %s: ranges are required", aff.Ecosystem, aff.Name)
		}
		for _, r := range aff.Ranges {
			if _, err := affectedInterval(aff.Ecosystem, r); err != nil {
				return fmt.Errorf("%s %s: %w", aff.Ecosystem, aff.Name, err)
			}
		}
	case EcoGit:
		if _, opaque := NormalizeRepo(aff.Repo); opaque {
			return fmt.Errorf("git repo %q is not a public repository URL", aff.Repo)
		}
		if len(aff.Ranges) > 0 {
			return errors.New("git advisories have no version ranges; commit order is not computable offline")
		}
		for _, c := range aff.AffectedCommits {
			if !hexCommit.MatchString(c) {
				return fmt.Errorf("affected commit %q: want 40 hex digits", c)
			}
		}
		if len(aff.AffectedCommits) == 0 {
			return errors.New("git advisories need affected_commits")
		}
	case EcoModule:
		if len(aff.Signatures) == 0 {
			return errors.New("module advisories need signatures")
		}
		for _, r := range aff.Ranges {
			if r.Fixed != "" || r.LastAffected != "" || r.Introduced != "" {
				return errors.New("module advisories cannot carry a version range")
			}
		}
		for _, sig := range aff.Signatures {
			if sig.Module == "" && sig.PathSuffix == "" {
				return errors.New("module signature needs module or path_suffix")
			}
		}
	default:
		return fmt.Errorf("ecosystem %q: want npm, pypi, docker, git, or module", aff.Ecosystem)
	}
	return nil
}

func affectedInterval(eco string, r Range) (struct{}, error) {
	var err error
	switch eco {
	case EcoNPM, EcoDocker:
		_, err = semverAffected(r)
	case EcoPyPI:
		_, err = pepAffected(r)
	default:
		err = fmt.Errorf("ecosystem %q has no version order", eco)
	}
	return struct{}{}, err
}

// NormalizeName returns the ecosystem's comparison form of a package name.
func NormalizeName(eco, name string) string {
	switch eco {
	case EcoPyPI:
		return pep503Sep.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	case EcoDocker:
		return NormalizeDocker(name)
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

// NormalizeDocker applies the implicit docker.io names a reference
// without a registry uses. A name with no slash is library/. A name
// with one slash whose first component has no dot or colon is on
// docker.io. Anything else is already a registry path.
func NormalizeDocker(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch strings.Count(name, "/") {
	case 0:
		return "docker.io/library/" + name
	case 1:
		first, _, _ := strings.Cut(name, "/")
		if !strings.ContainsAny(first, ".:") {
			return "docker.io/" + name
		}
	}
	return name
}

// NormalizeRepo returns the comparison form of a git repository URL:
// git+ stripped, host lowercased, .git and a trailing slash removed.
// opaque is true when the URL carries userinfo or the redaction marker,
// which must not be matched and must not be copied into a finding.
func NormalizeRepo(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, Redacted) {
		return "", true
	}
	if strings.HasPrefix(raw, "github:") {
		rest := strings.TrimPrefix(raw, "github:")
		rest = strings.TrimSuffix(rest, ".git")
		rest = strings.Trim(rest, "/")
		if rest == "" || strings.Contains(rest, "://") || strings.Contains(rest, "@") {
			return "", true
		}
		return "https://github.com/" + rest, false
	}
	s := strings.TrimPrefix(raw, "git+")
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil {
		return "", true
	}
	switch u.Scheme {
	case "https", "http", "ssh", "git":
	default:
		return "", true
	}
	path := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	if path == "" || path == "/" {
		return "", true
	}
	scheme := u.Scheme
	if scheme == "ssh" || scheme == "git" {
		scheme = "https"
	}
	return scheme + "://" + strings.ToLower(u.Host) + path, false
}

// PURL is the canonical package URL of a ref. An exact version is the
// version alone. A range keeps the constraint text.
func (r PackageRef) PURL() string {
	switch r.Ecosystem {
	case EcoNPM:
		return "pkg:npm/" + strings.ReplaceAll(r.Name, "@", "%40") + "@" + r.Version
	case EcoPyPI:
		return "pkg:pypi/" + r.Name + "@" + r.Version
	case EcoDocker:
		return "pkg:docker/" + r.Name + "@" + r.Version
	case EcoGit:
		p := "pkg:generic/" + strings.TrimPrefix(strings.TrimPrefix(r.Repo, "https://"), "http://")
		if r.Kind == KindExact && r.Version != "" {
			p += "@" + r.Version
		}
		return p
	case EcoModule:
		return "pkg:generic/" + r.Name
	default:
		return ""
	}
}

// Match returns the advisories whose affected ranges contain ref.
// digest and opaque refs never match. Hits are deduped by advisory id
// and package URL and sorted by ecosystem, name, and id.
func (db *DB) Match(refs []PackageRef) ([]Hit, error) {
	if db == nil || len(refs) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	var hits []Hit
	for _, ref := range refs {
		if ref.Kind == KindDigest || ref.Kind == KindOpaque {
			continue
		}
		for _, idx := range db.candidates(ref) {
			a := db.advisories[idx]
			if a.Withdrawn != "" {
				continue
			}
			for _, aff := range a.Affected {
				hit, ok, err := matchAffected(a, aff, ref)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
				key := hit.ID + "\x00" + hit.PURL
				if seen[key] {
					continue
				}
				seen[key] = true
				hits = append(hits, hit)
			}
		}
	}
	slices.SortFunc(hits, func(a, b Hit) int {
		if c := strings.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
			return c
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return hits, nil
}

func (db *DB) candidates(ref PackageRef) []int {
	switch ref.Ecosystem {
	case EcoGit:
		return db.git[ref.Repo]
	case EcoModule:
		return db.modules
	default:
		return db.byPkg[ref.Ecosystem+"\x00"+ref.Name]
	}
}

func matchAffected(a Advisory, aff Affected, ref PackageRef) (Hit, bool, error) {
	if aff.Ecosystem != ref.Ecosystem {
		return Hit{}, false, nil
	}
	var ok bool
	var err error
	switch aff.Ecosystem {
	case EcoNPM, EcoPyPI, EcoDocker:
		if NormalizeName(aff.Ecosystem, aff.Name) != ref.Name {
			return Hit{}, false, nil
		}
		ok, err = versionMatch(aff, ref)
	case EcoGit:
		repo, opaque := NormalizeRepo(aff.Repo)
		if opaque || repo != ref.Repo {
			return Hit{}, false, nil
		}
		ok = gitMatch(aff, ref, advisoryFixed(a))
	case EcoModule:
		var sig string
		sig, ok = signatureMatch(aff, ref)
		ok = ok && !advisoryFixed(a)
		// The argv path can be absolute; only the signature is stable
		// and free of local paths.
		ref.Name, ref.Spec = sig, sig
	default:
		return Hit{}, false, nil
	}
	if err != nil || !ok {
		return Hit{}, false, err
	}
	hit := Hit{
		ID:        a.ID,
		Aliases:   append([]string(nil), a.Aliases...),
		Severity:  a.Severity,
		Ecosystem: ref.Ecosystem,
		Name:      ref.Name,
		Spec:      ref.Spec,
		Kind:      ref.Kind,
		Version:   ref.Version,
		Fixed:     fixedOf(aff),
		PURL:      ref.PURL(),
		Refs:      append([]string(nil), a.Refs...),
		Repo:      ref.Repo,
	}
	return hit, true, nil
}

func versionMatch(aff Affected, ref PackageRef) (bool, error) {
	switch ref.Kind {
	case KindExact:
		return versionIn(aff.Ecosystem, ref.Version, aff.Ranges)
	case KindRange:
		return rangeCovered(aff.Ecosystem, ref.Version, aff.Ranges)
	case KindUnpinned:
		return !hasFixed(aff), nil
	default:
		return false, nil
	}
}

// gitMatch matches any ref, commit, tag, or branch, when the advisory
// has no fix: no ref of the repository is known to be safe. With a fix,
// only an affected commit matches. Git entries carry no ranges, so
// fixed is decided over the whole advisory.
func gitMatch(aff Affected, ref PackageRef, fixed bool) bool {
	switch ref.Kind {
	case KindExact:
		if !fixed {
			return ref.Version != ""
		}
		refHex := strings.ToLower(ref.Version)
		if len(refHex) < 7 || !isHex(refHex) {
			return false
		}
		for _, c := range aff.AffectedCommits {
			if strings.HasPrefix(strings.ToLower(c), refHex) {
				return true
			}
		}
		return false
	case KindUnpinned:
		return !fixed
	default:
		return false
	}
}

func isHex(s string) bool {
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return s != ""
}

// signatureMatch returns the signature ref matched, never ref's own path.
func signatureMatch(aff Affected, ref PackageRef) (string, bool) {
	for _, sig := range aff.Signatures {
		if sig.Module != "" && ref.Name == sig.Module {
			return sig.Module, true
		}
		if sig.PathSuffix != "" && pathSuffixMatch(sig.PathSuffix, ref.Name) {
			return strings.ReplaceAll(sig.PathSuffix, `\`, `/`), true
		}
	}
	return "", false
}

func pathSuffixMatch(sig, path string) bool {
	path = strings.TrimPrefix(strings.ReplaceAll(path, `\`, `/`), "./")
	sig = strings.ReplaceAll(sig, `\`, `/`)
	return path == sig || strings.HasSuffix(path, "/"+sig)
}

func advisoryFixed(a Advisory) bool {
	for _, aff := range a.Affected {
		if hasFixed(aff) {
			return true
		}
	}
	return false
}

func hasFixed(aff Affected) bool {
	for _, r := range aff.Ranges {
		if r.Fixed != "" {
			return true
		}
	}
	return false
}

func fixedOf(aff Affected) string {
	best := ""
	for _, r := range aff.Ranges {
		if r.Fixed == "" {
			continue
		}
		if best == "" {
			best = r.Fixed
			continue
		}
		if c, ok := cmpVersion(aff.Ecosystem, r.Fixed, best); ok && c > 0 {
			best = r.Fixed
		}
	}
	return best
}

// Excerpt is the fingerprint text of hits: sorted package URLs, then
// sorted advisory ids, separated by single spaces.
func Excerpt(hits []Hit) string {
	var purls, ids []string
	seenP, seenI := map[string]bool{}, map[string]bool{}
	for _, h := range hits {
		if h.PURL != "" && !seenP[h.PURL] {
			seenP[h.PURL] = true
			purls = append(purls, h.PURL)
		}
		if h.ID != "" && !seenI[h.ID] {
			seenI[h.ID] = true
			ids = append(ids, h.ID)
		}
	}
	slices.Sort(purls)
	slices.Sort(ids)
	return strings.Join(append(purls, ids...), " ")
}

// Title is the per-match title. Hits of the same package and version
// share one clause. server is the MCP server name.
func Title(server string, hits []Hit) string {
	if strings.TrimSpace(server) == "" {
		server = "server"
	}
	type group struct {
		order   int
		display string
		hits    []Hit
		noFix   bool
		fixed   string
	}
	var groups []group
	index := map[string]int{}
	for _, h := range hits {
		key := h.Ecosystem + "\x00" + h.Name + "\x00" + h.Version
		i, ok := index[key]
		if !ok {
			i = len(groups)
			index[key] = i
			groups = append(groups, group{order: i, display: displayPkg(h)})
		}
		g := &groups[i]
		g.hits = append(g.hits, h)
		if h.Fixed == "" {
			g.noFix = true
			continue
		}
		if g.fixed == "" {
			g.fixed = h.Fixed
			continue
		}
		if c, ok := cmpVersion(h.Ecosystem, h.Fixed, g.fixed); ok && c > 0 {
			g.fixed = h.Fixed
		}
	}
	parts := make([]string, len(groups))
	for i, g := range groups {
		clause := "has no fixed version"
		if !g.noFix && g.fixed != "" {
			clause = "fixed in " + g.fixed
		}
		parts[i] = fmt.Sprintf("MCP server %s pins %s: %s (%s)", server, g.display, aliasList(g.hits), clause)
	}
	return strings.Join(parts, "; ")
}

func displayPkg(h Hit) string {
	switch h.Ecosystem {
	case EcoGit:
		name := strings.TrimPrefix(strings.TrimPrefix(h.Repo, "https://"), "http://")
		if name == "" {
			name = h.Name
		}
		if h.Kind == KindExact && h.Version != "" {
			return name + "@" + h.Version
		}
		return name
	case EcoModule:
		return h.Name
	default:
		if h.Version == "" {
			return h.Name
		}
		return h.Name + "@" + h.Version
	}
}

func aliasList(hits []Hit) string {
	var cve, ghsa, other, ids []string
	seen := map[string]bool{}
	for _, h := range hits {
		if !seen[h.ID] {
			seen[h.ID] = true
			ids = append(ids, h.ID)
		}
		for _, a := range h.Aliases {
			if seen[a] {
				continue
			}
			seen[a] = true
			switch {
			case strings.HasPrefix(a, "CVE-"):
				cve = append(cve, a)
			case strings.HasPrefix(a, "GHSA-"):
				ghsa = append(ghsa, a)
			default:
				other = append(other, a)
			}
		}
	}
	slices.Sort(cve)
	slices.Sort(ghsa)
	slices.Sort(other)
	labels := append(append(cve, ghsa...), other...)
	if len(labels) == 0 {
		slices.Sort(ids)
		labels = ids
	}
	return strings.Join(labels, ", ")
}

// Refs returns rule refs followed by the advisory refs of hits, in
// order, without duplicates.
func Refs(rule []string, hits []Hit) []string {
	seen := map[string]bool{}
	var out []string
	add := func(r string) {
		if r == "" || seen[r] {
			return
		}
		seen[r] = true
		out = append(out, r)
	}
	for _, r := range rule {
		add(r)
	}
	for _, h := range hits {
		for _, r := range h.Refs {
			add(r)
		}
	}
	return out
}
