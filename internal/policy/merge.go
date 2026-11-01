package policy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"time"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// LayerKind is where a policy layer comes from. Layers merge in the
// order default, org, extends, repo, local: later layers override
// earlier ones except where an earlier layer locked a value.
type LayerKind string

const (
	LayerDefault LayerKind = "default"
	// LayerOrg is the managed policy, the --org-policy files, and what
	// they extend: sources the repository does not control.
	LayerOrg LayerKind = "org"
	// LayerExtends is what the repo policy extends. It merges after the
	// org layer and cannot replace it.
	LayerExtends LayerKind = "extends"
	LayerRepo    LayerKind = "repo"
	LayerLocal   LayerKind = "local"
)

// Origin records which layer and file set a value.
type Origin struct {
	Layer  LayerKind
	Source string
}

// Layer is one parsed policy file in merge order.
type Layer struct {
	Kind   LayerKind
	Source string
	File   *File
}

// RuleCatalog supplies the rules that lock checks need (base severity,
// pack, harnesses) and the ids that custom rules must not reuse.
// *rules.Catalog implements it.
type RuleCatalog interface {
	Rule(id string) (*rules.Rule, bool)
	Rules() []*rules.Rule
}

// Exception is a validated exceptions entry.
type Exception struct {
	Rule   string
	Path   string
	SHA256 string
	Reason string
	// Expires is the last day the exception applies, at 00:00 UTC.
	Expires time.Time
	Origin  Origin
}

// CustomRule is a compiled custom entry.
type CustomRule struct {
	ID string
	// When is nil when the entry has no precondition.
	When     *rules.Expr
	DenyIf   *rules.Expr
	Message  string
	Severity model.Severity
	Origin   Origin
}

// RuleLock is a locked.rules pattern and the severity overrides in
// effect when it was declared.
type RuleLock struct {
	Pattern   string
	Origin    Origin
	overrides map[string]model.Severity
}

// ExemptionLock stops a later layer from exempting a rule. It cannot
// add an exception for the rule, and rules.include, the allowlist,
// cannot drop it. locked.rules and locked.exceptions both create these.
type ExemptionLock struct {
	Pattern string
	Origin  Origin
}

// ModeLock is a locked mode: later layers cannot pick a weaker mode.
// Locking the mode also locks fail-on to a ceiling, the value in effect
// when the mode was locked: a later layer may lower fail-on (stricter,
// high to medium) but not raise it (weaker, high to critical), since
// that would hollow out the mode lock.
type ModeLock struct {
	Floor         Mode
	FailOnCeiling model.Severity
	Origin        Origin
}

// PackFloor is the lowest version a later layer may pin for a pack.
// locked.rules and locked.exceptions set it to the version in effect
// when they were declared: the pinned version, or the version of the
// catalog rules the lock covers. A pin below it would swap the locked
// rules for older ones.
type PackFloor struct {
	Version string
	Origin  Origin
}

// HarnessLock keeps a harness in the harnesses list. locked.rules and
// locked.exceptions create one for each listed harness that a locked
// rule covers, or for every listed harness when the catalog knows no
// rule the lock matches. Dropping the harness would exempt the locked
// rules on it.
type HarnessLock struct {
	Harness model.Harness
	Origin  Origin
}

// Effective is the merged policy. Provenance maps a value path to the
// layer that set it. Keys are "mode", "pack.<name>", "harnesses",
// "rules.include", "rules.severity_overrides.<id>",
// "rules.exceptions[<i>]" (index into Exceptions), "custom.<id>",
// "secrets.rulesets", "secrets.store", "privacy.egress",
// "privacy.redact", "cloud.report_channel", "fail-on", "locked.mode",
// "locked.rules[<pattern>]", and "locked.exceptions[<pattern>]".
type Effective struct {
	Mode Mode
	// FailOn is the lowest severity that fails the run. The zero value
	// never fails. It starts as the surface default and a policy layer
	// replaces it.
	FailOn            model.Severity
	Packs             []rules.PackRef
	Harnesses         []model.Harness
	Include           []string
	SeverityOverrides map[string]model.Severity
	Exceptions        []Exception
	Custom            []*CustomRule
	SecretRulesets    []string
	SecretStore       string
	Egress            string
	Redact            bool
	ReportChannel     []string
	ModeLock          *ModeLock
	RuleLocks         []RuleLock
	ExemptionLocks    []ExemptionLock
	PackFloors        map[string]PackFloor
	HarnessLocks      []HarnessLock
	Provenance        map[string]Origin
	Layers            []Origin
}

var defaultOrigin = Origin{Layer: LayerDefault, Source: "default"}

// defaults is the policy with no files. Mode and fail-on come from the
// surface (DefaultsFor). The other values are the spec sample's
// local-only choices (every harness, every rule, no egress, redacted,
// fingerprint store).
func defaults(d Defaults) *Effective {
	e := &Effective{
		Mode:   d.Mode,
		FailOn: d.FailOn,
		Harnesses: []model.Harness{
			model.HarnessClaude, model.HarnessCodex, model.HarnessCursor, model.HarnessCopilot,
			model.HarnessGemini, model.HarnessOpenCode, model.HarnessWindsurf, model.HarnessDevin,
		},
		Include:           []string{"*"},
		SeverityOverrides: map[string]model.Severity{},
		PackFloors:        map[string]PackFloor{},
		SecretStore:       SecretStoreFingerprintOnly,
		Egress:            EgressNone,
		Redact:            true,
		Provenance:        map[string]Origin{},
		Layers:            []Origin{defaultOrigin},
	}
	for _, k := range []string{"mode", "fail-on", "harnesses", "rules.include", "secrets.store", "privacy.egress", "privacy.redact"} {
		e.Provenance[k] = defaultOrigin
	}
	return e
}

// Merge applies layers over the defaults for surface. env compiles
// custom rules. catalog may be nil, in which case no lower layer may
// override the severity of a locked rule that an upper layer did not
// override. A layer that sets mode or fail-on replaces the surface
// default; a layer that omits them leaves it.
func Merge(env *rules.Env, catalog RuleCatalog, surface Surface, layers []Layer) (*Effective, error) {
	d, err := DefaultsFor(surface)
	if err != nil {
		return nil, err
	}
	e := defaults(d)
	customIDs := map[string]Origin{}
	for _, l := range layers {
		if err := e.apply(env, catalog, l, customIDs); err != nil {
			return nil, &Error{Source: l.Source, Err: err}
		}
	}
	return e, nil
}

func (e *Effective) apply(env *rules.Env, catalog RuleCatalog, l Layer, customIDs map[string]Origin) error {
	f := l.File
	o := Origin{Layer: l.Kind, Source: l.Source}
	e.Layers = append(e.Layers, o)
	var errs []error

	if f.Mode != "" {
		if lock := e.ModeLock; lock != nil && f.Mode.strength() < lock.Floor.strength() {
			errs = append(errs, fmt.Errorf("mode %s: locked at %s by %s", f.Mode, lock.Floor, lock.Origin.Source))
		} else {
			e.Mode = f.Mode
			e.Provenance["mode"] = o
		}
	}
	if f.FailOn != "" {
		if lock := e.ModeLock; lock != nil && aboveCeiling(f.FailOn, lock.FailOnCeiling) {
			errs = append(errs, fmt.Errorf("fail-on %s: above the %s ceiling locked with the mode by %s", f.FailOn, lock.FailOnCeiling, lock.Origin.Source))
		} else {
			e.FailOn = f.FailOn
			e.Provenance["fail-on"] = o
		}
	}
	for _, p := range f.Pack {
		ref, _ := rules.ParsePackRef(p)
		if fl, ok := e.PackFloors[ref.Name]; ok && rules.CompareVersions(ref.Version, fl.Version) < 0 {
			errs = append(errs, fmt.Errorf("pack %s: below %s@%s, locked by %s", ref, ref.Name, fl.Version, fl.Origin.Source))
			continue
		}
		i := slices.IndexFunc(e.Packs, func(r rules.PackRef) bool { return r.Name == ref.Name })
		if i >= 0 {
			e.Packs[i] = ref
		} else {
			e.Packs = append(e.Packs, ref)
		}
		e.Provenance["pack."+ref.Name] = o
	}
	if f.Harnesses != nil {
		next := make([]model.Harness, len(f.Harnesses))
		for i, h := range f.Harnesses {
			next[i] = model.Harness(h)
		}
		var dropped []error
		for _, lock := range e.HarnessLocks {
			if !slices.Contains(next, lock.Harness) {
				dropped = append(dropped, fmt.Errorf("harnesses: %s cannot be removed; rules locked by %s cover it", lock.Harness, lock.Origin.Source))
			}
		}
		if dropped != nil {
			errs = append(errs, dropped...)
		} else {
			e.Harnesses = next
			e.Provenance["harnesses"] = o
		}
	}
	if f.Rules.Include != nil {
		e.Include = slices.Clone(f.Rules.Include)
		e.Provenance["rules.include"] = o
	}
	for _, id := range slices.Sorted(maps.Keys(f.Rules.SeverityOverrides)) {
		sev := model.Severity(f.Rules.SeverityOverrides[id])
		if err := e.checkSeverityLock(catalog, id, sev); err != nil {
			errs = append(errs, err)
			continue
		}
		e.SeverityOverrides[id] = sev
		e.Provenance["rules.severity_overrides."+id] = o
	}
	for _, spec := range f.Rules.Exceptions {
		if lock, ok := e.exemptionLock(spec.Rule); ok {
			errs = append(errs, fmt.Errorf("rules.exceptions: %s is locked by %s; a later layer cannot exempt it", spec.Rule, lock.Origin.Source))
			continue
		}
		expires, _ := time.Parse(ExpiresLayout, spec.Expires)
		e.Provenance[fmt.Sprintf("rules.exceptions[%d]", len(e.Exceptions))] = o
		e.Exceptions = append(e.Exceptions, Exception{
			Rule: spec.Rule, Path: spec.Path, SHA256: spec.SHA256, Reason: spec.Reason,
			Expires: expires, Origin: o,
		})
	}
	for _, spec := range f.Custom {
		if prev, ok := customIDs[spec.ID]; ok {
			errs = append(errs, fmt.Errorf("custom: %s is already defined in %s", spec.ID, prev.Source))
			continue
		}
		if catalog != nil {
			if _, ok := catalog.Rule(spec.ID); ok {
				errs = append(errs, fmt.Errorf("custom: %s is a pack rule id", spec.ID))
				continue
			}
		}
		c, err := compileCustom(env, spec, o)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		customIDs[spec.ID] = o
		e.Custom = append(e.Custom, c)
		e.Provenance["custom."+spec.ID] = o
	}
	if s := f.Secrets; s != nil {
		if s.Rulesets != nil {
			e.SecretRulesets = slices.Clone(s.Rulesets)
			e.Provenance["secrets.rulesets"] = o
		}
		if s.Store != "" {
			e.SecretStore = s.Store
			e.Provenance["secrets.store"] = o
		}
	}
	if p := f.Privacy; p != nil {
		if p.Egress != "" {
			e.Egress = p.Egress
			e.Provenance["privacy.egress"] = o
		}
		if p.Redact != nil {
			e.Redact = *p.Redact
			e.Provenance["privacy.redact"] = o
		}
	}
	if c := f.Cloud; c != nil && c.ReportChannel != nil {
		e.ReportChannel = slices.Clone(c.ReportChannel)
		e.Provenance["cloud.report_channel"] = o
	}
	if lk := f.Locked; lk != nil {
		if lk.Mode != nil {
			switch {
			case *lk.Mode:
				e.ModeLock = &ModeLock{Floor: e.Mode, FailOnCeiling: e.FailOn, Origin: o}
				e.Provenance["locked.mode"] = o
			case e.ModeLock != nil:
				errs = append(errs, fmt.Errorf("locked.mode: false cannot unlock the mode locked by %s", e.ModeLock.Origin.Source))
			}
		}
		for _, p := range lk.Rules {
			e.RuleLocks = append(e.RuleLocks, RuleLock{Pattern: p, Origin: o, overrides: maps.Clone(e.SeverityOverrides)})
			e.ExemptionLocks = append(e.ExemptionLocks, ExemptionLock{Pattern: p, Origin: o})
			e.Provenance["locked.rules["+p+"]"] = o
		}
		for _, p := range lk.Exceptions {
			e.ExemptionLocks = append(e.ExemptionLocks, ExemptionLock{Pattern: p, Origin: o})
			e.Provenance["locked.exceptions["+p+"]"] = o
		}
		e.lockCoverage(catalog, slices.Concat(lk.Rules, lk.Exceptions), o)
	}
	return errors.Join(errs...)
}

// lockCoverage records the pack floors and harness locks for the rule
// patterns a layer locked, from the packs and harnesses then in effect.
func (e *Effective) lockCoverage(catalog RuleCatalog, patterns []string, o Origin) {
	if len(patterns) == 0 {
		return
	}
	var locked []*rules.Rule
	if catalog != nil {
		for _, r := range catalog.Rules() {
			if slices.ContainsFunc(patterns, func(p string) bool { return matchID(p, r.ID) }) {
				locked = append(locked, r)
			}
		}
	}
	// A pinned version wins over the catalog's: the lock covers the
	// rules the pin selects.
	floors := slices.Clone(e.Packs)
	for _, r := range locked {
		if r.Pack.Name != "" && !slices.ContainsFunc(floors, func(p rules.PackRef) bool { return p.Name == r.Pack.Name }) {
			floors = append(floors, r.Pack)
		}
	}
	for _, ref := range floors {
		if fl, ok := e.PackFloors[ref.Name]; !ok || rules.CompareVersions(ref.Version, fl.Version) > 0 {
			e.PackFloors[ref.Name] = PackFloor{Version: ref.Version, Origin: o}
		}
	}
	for _, h := range e.Harnesses {
		covered := locked == nil || slices.ContainsFunc(locked, func(r *rules.Rule) bool { return slices.Contains(r.Harness, h) })
		if covered && !slices.ContainsFunc(e.HarnessLocks, func(l HarnessLock) bool { return l.Harness == h }) {
			e.HarnessLocks = append(e.HarnessLocks, HarnessLock{Harness: h, Origin: o})
		}
	}
}

// checkSeverityLock rejects lowering a locked rule below the severity
// it had when it was locked: the override then in effect, or else the
// rule's base severity.
func (e *Effective) checkSeverityLock(catalog RuleCatalog, id string, sev model.Severity) error {
	for _, lock := range e.RuleLocks {
		if !matchID(lock.Pattern, id) {
			continue
		}
		floor, ok := lock.overrides[id]
		if !ok && catalog != nil {
			if r, found := catalog.Rule(id); found {
				floor, ok = r.Severity, true
			}
		}
		if !ok {
			return fmt.Errorf("rules.severity_overrides.%s: locked by %s and its severity is unknown, so it cannot be overridden here", id, lock.Origin.Source)
		}
		if c, _ := sev.Compare(floor); c < 0 {
			return fmt.Errorf("rules.severity_overrides.%s: %s is below %s, locked by %s", id, sev, floor, lock.Origin.Source)
		}
	}
	return nil
}

func (e *Effective) ruleLock(id string) (RuleLock, bool) {
	for _, lock := range e.RuleLocks {
		if matchID(lock.Pattern, id) {
			return lock, true
		}
	}
	return RuleLock{}, false
}

func (e *Effective) exemptionLock(id string) (ExemptionLock, bool) {
	for _, lock := range e.ExemptionLocks {
		if matchID(lock.Pattern, id) {
			return lock, true
		}
	}
	return ExemptionLock{}, false
}

func compileCustom(env *rules.Env, spec CustomSpec, o Origin) (*CustomRule, error) {
	c := &CustomRule{ID: spec.ID, Message: spec.Message, Severity: model.SeverityHigh, Origin: o}
	if spec.Severity != "" {
		c.Severity = model.Severity(spec.Severity)
	}
	if spec.When != "" {
		when, err := env.Compile(spec.When)
		if err != nil {
			return nil, fmt.Errorf("custom %s: when: %w", spec.ID, err)
		}
		c.When = when
	}
	deny, err := env.Compile(spec.DenyIf)
	if err != nil {
		return nil, fmt.Errorf("custom %s: deny_if: %w", spec.ID, err)
	}
	c.DenyIf = deny
	return c, nil
}

// Deny reports whether the rule denies the event in in: when (if set)
// and deny_if are both true.
func (c *CustomRule) Deny(ctx context.Context, in *rules.Input) (bool, error) {
	if c.When != nil {
		ok, err := c.When.Eval(ctx, in)
		if err != nil || !ok {
			return false, err
		}
	}
	return c.DenyIf.Eval(ctx, in)
}

func matchID(pattern, id string) bool {
	ok, _ := path.Match(pattern, id)
	return ok
}

// aboveCeiling reports whether failOn is weaker than ceiling, i.e. it
// would raise the fail-on threshold above the ceiling a mode lock set.
// Both are always valid severities: File.Validate rejects an unknown
// fail-on, and a ceiling is only ever copied from a prior e.FailOn.
func aboveCeiling(failOn, ceiling model.Severity) bool {
	c, _ := failOn.Compare(ceiling)
	return c > 0
}

// RuleLocked reports whether a locked.rules pattern covers id.
// That freezes the severity floor. It also exempt-locks the rule.
func (e *Effective) RuleLocked(id string) bool {
	_, ok := e.ruleLock(id)
	return ok
}

// ExemptionLocked reports whether a later layer is forbidden from
// exempting id, through an exception or by leaving it out of
// rules.include. locked.rules and locked.exceptions both do this.
func (e *Effective) ExemptionLocked(id string) bool {
	_, ok := e.exemptionLock(id)
	return ok
}

// Selected reports whether rule id is selected, whatever the harness.
// rules.include is the allowlist. A rule an earlier layer locked stays
// selected when a later include leaves it out, so a repo cannot exempt
// itself by narrowing the allowlist.
func (e *Effective) Selected(id string) bool {
	for _, p := range e.Include {
		if matchID(p, id) {
			return true
		}
	}
	return e.ExemptionLocked(id)
}

// HarnessEnabled reports whether items of harness h are scanned. The
// harnesses list names products only, so surfaces such as vscode are
// always scanned.
func (e *Effective) HarnessEnabled(h model.Harness) bool {
	return !h.IsProduct() || slices.Contains(e.Harnesses, h)
}

// Enabled reports whether rule id runs on items of harness h: the rule
// is selected and the harness is enabled. The rule's own harness list
// and file globs are checked by the engine.
func (e *Effective) Enabled(id string, h model.Harness) bool {
	return e.Selected(id) && e.HarnessEnabled(h)
}

// RuleFilter is Enabled as an engine filter, so the engine evaluates
// exactly the rules Enabled reports.
func (e *Effective) RuleFilter() rules.Filter {
	return func(r *rules.Rule, item model.ConfigItem) bool {
		return e.Enabled(r.ID, item.Harness)
	}
}

// ApplyFailOn sets the invocation fail-on, such as the scan --fail-on
// flag. A locked mode keeps its fail-on ceiling: the flag may lower the
// threshold and may not raise it. Loosening returns an error.
func (e *Effective) ApplyFailOn(sev model.Severity) error {
	if !sev.Valid() {
		return fmt.Errorf("fail-on %q: unknown", sev)
	}
	if lock := e.ModeLock; lock != nil && lock.FailOnCeiling != "" && aboveCeiling(sev, lock.FailOnCeiling) {
		return fmt.Errorf("fail-on %s: above the %s ceiling locked with the mode by %s", sev, lock.FailOnCeiling, lock.Origin.Source)
	}
	e.FailOn = sev
	return nil
}

// Fails reports whether a finding of severity sev fails this policy's
// run: Mode is enforce and sev is at or above FailOn. audit and warn
// never fail, on any surface, which is why the hook's default mode,
// warn, shows findings and does not block.
func (e *Effective) Fails(sev model.Severity) (bool, error) {
	return (Defaults{Mode: e.Mode, FailOn: e.FailOn}).Fails(sev)
}

// Severity returns the override for id, or base.
func (e *Effective) Severity(id string, base model.Severity) model.Severity {
	if sev, ok := e.SeverityOverrides[id]; ok {
		return sev
	}
	return base
}

// ExceptionStatus is the result of an exception lookup.
type ExceptionStatus int

const (
	// ExceptionNone: no exception names this rule and path.
	ExceptionNone ExceptionStatus = iota
	// ExceptionActive: an exception matches and suppresses the finding.
	ExceptionActive
	// ExceptionExpired: an exception matched by hash but its date passed.
	ExceptionExpired
	// ExceptionHashMismatch: an exception names the file but the file changed.
	ExceptionHashMismatch
)

func (s ExceptionStatus) String() string {
	switch s {
	case ExceptionNone:
		return "none"
	case ExceptionActive:
		return "active"
	case ExceptionExpired:
		return "expired"
	case ExceptionHashMismatch:
		return "hash-mismatch"
	default:
		return fmt.Sprintf("ExceptionStatus(%d)", int(s))
	}
}

// Exception looks up an exception for rule on path with content hash
// sha256 at time now. An exception applies through the end of its
// expires day in UTC, and only while sha256 matches. When several
// entries name the rule and path, an active one wins, then expired,
// then hash mismatch.
func (e *Effective) Exception(rule, path, sha256 string, now time.Time) (*Exception, ExceptionStatus) {
	var best *Exception
	status := ExceptionNone
	for i := range e.Exceptions {
		ex := &e.Exceptions[i]
		if ex.Rule != rule || ex.Path != path {
			continue
		}
		s := ExceptionActive
		switch {
		case ex.SHA256 != sha256:
			s = ExceptionHashMismatch
		case !now.UTC().Before(ex.Expires.AddDate(0, 0, 1)):
			s = ExceptionExpired
		}
		if best == nil || rank(s) > rank(status) {
			best, status = ex, s
		}
	}
	return best, status
}

func rank(s ExceptionStatus) int {
	switch s {
	case ExceptionActive:
		return 3
	case ExceptionExpired:
		return 2
	case ExceptionHashMismatch:
		return 1
	default:
		return 0
	}
}
