package policy

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules"
	"github.com/vgmartinez/tripcord/internal/strictyaml"
)

// MaxFileBytes caps one policy file.
const MaxFileBytes = 256 << 10

// Version is the only supported policy file version.
const Version = 1

// Mode is the policy mode. Enforce is the strictest and audit the least.
// The mode used when no policy layer sets one depends on the surface;
// see DefaultsFor.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeWarn    Mode = "warn"
	ModeAudit   Mode = "audit"
)

// strength orders modes for locking: a lower layer may not pick a mode
// with lower strength than a locked one.
func (m Mode) strength() int {
	switch m {
	case ModeEnforce:
		return 3
	case ModeWarn:
		return 2
	case ModeAudit:
		return 1
	default:
		return 0
	}
}

// Fixed vocabularies from the spec sample.
const (
	SecretStoreFingerprintOnly = "fingerprint-only"
	EgressNone                 = "none"
)

var reportChannels = []string{"hook-message", "git-notes"}

var rulesetPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// StringList is a YAML string or list of strings.
type StringList []string

// UnmarshalYAML accepts a scalar or a sequence.
func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*s = StringList{node.Value}
		return nil
	}
	var list []string
	if err := node.Decode(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

// File is one policy.yaml as written. Omitted sections inherit from
// the layer below; see Merge.
type File struct {
	Version   int            `yaml:"version"`
	Pack      StringList     `yaml:"pack"`
	Extends   StringList     `yaml:"extends"`
	Mode      Mode           `yaml:"mode"`
	FailOn    model.Severity `yaml:"fail-on"`
	Harnesses []string       `yaml:"harnesses"`
	Rules     RulesSection   `yaml:"rules"`
	Custom    []CustomSpec   `yaml:"custom"`
	Secrets   *Secrets       `yaml:"secrets"`
	Privacy   *Privacy       `yaml:"privacy"`
	Cloud     *Cloud         `yaml:"cloud"`
	Locked    *Locked        `yaml:"locked"`
}

// RulesSection selects and adjusts rules.
type RulesSection struct {
	Include           []string          `yaml:"include"`
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
	Exceptions        []ExceptionSpec   `yaml:"exceptions"`
}

// ExceptionSpec suppresses one rule on one file while the file hash
// matches and the date has not passed. Every field is required.
type ExceptionSpec struct {
	Rule    string `yaml:"rule"`
	Path    string `yaml:"path"`
	SHA256  string `yaml:"sha256"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"`
}

// CustomSpec is a policy-defined event rule. when is an optional
// precondition; deny_if decides.
type CustomSpec struct {
	ID       string `yaml:"id"`
	When     string `yaml:"when"`
	DenyIf   string `yaml:"deny_if"`
	Message  string `yaml:"message"`
	Severity string `yaml:"severity"`
}

// Secrets configures secret detection.
type Secrets struct {
	Rulesets []string `yaml:"rulesets"`
	Store    string   `yaml:"store"`
}

// Privacy configures data handling. egress has one value, none.
type Privacy struct {
	Egress string `yaml:"egress"`
	Redact *bool  `yaml:"redact"`
}

// Cloud configures how cloud-agent runs report back.
type Cloud struct {
	ReportChannel []string `yaml:"report_channel"`
}

// Locked lists values a later layer cannot relax. v0 locks mode, rules,
// and exceptions. Nothing else (harnesses, privacy, secrets, cloud,
// packs, custom rules) is lockable yet.
//
//	locked:
//	  mode: true               # later layers cannot pick a weaker mode
//	  rules: [TC-CFG-*]        # severity floor
//	  exceptions: [TC-SEC-*]   # later layers cannot add exceptions
//
// Locking a rule, either under rules or under exceptions, also locks it
// against the allowlist: a later rules.include cannot drop it. A repo
// cannot exempt itself from a rule an earlier layer locked.
type Locked struct {
	Mode       *bool    `yaml:"mode"`
	Rules      []string `yaml:"rules"`
	Exceptions []string `yaml:"exceptions"`
}

// ExpiresLayout is the exceptions[].expires date format.
const ExpiresLayout = "2006-01-02"

// Parse decodes and validates one policy file. It does not compile CEL
// or resolve extends.
func Parse(data []byte) (*File, error) {
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("policy is %d bytes, limit %d", len(data), MaxFileBytes)
	}
	var f File
	if err := strictyaml.Decode(data, &f); err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Validate checks one file in isolation.
func (f *File) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if f.Version != Version {
		add("version: got %d, want %d", f.Version, Version)
	}
	names := map[string]bool{}
	for _, p := range f.Pack {
		ref, err := rules.ParsePackRef(p)
		if err != nil {
			add("pack: %v", err)
			continue
		}
		if names[ref.Name] {
			add("pack: %s is listed twice", ref.Name)
		}
		names[ref.Name] = true
	}
	for _, e := range f.Extends {
		if _, _, err := ParseExtends(e); err != nil {
			add("extends: %v", err)
		}
	}
	if f.Mode != "" && f.Mode.strength() == 0 {
		add("mode %q: want enforce, warn, or audit", f.Mode)
	}
	if f.FailOn != "" {
		if _, err := model.ParseSeverity(string(f.FailOn)); err != nil {
			add("fail-on: %v", err)
		}
	}
	if f.Harnesses != nil {
		if len(f.Harnesses) == 0 {
			add("harnesses: empty list; omit the key to inherit")
		}
		seen := map[string]bool{}
		for _, h := range f.Harnesses {
			if !model.Harness(h).IsProduct() {
				add("harnesses: %q is not a harness", h)
			}
			if seen[h] {
				add("harnesses: %q is listed twice", h)
			}
			seen[h] = true
		}
	}
	if f.Rules.Include != nil && len(f.Rules.Include) == 0 {
		add("rules.include: empty list; omit the key to inherit")
	}
	for _, p := range f.Rules.Include {
		if err := validateIDGlob(p); err != nil {
			add("rules.include: %v", err)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(f.Rules.SeverityOverrides)) {
		sev := f.Rules.SeverityOverrides[id]
		if !rules.ValidID(id) {
			add("rules.severity_overrides: %q is not a rule id", id)
		}
		if _, err := model.ParseSeverity(sev); err != nil {
			add("rules.severity_overrides.%s: %v", id, err)
		}
	}
	for i, ex := range f.Rules.Exceptions {
		if err := ex.validate(); err != nil {
			add("rules.exceptions[%d]: %v", i, err)
		}
	}
	ids := map[string]bool{}
	for i, c := range f.Custom {
		if !rules.ValidID(c.ID) {
			add("custom[%d]: id %q is not a rule id", i, c.ID)
		}
		if ids[c.ID] {
			add("custom[%d]: id %s is defined twice", i, c.ID)
		}
		ids[c.ID] = true
		if strings.TrimSpace(c.DenyIf) == "" {
			add("custom[%d]: deny_if is required", i)
		}
		if strings.TrimSpace(c.Message) == "" {
			add("custom[%d]: message is required", i)
		}
		if c.Severity != "" {
			if _, err := model.ParseSeverity(c.Severity); err != nil {
				add("custom[%d]: %v", i, err)
			}
		}
	}
	if s := f.Secrets; s != nil {
		for _, r := range s.Rulesets {
			if !rulesetPattern.MatchString(r) {
				add("secrets.rulesets: %q is not a ruleset name", r)
			}
		}
		if s.Store != "" && s.Store != SecretStoreFingerprintOnly {
			add("secrets.store %q: only %s is supported; secret values are never stored", s.Store, SecretStoreFingerprintOnly)
		}
	}
	if p := f.Privacy; p != nil && p.Egress != "" && p.Egress != EgressNone {
		add("privacy.egress %q: only %s is supported; tripcord has no network mode", p.Egress, EgressNone)
	}
	if c := f.Cloud; c != nil {
		for _, ch := range c.ReportChannel {
			if !contains(reportChannels, ch) {
				add("cloud.report_channel: %q: want one of %s", ch, strings.Join(reportChannels, ", "))
			}
		}
	}
	if l := f.Locked; l != nil {
		for _, p := range l.Rules {
			if err := validateIDGlob(p); err != nil {
				add("locked.rules: %v", err)
			}
		}
		for _, p := range l.Exceptions {
			if err := validateIDGlob(p); err != nil {
				add("locked.exceptions: %v", err)
			}
		}
	}
	return errors.Join(errs...)
}

func (ex ExceptionSpec) validate() error {
	if !rules.ValidID(ex.Rule) {
		return fmt.Errorf("rule %q is not a rule id", ex.Rule)
	}
	if err := validateRelPath(ex.Path); err != nil {
		return err
	}
	if !isSHA256Hex(ex.SHA256) {
		return fmt.Errorf("sha256 must be 64 lowercase hex characters")
	}
	if strings.TrimSpace(ex.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	if _, err := time.Parse(ExpiresLayout, ex.Expires); err != nil {
		return fmt.Errorf("expires %q: want YYYY-MM-DD", ex.Expires)
	}
	return nil
}

// validateIDGlob accepts a rule id or a path.Match pattern over ids.
func validateIDGlob(p string) error {
	if p == "" {
		return errors.New("empty pattern")
	}
	if _, err := path.Match(p, ""); err != nil {
		return fmt.Errorf("%q: %v", p, err)
	}
	return nil
}

// validateRelPath accepts a clean repo-relative or ~/ path using /.
func validateRelPath(p string) error {
	rest := strings.TrimPrefix(p, "~/")
	if rest == "" || strings.HasPrefix(rest, "/") || strings.Contains(p, `\`) || path.Clean(rest) != rest {
		return fmt.Errorf("path %q must be a clean repo-relative or ~/ path using /", p)
	}
	if rest == ".." || strings.HasPrefix(rest, "../") {
		return fmt.Errorf("path %q must not leave the repository", p)
	}
	return nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// ExtendsKind says how an extends entry is resolved.
type ExtendsKind int

const (
	// ExtendsPath is a policy file path, relative to the declaring file.
	ExtendsPath ExtendsKind = iota + 1
	// ExtendsPack is a pack reference resolved by a Resolver.
	ExtendsPack
)

// ParseExtends classifies an extends entry. Entries starting with ./,
// ../, or / are paths; anything else must be a pack reference such as
// vgmartinez/org-policy@2026.11.
func ParseExtends(s string) (ExtendsKind, rules.PackRef, error) {
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "/") {
		return ExtendsPath, rules.PackRef{}, nil
	}
	ref, err := rules.ParsePackRef(s)
	if err != nil {
		return 0, rules.PackRef{}, fmt.Errorf("%q is neither a ./ or ../ path nor a pack reference: %v", s, err)
	}
	return ExtendsPack, ref, nil
}
