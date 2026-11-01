package rules

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/strictyaml"
)

// MaxRuleBytes caps one rule file.
const MaxRuleBytes = 64 << 10

// Spec is one rule file as written, before compilation.
//
//	id: TC-CFG-002
//	pack: tripcord/core
//	title: "VS Code task that runs when the folder opens"
//	severity: high
//	harness: [vscode, cursor, windsurf]
//	files: [".vscode/tasks.json"]
//	when: >-
//	  has(task.runOptions) && has(task.runOptions.runOn) &&
//	    task.runOptions.runOn == "folderOpen"
//	fix: "Remove runOn: folderOpen or move the task to an explicit script"
//	refs:
//	  - https://example.com/incident
//
// Every key except severity_when and evidence is required, and unknown
// keys are rejected. evidence, when present, names what a finding's
// excerpt describes besides the config citation: hidden_chars is the
// item's hidden code points by code point, line, and column (see
// internal/hiddenchar), never the text they hide. severity_when, when
// present, is tried in order after when is true: the first true clause
// is the severity of that match, and an item no clause accepts is not a
// match. when then holds only what the clauses share, so a pattern is
// written once. severity is the rule's catalog severity and the floor a
// policy lock refuses to lower. A policy severity override still
// replaces the per-match result.
type Spec struct {
	ID           string         `yaml:"id"`
	Pack         string         `yaml:"pack"`
	Title        string         `yaml:"title"`
	Severity     string         `yaml:"severity"`
	SeverityWhen []SeverityWhen `yaml:"severity_when"`
	Harness      []string       `yaml:"harness"`
	Files        []string       `yaml:"files"`
	When         string         `yaml:"when"`
	Fix          string         `yaml:"fix"`
	Refs         []string       `yaml:"refs"`
	Evidence     string         `yaml:"evidence"`
}

// EvidenceHiddenChars puts an item's hidden code points in the finding's
// excerpt and its first line in the location. EvidenceInstructionMatch puts
// the first matched instruction line in the location without exposing text.
const (
	EvidenceHiddenChars      = "hidden_chars"
	EvidenceInstructionMatch = "instruction_match"
)

// SeverityWhen is one per-match severity clause. Title, when set,
// replaces the rule title on the findings of that clause, for a match
// whose reason the rule title does not say.
type SeverityWhen struct {
	Severity string `yaml:"severity"`
	When     string `yaml:"when"`
	Title    string `yaml:"title"`
}

// ParseSpec decodes and validates one rule document. It does not
// compile the when expression.
func ParseSpec(data []byte) (*Spec, error) {
	if len(data) > MaxRuleBytes {
		return nil, fmt.Errorf("rule is %d bytes, limit %d", len(data), MaxRuleBytes)
	}
	var spec Spec
	if err := strictyaml.Decode(data, &spec); err != nil {
		return nil, err
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return &spec, nil
}

// Validate checks every field except the CEL expression.
func (s *Spec) Validate() error {
	if !ValidID(s.ID) {
		return fmt.Errorf("id %q: want an id such as TC-CFG-001", s.ID)
	}
	if _, err := ParsePackName(s.Pack); err != nil {
		return err
	}
	if strings.TrimSpace(s.Title) == "" {
		return errors.New("title is required")
	}
	if _, err := model.ParseSeverity(s.Severity); err != nil {
		return err
	}
	for i, clause := range s.SeverityWhen {
		if _, err := model.ParseSeverity(clause.Severity); err != nil {
			return fmt.Errorf("severity_when[%d]: %w", i, err)
		}
		if strings.TrimSpace(clause.When) == "" {
			return fmt.Errorf("severity_when[%d]: when is required", i)
		}
	}
	if len(s.Harness) == 0 {
		return errors.New("harness needs at least one entry")
	}
	seen := map[string]bool{}
	for _, h := range s.Harness {
		if _, err := model.ParseHarness(h); err != nil {
			return err
		}
		if seen[h] {
			return fmt.Errorf("harness %q is listed twice", h)
		}
		seen[h] = true
	}
	if len(s.Files) == 0 {
		return errors.New("files needs at least one glob")
	}
	for _, f := range s.Files {
		if err := validateFileGlob(f); err != nil {
			return err
		}
	}
	if strings.TrimSpace(s.When) == "" {
		return errors.New("when is required")
	}
	if strings.TrimSpace(s.Fix) == "" {
		return errors.New("fix is required")
	}
	if len(s.Refs) == 0 {
		return errors.New("refs needs at least one incident or official documentation link")
	}
	if s.Evidence != "" && s.Evidence != EvidenceHiddenChars && s.Evidence != EvidenceInstructionMatch {
		return fmt.Errorf("evidence %q: want %s, %s, or nothing", s.Evidence, EvidenceHiddenChars, EvidenceInstructionMatch)
	}
	for _, ref := range s.Refs {
		if err := validateRef(ref); err != nil {
			return err
		}
	}
	return nil
}

// validateFileGlob accepts a repo-relative or ~/ doublestar glob.
func validateFileGlob(glob string) error {
	rest := strings.TrimPrefix(glob, "~/")
	switch {
	case rest == "":
		return fmt.Errorf("files: empty glob")
	case strings.HasPrefix(rest, "/"), strings.Contains(glob, `\`):
		return fmt.Errorf("files: %q must be repo-relative or start with ~/, using /", glob)
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == ".." || seg == "." {
			return fmt.Errorf("files: %q must not contain . or .. segments", glob)
		}
	}
	if !doublestar.ValidatePattern(glob) {
		return fmt.Errorf("files: %q is not a valid glob", glob)
	}
	return nil
}

func validateRef(ref string) error {
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("refs: %q must be an https URL", ref)
	}
	return nil
}

// SeverityClause is a compiled per-match severity. Title is empty when
// the clause keeps the rule title.
type SeverityClause struct {
	Severity model.Severity
	Title    string
	When     *Expr
}

// Rule is a validated rule with its expression compiled.
type Rule struct {
	ID           string
	Pack         PackRef
	Title        string
	Severity     model.Severity
	SeverityWhen []SeverityClause
	Harness      []model.Harness
	Files        []string
	Fix          string
	Refs         []string
	When         *Expr
	// Evidence is the spec's evidence: "" or EvidenceHiddenChars.
	Evidence string
}

// Compile validates spec and compiles its when expression in env.
// manifest is the pack the rule belongs to. spec.Pack must be that
// pack's name; the compiled rule inherits manifest's version.
func Compile(spec *Spec, manifest PackRef, env *Env) (*Rule, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if manifest.Name == "" || manifest.Version == "" || spec.Pack != manifest.Name {
		return nil, fmt.Errorf("pack %s does not match the manifest %s", spec.Pack, manifest)
	}
	when, err := env.Compile(spec.When)
	if err != nil {
		return nil, fmt.Errorf("when: %w", err)
	}
	clauses := make([]SeverityClause, len(spec.SeverityWhen))
	for i, clause := range spec.SeverityWhen {
		expr, err := env.Compile(clause.When)
		if err != nil {
			return nil, fmt.Errorf("severity_when[%d]: %w", i, err)
		}
		sev, _ := model.ParseSeverity(clause.Severity)
		clauses[i] = SeverityClause{Severity: sev, Title: strings.TrimSpace(clause.Title), When: expr}
	}
	sev, _ := model.ParseSeverity(spec.Severity)
	harness := make([]model.Harness, len(spec.Harness))
	for i, h := range spec.Harness {
		harness[i] = model.Harness(h)
	}
	return &Rule{
		ID:           spec.ID,
		Pack:         manifest,
		Title:        spec.Title,
		Severity:     sev,
		SeverityWhen: clauses,
		Harness:      harness,
		Files:        append([]string(nil), spec.Files...),
		Fix:          spec.Fix,
		Refs:         append([]string(nil), spec.Refs...),
		Evidence:     spec.Evidence,
		When:         when,
	}, nil
}

// SeverityFor reports the severity of an item whose when is true.
// Clauses are tried in the order they are written; the first true one
// wins. A rule without clauses matches at its own severity. A rule with
// clauses matches only when one is true: ok is false otherwise. A clause
// that fails to evaluate is an error, the same as the when expression.
func (r *Rule) SeverityFor(ctx context.Context, in *Input) (sev model.Severity, ok bool, err error) {
	clause, ok, err := r.clauseFor(ctx, in)
	return clause.Severity, ok, err
}

// clauseFor is SeverityFor returning the whole clause. A rule without
// clauses matches with its own severity and no title override.
func (r *Rule) clauseFor(ctx context.Context, in *Input) (SeverityClause, bool, error) {
	if len(r.SeverityWhen) == 0 {
		return SeverityClause{Severity: r.Severity}, true, nil
	}
	for _, clause := range r.SeverityWhen {
		matched, err := clause.When.Eval(ctx, in)
		if err != nil {
			return SeverityClause{}, false, err
		}
		if matched {
			return clause, true, nil
		}
	}
	return SeverityClause{}, false, nil
}

// Applies reports whether item is in scope for r: its harness is listed
// and its path matches one of the file globs.
func (r *Rule) Applies(item model.ConfigItem) bool {
	harnessOK := false
	for _, h := range r.Harness {
		if h == item.Harness {
			harnessOK = true
			break
		}
	}
	if !harnessOK {
		return false
	}
	for _, glob := range r.Files {
		if doublestar.MatchUnvalidated(glob, item.Path) {
			return true
		}
	}
	return false
}
