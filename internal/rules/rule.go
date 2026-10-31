package rules

import (
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
// Every key is required and unknown keys are rejected.
type Spec struct {
	ID       string   `yaml:"id"`
	Pack     string   `yaml:"pack"`
	Title    string   `yaml:"title"`
	Severity string   `yaml:"severity"`
	Harness  []string `yaml:"harness"`
	Files    []string `yaml:"files"`
	When     string   `yaml:"when"`
	Fix      string   `yaml:"fix"`
	Refs     []string `yaml:"refs"`
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

// Rule is a validated rule with its expression compiled.
type Rule struct {
	ID       string
	Pack     PackRef
	Title    string
	Severity model.Severity
	Harness  []model.Harness
	Files    []string
	Fix      string
	Refs     []string
	When     *Expr
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
	sev, _ := model.ParseSeverity(spec.Severity)
	harness := make([]model.Harness, len(spec.Harness))
	for i, h := range spec.Harness {
		harness[i] = model.Harness(h)
	}
	return &Rule{
		ID:       spec.ID,
		Pack:     manifest,
		Title:    spec.Title,
		Severity: sev,
		Harness:  harness,
		Files:    append([]string(nil), spec.Files...),
		Fix:      spec.Fix,
		Refs:     append([]string(nil), spec.Refs...),
		When:     when,
	}, nil
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
