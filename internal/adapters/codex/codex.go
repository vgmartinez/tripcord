// Package codex discovers OpenAI Codex configuration without executing
// it: config.toml (MCP servers, sandbox and approval settings, inline
// hooks), hooks.json, AGENTS.override.md, .codex/rules/*.rules (and the
// user and system layers), and its own, deprecated ~/.codex/skills. A
// .rules file is Codex's Starlark-based exec policy; it is parsed
// conservatively and never executed (see rules_parse.go). AGENTS.md and
// shared skills are read by the generic adapter.
package codex

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

const product = "Codex"

// maxProfiles caps $CODEX_HOME/*.config.toml profile files.
const maxProfiles = 64

// maxRulesFiles caps $CODEX_HOME/rules/*.rules files.
const maxRulesFiles = 64

// Options controls discovery. The zero value scans repository scope only,
// so a repository scan never reads the home directory or system files.
type Options struct {
	SkipRepo       bool
	IncludeUser    bool
	IncludeManaged bool
	// HomeDir overrides os.UserHomeDir.
	HomeDir string
	// Getenv overrides os.Getenv (for CODEX_HOME).
	Getenv func(string) string
	// ManagedDir overrides /etc/codex. Codex documents no system
	// configuration file outside Unix; on Windows the managed scope is
	// empty unless ManagedDir is set.
	ManagedDir string
	Limits     *kit.Limits
}

// Adapter discovers Codex config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns a Codex adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessCodex }

// SharedOwners implements adapters.SharedReader: Codex also loads
// AGENTS.md and .agents/skills, both in the repository and, at user
// scope, ~/.agents/skills; the generic adapter reports all of them.
// Codex's own, deprecated ~/.codex/skills has no other reader and is
// reported here, not by generic.
func (*Adapter) SharedOwners() []model.Harness { return []model.Harness{model.SurfaceGeneric} }

// Detect reports whether the repository holds a file Codex reads, or a
// config path that cannot be read safely.
func (a *Adapter) Detect(repoRoot string) bool {
	if a.options.IncludeUser || a.options.IncludeManaged {
		return true
	}
	if a.options.SkipRepo {
		return false
	}
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		return false
	}
	defer func() { _ = reader.Close() }()
	c := kit.NewCollector(model.HarnessCodex, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every supported file in the enabled scopes. It never
// runs hooks, starts MCP servers, or invokes any program.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.HarnessCodex, product)
	trust := trustUnknown
	if a.options.IncludeUser {
		trust = a.discoverUser(ctx, c, repoRoot)
	}
	if !a.options.SkipRepo {
		if err := a.discoverRepo(ctx, repoRoot, c, trust); err != nil {
			return nil, err
		}
	}
	if a.options.IncludeManaged {
		a.discoverManaged(c)
	}
	return c.Result()
}

func (a *Adapter) getenv(name string) string {
	if a.options.Getenv != nil {
		return a.options.Getenv(name)
	}
	return os.Getenv(name)
}

type role int

const (
	roleNone role = iota
	roleConfig
	roleHooks
	roleOverride
	roleRules
)

func classify(rel string) role {
	segments := kit.Segments(rel)
	n := len(segments)
	base := segments[n-1]
	parent, grandparent := "", ""
	if n >= 2 {
		parent = segments[n-2]
	}
	if n >= 3 {
		grandparent = segments[n-3]
	}
	switch {
	case parent == ".codex" && base == "config.toml":
		return roleConfig
	case parent == ".codex" && base == "hooks.json":
		return roleHooks
	case base == "agents.override.md":
		return roleOverride
	case grandparent == ".codex" && parent == "rules" && strings.HasSuffix(base, ".rules"):
		return roleRules
	}
	return roleNone
}

var matcher = kit.Matcher{
	Candidate: func(rel string) bool { return classify(rel) != roleNone },
	Relevant:  func(rel string) bool { return kit.HasSegment(kit.Segments(rel), ".codex") },
}

func (a *Adapter) discoverRepo(ctx context.Context, repoRoot string, c *kit.Collector, trust string) error {
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		c.Warn(model.ScopeRepo, "", "cannot open repository: %v", err)
		return nil
	}
	defer func() { _ = reader.Close() }()
	files, err := kit.Walk(ctx, reader, a.limits, c, matcher)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.Warn(model.ScopeRepo, "", "cannot list repository: %v", err)
		return nil
	}
	r := kit.NewRepoReader(reader, a.limits, c)
	for _, rel := range files {
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		src := c.Source(model.ScopeRepo, rel, raw)
		switch classify(rel) {
		case roleConfig:
			(&file{Source: src.WithField("project_trust", trust)}).config(raw)
		case roleHooks:
			(&file{Source: src.WithField("project_trust", trust)}).hooksFile(raw)
		case roleOverride:
			src.Markdown(model.ConfigKindInstructions, "agents-override", raw, kit.LooseFrontmatter)
		case roleRules:
			(&file{Source: src.WithField("project_trust", trust)}).rulesFile(raw)
		case roleNone:
		}
	}
	return nil
}

// discoverUser reads $CODEX_HOME (default ~/.codex) and returns the trust
// status of repoRoot recorded in its config.toml.
func (a *Adapter) discoverUser(ctx context.Context, c *kit.Collector, repoRoot string) string {
	home, ok := kit.ResolveHome(c, a.options.HomeDir)
	if !ok {
		return trustUnknown
	}
	dir, ok := kit.ResolveUserDir(c, home, "CODEX_HOME", a.getenv("CODEX_HOME"), ".codex")
	if !ok {
		return trustUnknown
	}
	trust := trustUnknown
	abs, logical := dir.File("config.toml")
	diags := len(c.Diagnostics())
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		f := &file{Source: c.Source(model.ScopeUser, logical, raw)}
		if tree := f.config(raw); tree != nil {
			trust = projectTrust(tree, repoRoot)
		}
	} else if len(c.Diagnostics()) == diags {
		trust = trustUnset
	}
	for _, name := range c.ListLocal(model.ScopeUser, dir.Abs, dir.Logical, ".config.toml", maxProfiles) {
		abs, logical := dir.File(name)
		if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeUser, logical, raw)}).config(raw)
		}
	}
	abs, logical = dir.File("hooks.json")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeUser, logical, raw)}).hooksFile(raw)
	}
	rulesDir := dir.Dir("rules")
	for _, name := range c.ListLocal(model.ScopeUser, rulesDir.Abs, rulesDir.Logical, ".rules", maxRulesFiles) {
		abs, logical := rulesDir.File(name)
		if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeUser, logical, raw)}).rulesFile(raw)
		}
	}
	for _, name := range []string{"AGENTS.md", "AGENTS.override.md"} {
		abs, logical := dir.File(name)
		if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
			role := "agents"
			if name != "AGENTS.md" {
				role = "agents-override"
			}
			c.Source(model.ScopeUser, logical, raw).Markdown(model.ConfigKindInstructions, role, raw, kit.LooseFrontmatter)
		}
	}
	a.discoverUserSkills(ctx, c, dir.Dir("skills"))
	return trust
}

// discoverUserSkills reads $CODEX_HOME/skills: Codex's deprecated,
// backward-compatible user-skill location, kept alongside the current
// ~/.agents/skills (shared with other harnesses and read by the generic
// adapter, not here).
func (a *Adapter) discoverUserSkills(ctx context.Context, c *kit.Collector, dir kit.UserDir) {
	reader, files, err := kit.OpenUserWalk(ctx, c, a.limits, dir, kit.SkillFileMatcher)
	if err != nil || reader == nil {
		return
	}
	defer func() { _ = reader.Close() }()
	r := kit.NewScopedReader(reader, a.limits, c, model.ScopeUser, dir.Logical)
	for _, rel := range files {
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		c.Source(model.ScopeUser, dir.Logical+"/"+rel, raw).Markdown(model.ConfigKindSkill, "skill", raw, kit.StrictFrontmatter)
	}
}

func defaultManagedDir() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "/etc/codex"
}

func (a *Adapter) discoverManaged(c *kit.Collector) {
	dir := a.options.ManagedDir
	if dir == "" {
		dir = defaultManagedDir()
	}
	if dir == "" {
		return
	}
	logicalDir := kit.ManagedPath(dir)
	for _, name := range []string{"config.toml", "requirements.toml"} {
		abs := filepath.Join(dir, name)
		logical := path.Join(logicalDir, name)
		if raw, ok := c.ReadLocal(model.ScopeManaged, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeManaged, logical, raw)}).config(raw)
		}
	}
}

const (
	trustTrusted   = "trusted"
	trustUntrusted = "untrusted"
	// trustUnset means the user config was read and has no entry for the
	// repository; Codex asks before loading the project layer.
	trustUnset = "unset"
	// trustUnknown means the user config was not read (repository scope
	// only) or could not be parsed.
	trustUnknown = "unknown"
)

// projectTrust looks up projects.<repoRoot>.trust_level. Keys are
// absolute paths; both sides are cleaned and symlink-resolved.
func projectTrust(tree map[string]any, repoRoot string) string {
	projects, ok := tree["projects"].(map[string]any)
	if !ok {
		return trustUnset
	}
	want := canonical(repoRoot)
	for key, value := range projects {
		if canonical(key) != want {
			continue
		}
		entry, ok := value.(map[string]any)
		if !ok {
			continue
		}
		switch level, _ := entry["trust_level"].(string); strings.ToLower(level) {
		case trustTrusted:
			return trustTrusted
		case trustUntrusted:
			return trustUntrusted
		}
	}
	return trustUnset
}

func canonical(p string) string {
	if p == "" || !filepath.IsAbs(p) {
		return ""
	}
	p = filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return p
}
