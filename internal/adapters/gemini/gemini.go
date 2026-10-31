// Package gemini discovers Gemini CLI configuration without executing
// it: settings.json (MCP servers, hooks, hooksConfig, and the settings
// that decide what runs or what is approved) in the repository, the
// user's $GEMINI_CLI_HOME/.gemini, and the system settings directory,
// and GEMINI.md context files. AGENTS.md and shared skills are read by
// the generic adapter.
package gemini

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

const product = "Gemini CLI"

// Options controls discovery. The zero value scans repository scope only,
// so a repository scan never reads the home directory or system files.
type Options struct {
	SkipRepo       bool
	IncludeUser    bool
	IncludeManaged bool
	// HomeDir overrides os.UserHomeDir.
	HomeDir string
	// Getenv overrides os.Getenv (for GEMINI_CLI_HOME,
	// GEMINI_CLI_SYSTEM_SETTINGS_PATH, GEMINI_CLI_SYSTEM_DEFAULTS_PATH,
	// and ProgramData).
	Getenv func(string) string
	// ManagedDir overrides the system settings directory:
	// /Library/Application Support/GeminiCli on macOS, /etc/gemini-cli on
	// Linux, and %ProgramData%\gemini-cli on Windows.
	ManagedDir string
	Limits     *kit.Limits
}

// Adapter discovers Gemini CLI config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns a Gemini CLI adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessGemini }

// SharedOwners implements adapters.SharedReader: Gemini CLI can be
// pointed at AGENTS.md (context.fileName) and reads shared skills, both
// reported by the generic adapter.
func (*Adapter) SharedOwners() []model.Harness { return []model.Harness{model.SurfaceGeneric} }

// Detect reports whether the repository holds a file Gemini CLI reads, or
// a config path that cannot be read safely.
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
	c := kit.NewCollector(model.HarnessGemini, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every supported file in the enabled scopes. It never
// runs hooks, starts MCP servers, or invokes any program.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.HarnessGemini, product)
	if !a.options.SkipRepo {
		if err := a.discoverRepo(ctx, repoRoot, c); err != nil {
			return nil, err
		}
	}
	if a.options.IncludeUser {
		a.discoverUser(c)
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
	roleSettings
	roleContext
)

// classify returns how Gemini CLI reads rel. Workspace settings live in
// .gemini/ of the directory Gemini CLI starts in, and GEMINI.md is loaded
// from every directory between the project root and the working
// directory, so both are matched at any depth. Matching is
// case-insensitive: macOS and Windows resolve ".Gemini/Settings.json" to
// the same file.
func classify(rel string) role {
	segments := kit.Segments(rel)
	n := len(segments)
	base := segments[n-1]
	parent := ""
	if n >= 2 {
		parent = segments[n-2]
	}
	switch {
	case parent == ".gemini" && base == "settings.json":
		return roleSettings
	case base == "gemini.md":
		return roleContext
	}
	return roleNone
}

var matcher = kit.Matcher{
	Candidate: func(rel string) bool { return classify(rel) != roleNone },
	Relevant:  func(rel string) bool { return kit.HasSegment(kit.Segments(rel), ".gemini") },
}

func (a *Adapter) discoverRepo(ctx context.Context, repoRoot string, c *kit.Collector) error {
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
		f := &file{Source: c.Source(model.ScopeRepo, rel, raw)}
		switch classify(rel) {
		case roleSettings:
			f.settings(raw)
		case roleContext:
			f.Markdown(model.ConfigKindInstructions, "gemini", raw, kit.LooseFrontmatter)
		case roleNone:
		}
	}
	return nil
}

// discoverUser reads $GEMINI_CLI_HOME/.gemini (default ~/.gemini):
// settings.json and GEMINI.md. GEMINI_CLI_HOME replaces the home
// directory Gemini CLI puts .gemini under.
func (a *Adapter) discoverUser(c *kit.Collector) {
	home, ok := kit.ResolveHome(c, a.options.HomeDir)
	if !ok {
		return
	}
	base, ok := kit.ResolveUserDir(c, home, "GEMINI_CLI_HOME", a.getenv("GEMINI_CLI_HOME"), "")
	if !ok {
		return
	}
	dir := base.Dir(".gemini")
	abs, logical := dir.File("settings.json")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeUser, logical, raw)}).settings(raw)
	}
	abs, logical = dir.File("GEMINI.md")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		c.Source(model.ScopeUser, logical, raw).Markdown(model.ConfigKindInstructions, "gemini", raw, kit.LooseFrontmatter)
	}
}

// defaultManagedDir is the system settings directory.
func defaultManagedDir(goos string, getenv func(string) string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/GeminiCli"
	case "windows":
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\gemini-cli`
	default:
		return "/etc/gemini-cli"
	}
}

// discoverManaged reads the system settings.json, which overrides every
// other layer, and system-defaults.json, which every other layer
// overrides. GEMINI_CLI_SYSTEM_SETTINGS_PATH and
// GEMINI_CLI_SYSTEM_DEFAULTS_PATH move either file.
func (a *Adapter) discoverManaged(c *kit.Collector) {
	dir := a.options.ManagedDir
	if dir == "" {
		dir = defaultManagedDir(runtime.GOOS, a.getenv)
	}
	for _, f := range []struct{ name, env string }{
		{"settings.json", "GEMINI_CLI_SYSTEM_SETTINGS_PATH"},
		{"system-defaults.json", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH"},
	} {
		abs := filepath.Join(dir, f.name)
		logical := path.Join(kit.ManagedPath(dir), f.name)
		if v := strings.TrimSpace(a.getenv(f.env)); v != "" {
			if !filepath.IsAbs(v) {
				c.Warn(model.ScopeManaged, "", "%s is not an absolute path; system settings were not scanned", f.env)
				continue
			}
			abs = filepath.Clean(v)
			logical = kit.ManagedPath(abs)
		}
		if raw, ok := c.ReadLocal(model.ScopeManaged, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeManaged, logical, raw)}).settings(raw)
		}
	}
}
