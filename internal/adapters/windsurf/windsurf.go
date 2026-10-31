// Package windsurf discovers Windsurf (Cascade) and Devin Local hook
// configuration without executing it: hooks (.devin/hooks.json and
// .windsurf/hooks.json, both reported; the user's
// ~/.codeium/windsurf, windsurf-next and windsurf-insiders hooks; the
// JetBrains plugin's ~/.codeium/hooks.json; and the system hooks, both
// the Devin and Windsurf directories), MCP servers, and
// rules (.windsurf/rules/, .windsurf/global_rules.md, the legacy
// .windsurfrules, and memories/global_rules.md). AGENTS.md is read by
// the generic adapter.
package windsurf

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

const product = "Windsurf"

// Options controls discovery. The zero value scans repository scope only,
// so a repository scan never reads the home directory or system files.
type Options struct {
	SkipRepo       bool
	IncludeUser    bool
	IncludeManaged bool
	// HomeDir overrides os.UserHomeDir.
	HomeDir string
	// Getenv overrides os.Getenv (for ProgramData).
	Getenv func(string) string
	// ManagedDir overrides the Windsurf system hooks directory:
	// /Library/Application Support/Windsurf on macOS, /etc/windsurf on
	// Linux, and %ProgramData%\Windsurf on Windows.
	ManagedDir string
	// DevinManagedDir overrides the Devin system hooks directory:
	// /Library/Application Support/Devin on macOS, /etc/devin on Linux,
	// and %ProgramData%\Devin on Windows.
	DevinManagedDir string
	Limits          *kit.Limits
}

// Adapter discovers Windsurf config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns a Windsurf adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessWindsurf }

// SharedOwners implements adapters.SharedReader: Cascade also loads
// AGENTS.md, reported by the generic adapter.
func (*Adapter) SharedOwners() []model.Harness { return []model.Harness{model.SurfaceGeneric} }

// Detect reports whether the repository holds a file Windsurf reads, or a
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
	c := kit.NewCollector(model.HarnessWindsurf, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every supported file in the enabled scopes. It never
// runs hooks, starts MCP servers, or invokes any program.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.HarnessWindsurf, product)
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
	roleHooks
	roleRule
	roleGlobalRules
	roleLegacyRules
)

// classify returns how Windsurf reads rel. Cascade discovers .windsurf/
// directories in subdirectories of the workspace too, so they are
// matched at any depth; .windsurfrules is read at the workspace root
// only. Matching is case-insensitive: macOS and Windows resolve
// ".Windsurf/Rules/x.md" to the same file.
func classify(rel string) role {
	segments := kit.Segments(rel)
	n := len(segments)
	base := segments[n-1]
	if n == 1 && base == ".windsurfrules" {
		return roleLegacyRules
	}
	for i := n - 2; i >= 0; i-- {
		rest := segments[i+1:]
		switch segments[i] {
		case ".devin":
			// Devin Local loads .devin/hooks.json in place of the
			// Cascade .windsurf/hooks.json. Same format.
			if len(rest) == 1 && base == "hooks.json" {
				return roleHooks
			}
			return roleNone
		case ".windsurf":
			switch {
			case len(rest) == 1 && base == "hooks.json":
				return roleHooks
			case len(rest) == 1 && base == "global_rules.md":
				return roleGlobalRules
			case len(rest) >= 2 && rest[0] == "rules" && path.Ext(base) == ".md":
				return roleRule
			}
			return roleNone
		}
	}
	return roleNone
}

var matcher = kit.Matcher{
	Candidate: func(rel string) bool { return classify(rel) != roleNone },
	Relevant: func(rel string) bool {
		segments := kit.Segments(rel)
		return kit.HasSegment(segments, ".devin") ||
			kit.HasSegment(segments, ".windsurf") ||
			(len(segments) == 1 && segments[0] == ".windsurfrules")
	},
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
		role := classify(rel)
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		normalize(c.Source(model.ScopeRepo, rel, raw), role, raw)
	}
	return nil
}

func normalize(src *kit.Source, r role, raw []byte) {
	f := &file{Source: src}
	switch r {
	case roleHooks:
		f.hooks(raw)
	case roleRule:
		f.Markdown(model.ConfigKindInstructions, "rule", raw, kit.LooseFrontmatter)
	case roleGlobalRules:
		f.Markdown(model.ConfigKindInstructions, "global", raw, kit.LooseFrontmatter)
	case roleLegacyRules:
		f.Markdown(model.ConfigKindInstructions, "rules", raw, kit.LooseFrontmatter)
	case roleNone:
	}
}

// discoverUser reads ~/.codeium/windsurf (hooks.json, mcp_config.json,
// memories/global_rules.md) and the JetBrains plugin's
// ~/.codeium/hooks.json. Windsurf has no environment override for these
// paths.
func (a *Adapter) discoverUser(c *kit.Collector) {
	home, ok := kit.ResolveHome(c, a.options.HomeDir)
	if !ok {
		return
	}
	codeium := kit.HomeDir(home, ".codeium")
	// windsurf-next and windsurf-insiders are the Next and Insiders
	// release channels; each has the same user configuration as stable.
	for _, name := range []string{"windsurf", "windsurf-next", "windsurf-insiders"} {
		readProfile(c, codeium.Dir(name))
	}
	abs, logical := codeium.File("hooks.json")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeUser, logical, raw)}).hooks(raw)
	}
}

// readProfile reads one channel's user configuration: hooks, MCP
// servers, and the global rules.
func readProfile(c *kit.Collector, dir kit.UserDir) {
	for _, f := range []struct {
		dir  kit.UserDir
		name string
		read func(*file, []byte)
	}{
		{dir, "hooks.json", (*file).hooks},
		{dir, "mcp_config.json", (*file).mcpConfig},
		{dir.Dir("memories"), "global_rules.md", func(f *file, raw []byte) {
			f.Markdown(model.ConfigKindInstructions, "global", raw, kit.LooseFrontmatter)
		}},
	} {
		abs, logical := f.dir.File(f.name)
		if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
			f.read(&file{Source: c.Source(model.ScopeUser, logical, raw)}, raw)
		}
	}
}

// devinManagedDir is the Devin Local system hooks directory.
func devinManagedDir(goos string, getenv func(string) string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/Devin"
	case "windows":
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\Devin`
	default:
		return "/etc/devin"
	}
}

// defaultManagedDir is the Windsurf system hooks directory.
func defaultManagedDir(goos string, getenv func(string) string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/Windsurf"
	case "windows":
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\Windsurf`
	default:
		return "/etc/windsurf"
	}
}

// discoverManaged reads both system hooks.json files an administrator
// can deploy for every user. Devin Local can override Windsurf at runtime,
// but both configurations are reported: skipping the fallback would let
// an empty Devin file hide executable Windsurf hooks. When ManagedDir is
// set and DevinManagedDir is not (tests), only the Windsurf directory is
// consulted, so a host's /etc/devin is never read by accident.
func (a *Adapter) discoverManaged(c *kit.Collector) {
	windsurfDir := a.options.ManagedDir
	if windsurfDir == "" {
		windsurfDir = defaultManagedDir(runtime.GOOS, a.getenv)
	}
	devinDir := a.options.DevinManagedDir
	if devinDir == "" && a.options.ManagedDir == "" {
		devinDir = devinManagedDir(runtime.GOOS, a.getenv)
	}
	if devinDir != "" {
		abs := filepath.Join(devinDir, "hooks.json")
		logical := path.Join(kit.ManagedPath(devinDir), "hooks.json")
		if raw, ok := c.ReadLocal(model.ScopeManaged, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeManaged, logical, raw)}).hooks(raw)
			fallback := filepath.Join(windsurfDir, "hooks.json")
			if info, err := os.Lstat(fallback); err == nil && !info.IsDir() {
				c.Note(model.ScopeManaged, path.Join(kit.ManagedPath(windsurfDir), "hooks.json"), true, "Devin system hooks override this Windsurf file at runtime; it was also reported")
			}
		}
	}
	abs := filepath.Join(windsurfDir, "hooks.json")
	logical := path.Join(kit.ManagedPath(windsurfDir), "hooks.json")
	if raw, ok := c.ReadLocal(model.ScopeManaged, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeManaged, logical, raw)}).hooks(raw)
	}
}
