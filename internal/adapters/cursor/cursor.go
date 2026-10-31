// Package cursor discovers Cursor configuration without executing it:
// hooks.json (project, user, and enterprise), mcp.json (project and
// user), project rules (.cursor/rules/**/*.mdc and legacy .cursorrules),
// and the cloud-agent environment file .cursor/environment.json.
// AGENTS.md and .vscode files are read by the generic adapter, and the
// Claude Code hooks Cursor also loads by the Claude adapter.
package cursor

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

const product = "Cursor"

// Options controls discovery. The zero value scans repository scope only,
// so a repository scan never reads the home directory or system files.
type Options struct {
	SkipRepo       bool
	IncludeUser    bool
	IncludeManaged bool
	// HomeDir overrides os.UserHomeDir.
	HomeDir string
	// ManagedDir overrides the enterprise hooks directory:
	// /Library/Application Support/Cursor on macOS, /etc/cursor on Linux,
	// and %ProgramData%\Cursor on Windows.
	ManagedDir string
	Limits     *kit.Limits
}

// Adapter discovers Cursor config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns a Cursor adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessCursor }

// SharedOwners implements adapters.SharedReader: Cursor also loads
// AGENTS.md and .vscode files (generic) and Claude Code hooks (claude).
func (*Adapter) SharedOwners() []model.Harness {
	return []model.Harness{model.HarnessClaude, model.SurfaceGeneric}
}

// Detect reports whether the repository holds a file Cursor reads, or a
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
	c := kit.NewCollector(model.HarnessCursor, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every supported file in the enabled scopes. It never
// runs hooks, starts MCP servers, or invokes any program.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.HarnessCursor, product)
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

type role int

const (
	roleNone role = iota
	roleHooks
	roleMCP
	roleRule
	roleLegacyRules
	roleEnvironment
)

// classify returns how Cursor reads rel. Matching is case-insensitive:
// macOS and Windows resolve ".Cursor/Hooks.json" to the same file.
func classify(rel string) role {
	segments := kit.Segments(rel)
	n := len(segments)
	base := segments[n-1]
	parent := ""
	if n >= 2 {
		parent = segments[n-2]
	}
	switch {
	case parent == ".cursor" && base == "hooks.json":
		return roleHooks
	case parent == ".cursor" && base == "mcp.json":
		return roleMCP
	case parent == ".cursor" && base == "environment.json":
		return roleEnvironment
	case base == ".cursorrules":
		return roleLegacyRules
	case (strings.HasSuffix(base, ".mdc") || strings.HasSuffix(base, ".md")) && kit.HasSequence(segments[:n-1], []string{".cursor", "rules"}):
		return roleRule
	}
	return roleNone
}

var matcher = kit.Matcher{
	Candidate: func(rel string) bool { return classify(rel) != roleNone },
	Relevant:  func(rel string) bool { return kit.HasSegment(kit.Segments(rel), ".cursor") },
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
		case roleHooks:
			f.hooksFile(raw)
		case roleMCP:
			f.mcpFile(raw)
		case roleEnvironment:
			f.environment(raw)
		case roleRule:
			f.Markdown(model.ConfigKindInstructions, "rule", raw, kit.LooseFrontmatter)
		case roleLegacyRules:
			f.Markdown(model.ConfigKindInstructions, "cursorrules", raw, kit.LooseFrontmatter)
		case roleNone:
		}
	}
	return nil
}

// discoverUser reads ~/.cursor/hooks.json and ~/.cursor/mcp.json. Cursor
// documents no environment variable that moves this directory.
func (a *Adapter) discoverUser(c *kit.Collector) {
	home, ok := kit.ResolveHome(c, a.options.HomeDir)
	if !ok {
		return
	}
	dir, _ := kit.ResolveUserDir(c, home, "", "", ".cursor")
	abs, logical := dir.File("hooks.json")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeUser, logical, raw)}).hooksFile(raw)
	}
	abs, logical = dir.File("mcp.json")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeUser, logical, raw)}).mcpFile(raw)
	}
}

// defaultManagedDir is the documented enterprise (MDM) hooks directory.
func defaultManagedDir(goos string, getenv func(string) string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/Cursor"
	case "windows":
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\Cursor`
	default:
		return "/etc/cursor"
	}
}

func (a *Adapter) discoverManaged(c *kit.Collector) {
	dir := a.options.ManagedDir
	if dir == "" {
		dir = defaultManagedDir(runtime.GOOS, os.Getenv)
	}
	abs := filepath.Join(dir, "hooks.json")
	logical := path.Join(kit.ManagedPath(dir), "hooks.json")
	if raw, ok := c.ReadLocal(model.ScopeManaged, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeManaged, logical, raw)}).hooksFile(raw)
	}
}
