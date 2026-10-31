// Package generic discovers files that more than one coding agent reads:
// shared skills (.agents/skills, .github/skills) in the repository and,
// optionally, in the user's home (~/.agents/skills); AGENTS.md at any
// depth; and the VS Code workspace files .vscode/tasks.json and
// .vscode/mcp.json. Each file is reported here, once, so its fingerprint
// does not depend on which harness adapters ran. Skills and AGENTS.md use
// harness generic; the VS Code files use harness vscode, the surface
// Copilot, Cursor, and Windsurf share.
package generic

import (
	"context"
	"path"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// product names the readers of shared files in diagnostics.
const product = "a coding agent"

// Limits bounds repository discovery. The numbers match the Claude adapter.
type Limits = kit.Limits

// DefaultLimits are the scan defaults.
func DefaultLimits() Limits { return kit.DefaultLimits() }

// Options controls discovery. The zero value scans the repository.
type Options struct {
	// SkipRepo omits the repository. Managed scope has no shared files.
	SkipRepo bool
	// IncludeUser scans ~/.agents/skills, the shared user-scope skill
	// location several harnesses read (Codex also reads the
	// harness-specific, deprecated ~/.codex/skills itself).
	IncludeUser bool
	// HomeDir overrides os.UserHomeDir.
	HomeDir string
	Limits  *Limits
}

// Adapter discovers shared files.
type Adapter struct {
	options Options
	limits  Limits
}

// New returns the shared-files adapter.
func New(options Options) *Adapter {
	limits := DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.SurfaceGeneric }

// Detect reports whether the repository has a shared file, or a shared
// path that cannot be read safely.
func (a *Adapter) Detect(repoRoot string) bool {
	// User scope is outside the repository, so a repo with no shared
	// files still has configuration to read when that scope is on.
	if a.options.IncludeUser {
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
	c := kit.NewCollector(model.SurfaceGeneric, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every shared file in the enabled scopes. It never
// executes tasks, hooks, or servers.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.SurfaceGeneric, product)
	if a.options.IncludeUser {
		if err := a.discoverUser(ctx, c); err != nil {
			return nil, err
		}
	}
	if !a.options.SkipRepo {
		if err := a.discoverRepo(ctx, repoRoot, c); err != nil {
			return nil, err
		}
	}
	return c.Result()
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
		switch classify(rel) {
		case roleSkill:
			c.Append(claude.NormalizeSkill(model.SurfaceGeneric, model.ScopeRepo, rel, "", raw))
		case roleAgents:
			c.Source(model.ScopeRepo, rel, raw).Markdown(model.ConfigKindInstructions, "agents", raw, kit.LooseFrontmatter)
		case roleTasks:
			tasksFile(c.Source(model.ScopeRepo, rel, raw).WithHarness(model.SurfaceVSCode), raw)
		case roleMCP:
			mcpFile(c.Source(model.ScopeRepo, rel, raw).WithHarness(model.SurfaceVSCode), raw)
		case roleNone:
		}
	}
	return nil
}

// discoverUser reads ~/.agents/skills, the shared user-scope skill
// directory several harnesses read. Codex's deprecated, Codex-only
// ~/.codex/skills is read by the Codex adapter itself, not here.
func (a *Adapter) discoverUser(ctx context.Context, c *kit.Collector) error {
	home, ok := kit.ResolveHome(c, a.options.HomeDir)
	if !ok {
		return nil
	}
	dir := kit.HomeDir(home, ".agents/skills")
	reader, files, err := kit.OpenUserWalk(ctx, c, a.limits, dir, kit.SkillFileMatcher)
	if err != nil {
		return err
	}
	if reader == nil {
		return nil
	}
	defer func() { _ = reader.Close() }()
	r := kit.NewScopedReader(reader, a.limits, c, model.ScopeUser, dir.Logical)
	for _, rel := range files {
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		c.Append(claude.NormalizeSkill(model.SurfaceGeneric, model.ScopeUser, dir.Logical+"/"+rel, home, raw))
	}
	return nil
}

type role int

const (
	roleNone role = iota
	roleSkill
	roleAgents
	roleTasks
	roleMCP
)

// skillRoots are the shared skill directories. Claude's .claude/skills is
// not here.
var skillRoots = [][]string{{".agents", "skills"}, {".github", "skills"}}

// classify returns how rel is shared. AGENTS.md and the .vscode files are
// matched case-insensitively, because macOS and Windows resolve
// ".VSCode/Tasks.json" to the file VS Code opens. Skill paths keep the
// exact-case match of the Claude adapter's skill loader.
func classify(rel string) role {
	segments := kit.Segments(rel)
	n := len(segments)
	base := segments[n-1]
	parent := ""
	if n >= 2 {
		parent = segments[n-2]
	}
	switch {
	case path.Base(rel) == "SKILL.md" && isSkillDir(strings.Split(rel, "/")):
		return roleSkill
	case base == "agents.md":
		return roleAgents
	case parent == ".vscode" && base == "tasks.json":
		return roleTasks
	case parent == ".vscode" && base == "mcp.json":
		return roleMCP
	}
	return roleNone
}

func isSkillDir(segments []string) bool {
	parent := segments[:len(segments)-1]
	for _, root := range skillRoots {
		if kit.HasSequence(parent, root) {
			return true
		}
	}
	return false
}

var matcher = kit.Matcher{
	Candidate: func(rel string) bool { return classify(rel) != roleNone },
	Relevant: func(rel string) bool {
		segments := strings.Split(rel, "/")
		if segments[0] == ".vscode" {
			return true
		}
		for _, root := range skillRoots {
			if kit.HasSequence(segments, root) {
				return true
			}
		}
		return false
	},
}
