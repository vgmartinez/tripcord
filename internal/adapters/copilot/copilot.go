// Package copilot discovers GitHub Copilot configuration without
// executing it: repository and user hook files, inline hooks in Copilot
// CLI settings, custom agents with frontmatter hooks, instruction files,
// the user MCP config, machine-wide policy hooks, and the cloud agent's
// copilot-setup-steps workflow. AGENTS.md, shared skills, and .vscode
// files are read by the generic adapter; .mcp.json and .claude/settings.json
// by the Claude adapter.
package copilot

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

const product = "Copilot"

// maxDirFiles caps the *.json files read from one user or policy hooks
// directory.
const maxDirFiles = 256

// Options controls discovery. The zero value scans repository scope only,
// so a repository scan never reads the home directory or system files.
type Options struct {
	SkipRepo       bool
	IncludeUser    bool
	IncludeManaged bool
	// HomeDir overrides os.UserHomeDir.
	HomeDir string
	// Getenv overrides os.Getenv (for COPILOT_HOME and ProgramData).
	Getenv func(string) string
	// PolicyDir overrides the policy hooks directory:
	// /etc/github-copilot/policy.d on Linux and macOS, and
	// %ProgramData%\GitHub\Copilot\policy.d on Windows.
	PolicyDir string
	Limits    *kit.Limits
}

// Adapter discovers Copilot config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns a Copilot adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessCopilot }

// SharedOwners implements adapters.SharedReader: Copilot also loads
// AGENTS.md, shared skills, and .vscode files (generic), and .mcp.json and
// .claude/settings.json hooks (claude).
func (*Adapter) SharedOwners() []model.Harness {
	return []model.Harness{model.HarnessClaude, model.SurfaceGeneric}
}

// Detect reports whether the repository holds a file Copilot reads, or a
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
	c := kit.NewCollector(model.HarnessCopilot, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every supported file in the enabled scopes. It never
// runs hooks, workflows, or MCP servers.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.HarnessCopilot, product)
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
	roleSettings
	roleAgent
	roleRepoInstructions
	roleInstructions
	roleSetupSteps
)

// classify returns how Copilot reads rel. Copilot reads .github from the
// repository root only. Matching is case-insensitive: macOS and Windows
// resolve ".GitHub/Hooks/x.json" to the same file.
func classify(rel string) role {
	segments := kit.Segments(rel)
	n := len(segments)
	if n < 2 || segments[0] != ".github" {
		return roleNone
	}
	base := segments[n-1]
	switch {
	case n == 2 && base == "copilot-instructions.md":
		return roleRepoInstructions
	case n == 3 && segments[1] == "hooks" && strings.HasSuffix(base, ".json"):
		return roleHooks
	case n == 3 && segments[1] == "copilot" && (base == "settings.json" || base == "settings.local.json"):
		return roleSettings
	case n == 3 && segments[1] == "agents" && strings.HasSuffix(base, ".agent.md"):
		return roleAgent
	case n == 3 && segments[1] == "workflows" && base == "copilot-setup-steps.yml":
		return roleSetupSteps
	case n >= 3 && segments[1] == "instructions" && strings.HasSuffix(base, ".instructions.md"):
		return roleInstructions
	}
	return roleNone
}

// copilotDirs are the .github subdirectories Copilot reads from (see
// classify): hooks, copilot, agents, workflows, and instructions. An
// escaping symlink under any other .github subdirectory, such as
// .github/skills (generic's shared skill root) or .github/ISSUE_TEMPLATE,
// is not Copilot's to report.
var copilotDirs = map[string]bool{"hooks": true, "copilot": true, "agents": true, "workflows": true, "instructions": true}

var matcher = kit.Matcher{
	Candidate: func(rel string) bool { return classify(rel) != roleNone },
	Relevant: func(rel string) bool {
		segments := kit.Segments(rel)
		if segments[0] != ".github" {
			return false
		}
		return len(segments) == 1 || copilotDirs[segments[1]]
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
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		f := &file{Source: c.Source(model.ScopeRepo, rel, raw)}
		switch classify(rel) {
		case roleHooks:
			f.hooksFile(raw)
		case roleSettings:
			f.settings(raw)
		case roleAgent:
			f.agent(raw)
		case roleRepoInstructions:
			f.Markdown(model.ConfigKindInstructions, "copilot-instructions", raw, kit.LooseFrontmatter)
		case roleInstructions:
			f.Markdown(model.ConfigKindInstructions, "instructions", raw, kit.LooseFrontmatter)
		case roleSetupSteps:
			f.setupSteps(raw)
		case roleNone:
		}
	}
	return nil
}

// discoverUser reads $COPILOT_HOME (default ~/.copilot): mcp-config.json,
// settings.json, and hooks/*.json.
func (a *Adapter) discoverUser(c *kit.Collector) {
	home, ok := kit.ResolveHome(c, a.options.HomeDir)
	if !ok {
		return
	}
	dir, ok := kit.ResolveUserDir(c, home, "COPILOT_HOME", a.getenv("COPILOT_HOME"), ".copilot")
	if !ok {
		return
	}
	abs, logical := dir.File("mcp-config.json")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeUser, logical, raw)}).mcpConfig(raw)
	}
	abs, logical = dir.File("settings.json")
	if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
		(&file{Source: c.Source(model.ScopeUser, logical, raw)}).settings(raw)
	}
	hooksAbs, hooksLogical := dir.File("hooks")
	for _, name := range c.ListLocal(model.ScopeUser, hooksAbs, hooksLogical, ".json", maxDirFiles) {
		abs, logical := filepath.Join(hooksAbs, name), hooksLogical+"/"+name
		if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeUser, logical, raw)}).hooksFile(raw)
		}
	}
}

// defaultPolicyDir is the documented machine-wide policy hooks directory.
func defaultPolicyDir(goos string, getenv func(string) string) string {
	if goos == "windows" {
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\GitHub\Copilot\policy.d`
	}
	return "/etc/github-copilot/policy.d"
}

// discoverManaged reads policy.d/*.json. The Windows registry policy
// source (HKLM\Software\Policies\GitHub\Copilot) is not read.
func (a *Adapter) discoverManaged(c *kit.Collector) {
	dir := a.options.PolicyDir
	if dir == "" {
		dir = defaultPolicyDir(runtime.GOOS, a.getenv)
	}
	logicalDir := kit.ManagedPath(dir)
	for _, name := range c.ListLocal(model.ScopeManaged, dir, logicalDir, ".json", maxDirFiles) {
		abs, logical := filepath.Join(dir, name), path.Join(logicalDir, name)
		if raw, ok := c.ReadLocal(model.ScopeManaged, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeManaged, logical, raw)}).hooksFile(raw)
		}
	}
}
