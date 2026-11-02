// Package opencode discovers OpenCode configuration without executing
// it: opencode.json and opencode.jsonc (MCP servers, npm plugins,
// permissions, inline agents and commands, formatters, LSP servers,
// providers), .opencode/ agents and commands, and the JS/TS plugin and
// custom tool files OpenCode loads and runs, which are reported as
// executable configuration and never parsed. It covers the repository,
// the user config directory, OPENCODE_CONFIG and OPENCODE_CONFIG_DIR,
// the managed config directory, and, as redacted references only, the
// credential files in the data directory. AGENTS.md and shared skills
// are read by the generic adapter, CLAUDE.md and .claude/skills by the
// Claude adapter.
package opencode

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
)

const product = "OpenCode"

// maxDirFiles caps the plugin or tool files read from one user-scope
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
	// Getenv overrides os.Getenv (for XDG_CONFIG_HOME, XDG_DATA_HOME,
	// OPENCODE_CONFIG, OPENCODE_CONFIG_DIR, and ProgramData).
	Getenv func(string) string
	// ManagedDir overrides the managed config directory:
	// /Library/Application Support/opencode on macOS, /etc/opencode on
	// Linux, and %ProgramData%\opencode on Windows.
	ManagedDir string
	Limits     *kit.Limits
	// FingerprintKey selects the keyed k1 "sig:" discriminator for
	// entries that lost a secret to redaction; nil selects s1.
	FingerprintKey *fpkey.Key
}

// Adapter discovers OpenCode config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns an OpenCode adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessOpenCode }

// Classifies reports whether rel is a file this adapter reads. It uses
// the same path rules as discovery and does not open the file. Nested
// plugin and tool files are included; discovery notes them and does not
// treat them as the loaded entrypoint.
func (*Adapter) Classifies(rel string) bool { return classify(rel) != roleNone }

// SharedOwners implements adapters.SharedReader: OpenCode also loads
// AGENTS.md and shared skills (generic), and falls back to CLAUDE.md and
// .claude/skills (claude).
func (*Adapter) SharedOwners() []model.Harness {
	return []model.Harness{model.HarnessClaude, model.SurfaceGeneric}
}

// Detect reports whether the repository holds a file OpenCode reads, or a
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
	c := kit.NewCollector(model.HarnessOpenCode, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every supported file in the enabled scopes. It never
// loads a plugin, starts an MCP server, or invokes any program.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.HarnessOpenCode, product)
	c.SetFingerprintKey(a.options.FingerprintKey)
	if !a.options.SkipRepo {
		if err := a.discoverRepo(ctx, repoRoot, c); err != nil {
			return nil, err
		}
	}
	if a.options.IncludeUser {
		if err := a.discoverUser(ctx, c); err != nil {
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
	roleAgent
	roleCommand
	rolePlugin
	roleTool
	roleGlobalAgents
	roleNested
)

// codeExtensions are the file types OpenCode loads from plugin and tool
// directories.
var codeExtensions = map[string]bool{".js": true, ".ts": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true, ".jsx": true, ".tsx": true}

// classifyDir returns how OpenCode reads rel inside a config directory
// (.opencode/, the user config directory, or OPENCODE_CONFIG_DIR). Both
// the plural directory names and the older singular ones are read.
// Plugin and tool files are loaded from the directory itself, not from
// subdirectories (which hold their helper modules). global is true for
// the user config directory, whose AGENTS.md is OpenCode's own global
// rules file rather than a repository AGENTS.md.
func classifyDir(segments []string, global bool) role {
	n := len(segments)
	base := segments[n-1]
	if n == 1 {
		switch {
		case base == "opencode.json" || base == "opencode.jsonc" || (global && base == "config.json"):
			return roleConfig
		case global && base == "agents.md":
			return roleGlobalAgents
		}
		return roleNone
	}
	if base == "agents.md" && !global {
		return roleNone
	}
	if kit.HasSegment(segments, "node_modules") {
		return roleNone
	}
	ext := path.Ext(base)
	switch segments[0] {
	case "agents", "agent":
		if ext == ".md" {
			return roleAgent
		}
	case "commands", "command":
		if ext == ".md" {
			return roleCommand
		}
	case "plugins", "plugin":
		if codeExtensions[ext] {
			if n == 2 {
				return rolePlugin
			}
			return roleNested
		}
	case "tools", "tool":
		if codeExtensions[ext] {
			if n == 2 {
				return roleTool
			}
			return roleNested
		}
	}
	return roleNone
}

// classify returns how OpenCode reads rel in the repository. OpenCode
// looks for its config from the working directory up to the Git root, so
// opencode.json(c) and .opencode/ are matched at any depth. AGENTS.md is
// the generic adapter's. Matching is case-insensitive: macOS and Windows
// resolve ".OpenCode/Plugins/x.ts" to the same file.
func classify(rel string) role {
	segments := kit.Segments(rel)
	n := len(segments)
	base := segments[n-1]
	if base == "agents.md" {
		return roleNone
	}
	for i := n - 2; i >= 0; i-- {
		if segments[i] == ".opencode" {
			return classifyDir(segments[i+1:], false)
		}
	}
	if base == "opencode.json" || base == "opencode.jsonc" {
		return roleConfig
	}
	return roleNone
}

var matcher = kit.Matcher{
	Candidate: func(rel string) bool { return classify(rel) != roleNone },
	Relevant: func(rel string) bool {
		segments := kit.Segments(rel)
		base := segments[len(segments)-1]
		if base == "agents.md" || kit.HasSegment(segments, "node_modules") {
			return false
		}
		return kit.HasSegment(segments, ".opencode") || base == "opencode.json" || base == "opencode.jsonc"
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
	var nested []string
	for _, rel := range files {
		role := classify(rel)
		if role == roleNested {
			// The file is not read: OpenCode does not load it, and its
			// contents must not count against the byte budget.
			nested = append(nested, rel)
			continue
		}
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		normalize(c.Source(model.ScopeRepo, rel, raw), role, rel, raw)
	}
	noteNestedRepo(c, nested)
	return nil
}

// nestedNote is the informational diagnostic for a code file below a
// plugin or tool directory. OpenCode loads only the directory's own
// files; nested files are helper modules.
const nestedNote = "nested plugin or tool file; OpenCode loads only the files directly inside plugins/, plugin/, tools/, and tool/, so this file is not reported as executable configuration"

func normalize(src *kit.Source, r role, rel string, raw []byte) {
	f := &file{Source: src}
	switch r {
	case roleConfig:
		f.config(raw)
	case roleAgent:
		f.Markdown(model.ConfigKindInstructions, "agent", raw, kit.StrictFrontmatter)
	case roleCommand:
		f.Markdown(model.ConfigKindInstructions, "command", raw, kit.LooseFrontmatter)
	case roleGlobalAgents:
		f.Markdown(model.ConfigKindInstructions, "agents", raw, kit.LooseFrontmatter)
	case rolePlugin:
		f.codeFile("plugin", rel)
	case roleTool:
		f.codeFile("tool", rel)
	case roleNested:
		f.Note("%s", nestedNote)
	case roleNone:
	}
}

// discoverUser reads the user config directory ($XDG_CONFIG_HOME/opencode,
// default ~/.config/opencode), OPENCODE_CONFIG and OPENCODE_CONFIG_DIR
// when set, and records the credential files in the data directory
// ($XDG_DATA_HOME/opencode, default ~/.local/share/opencode) without
// reading them. A relative XDG value is ignored (the default is used);
// an XDG value outside home is scanned and noted, and does not by itself
// fail the scan. OPENCODE_CONFIG and OPENCODE_CONFIG_DIR outside home
// stay blocking.
func (a *Adapter) discoverUser(ctx context.Context, c *kit.Collector) error {
	home, ok := kit.ResolveHome(c, a.options.HomeDir)
	if !ok {
		return nil
	}
	if strings.TrimSpace(a.getenv("OPENCODE_CONFIG_CONTENT")) != "" {
		c.Note(model.ScopeUser, "", true, "OPENCODE_CONFIG_CONTENT is set; inline configuration from the environment was not scanned")
	}
	base := kit.ResolveXDGDir(c, home, "XDG_CONFIG_HOME", a.getenv("XDG_CONFIG_HOME"), ".config")
	if err := a.configDir(ctx, c, base.Dir("opencode"), true); err != nil {
		return err
	}
	if v := strings.TrimSpace(a.getenv("OPENCODE_CONFIG")); v != "" {
		if dir, ok := kit.ResolveUserDir(c, home, "OPENCODE_CONFIG", filepath.Dir(v), ""); ok {
			abs, logical := dir.File(filepath.Base(v))
			if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
				(&file{Source: c.Source(model.ScopeUser, logical, raw)}).config(raw)
			}
		}
	}
	if v := a.getenv("OPENCODE_CONFIG_DIR"); strings.TrimSpace(v) != "" {
		if dir, ok := kit.ResolveUserDir(c, home, "OPENCODE_CONFIG_DIR", v, ""); ok {
			if err := a.configDir(ctx, c, dir, false); err != nil {
				return err
			}
		}
	}
	data := kit.ResolveXDGDir(c, home, "XDG_DATA_HOME", a.getenv("XDG_DATA_HOME"), ".local/share")
	credentials(c, data.Dir("opencode"))
	return nil
}

// configDir reads a user-scope config directory: its config files and
// global AGENTS.md, Markdown agents and commands at any depth, and
// plugin and tool files directly inside plugins/ and tools/. The
// directory is not walked as a whole, because OpenCode installs plugin
// dependencies into its node_modules.
func (a *Adapter) configDir(ctx context.Context, c *kit.Collector, dir kit.UserDir, global bool) error {
	for _, name := range []string{"config.json", "opencode.json", "opencode.jsonc", "AGENTS.md"} {
		segments := []string{strings.ToLower(name)}
		r := classifyDir(segments, global)
		if r == roleNone {
			continue
		}
		abs, logical := dir.File(name)
		if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
			normalize(c.Source(model.ScopeUser, logical, raw), r, logical, raw)
		}
	}
	for _, sub := range []string{"agents", "agent", "commands", "command"} {
		if err := a.markdownDir(ctx, c, dir.Dir(sub), sub); err != nil {
			return err
		}
	}
	for _, sub := range []string{"plugins", "plugin", "tools", "tool"} {
		subDir := dir.Dir(sub)
		for _, name := range c.ListLocal(model.ScopeUser, subDir.Abs, subDir.Logical, "", maxDirFiles) {
			r := classifyDir([]string{sub, strings.ToLower(name)}, global)
			if r == roleNone {
				continue
			}
			abs, logical := subDir.File(name)
			if raw, ok := c.ReadLocal(model.ScopeUser, abs, logical); ok {
				normalize(c.Source(model.ScopeUser, logical, raw), r, logical, raw)
			}
		}
		noteNestedCode(c, subDir, sub)
	}
	return nil
}

// maxNestedNotes caps the nested plugin and tool files noted in one
// scan, so a dependency tree cannot flood the scan.
const maxNestedNotes = 32

// noteNestedRepo records at most maxNestedNotes nested code-file notes,
// then one deterministic summary naming the number omitted. The nested
// files are not read.
func noteNestedRepo(c *kit.Collector, files []string) {
	for i, rel := range files {
		if i == maxNestedNotes {
			remaining := len(files) - i
			noun, verb := "files", "were"
			if remaining == 1 {
				noun, verb = "file", "was"
			}
			c.Note(model.ScopeRepo, "", true, "further %d nested plugin or tool %s %s not listed", remaining, noun, verb)
			return
		}
		c.Note(model.ScopeRepo, rel, true, "%s", nestedNote)
	}
}

// noteNestedCode notes code files below a user-scope plugin or tool
// directory. node_modules and dot directories are skipped, and symlinks
// are not followed.
func noteNestedCode(c *kit.Collector, dir kit.UserDir, sub string) {
	var notes, visits int
	var walk func(abs, logical string)
	walk = func(abs, logical string) {
		visits++
		if visits > maxDirFiles || notes > maxNestedNotes {
			return
		}
		entries, err := os.ReadDir(abs)
		if err != nil {
			return
		}
		names := make([]string, 0, len(entries))
		byName := map[string]fs.DirEntry{}
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, ".") || strings.EqualFold(name, "node_modules") || entry.Type()&fs.ModeSymlink != 0 {
				continue
			}
			names = append(names, name)
			byName[name] = entry
		}
		sort.Strings(names)
		for _, name := range names {
			entry := byName[name]
			child := filepath.Join(abs, name)
			logicalChild := logical + "/" + name
			if entry.IsDir() {
				walk(child, logicalChild)
				continue
			}
			if abs == dir.Abs || !codeExtensions[strings.ToLower(path.Ext(name))] {
				continue
			}
			if notes == maxNestedNotes {
				c.Note(model.ScopeUser, dir.Logical, true, "further nested files in %s were not listed", sub)
				notes++
				return
			}
			c.Note(model.ScopeUser, logicalChild, true, "%s", nestedNote)
			notes++
		}
	}
	walk(dir.Abs, dir.Logical)
}

func (a *Adapter) markdownDir(ctx context.Context, c *kit.Collector, dir kit.UserDir, sub string) error {
	m := kit.Matcher{
		Candidate: func(rel string) bool { return strings.HasSuffix(strings.ToLower(rel), ".md") },
		Relevant:  func(string) bool { return true },
	}
	reader, files, err := kit.OpenUserWalk(ctx, c, a.limits, dir, m)
	if err != nil || reader == nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	r := kit.NewScopedReader(reader, a.limits, c, model.ScopeUser, dir.Logical)
	for _, rel := range files {
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		logical := dir.Logical + "/" + rel
		normalize(c.Source(model.ScopeUser, logical, raw), classifyDir(append([]string{sub}, kit.Segments(rel)...), true), logical, raw)
	}
	return nil
}

// credentialFiles hold provider API keys and MCP OAuth tokens. They are
// reported as secret-bearing references and never read.
var credentialFiles = []string{"auth.json", "mcp-auth.json"}

// credentials emits one env-setup item per credential file that exists.
// The file is not opened: its item's sha256 is the digest of empty input,
// not of the file, so no hash of the secret leaves the machine.
func credentials(c *kit.Collector, dir kit.UserDir) {
	for _, name := range credentialFiles {
		abs, logical := dir.File(name)
		info, err := os.Lstat(abs)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			c.Warn(model.ScopeUser, logical, "cannot inspect credential file")
			continue
		case info.IsDir():
			continue
		}
		src := c.Source(model.ScopeUser, logical, nil)
		src.Add(model.ConfigKindEnvSetup, []string{"credentials", name}, map[string]any{
			"setting":        "credentials",
			"file":           name,
			"secret_bearing": true,
			"value":          kit.Redacted,
		})
	}
}

// defaultManagedDir is the documented managed config directory.
func defaultManagedDir(goos string, getenv func(string) string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/opencode"
	case "windows":
		base := getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\opencode`
	default:
		return "/etc/opencode"
	}
}

// discoverManaged reads opencode.json and opencode.jsonc from the managed
// directory. macOS managed preferences (.mobileconfig) are not read.
func (a *Adapter) discoverManaged(c *kit.Collector) {
	dir := a.options.ManagedDir
	if dir == "" {
		dir = defaultManagedDir(runtime.GOOS, a.getenv)
	}
	for _, name := range []string{"opencode.json", "opencode.jsonc"} {
		abs := filepath.Join(dir, name)
		logical := path.Join(kit.ManagedPath(dir), name)
		if raw, ok := c.ReadLocal(model.ScopeManaged, abs, logical); ok {
			(&file{Source: c.Source(model.ScopeManaged, logical, raw)}).config(raw)
		}
	}
}
