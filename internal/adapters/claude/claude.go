// Package claude discovers Claude Code configuration without executing it.
package claude

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
)

// maxClaudeJSONBytes caps ~/.claude.json. Claude Code keeps per-project
// state there, so real files grow well past MaxConfigFileBytes; it is parsed
// as a stream and only the MCP server keys are retained.
const maxClaudeJSONBytes int64 = 256 << 20

// maxManagedDropIns caps managed-settings.d entries.
const maxManagedDropIns = 256

// legacyManagedDir is the legacy Windows managed directory. It is not
// scanned. When it exists, discovery emits an informational diagnostic.
var legacyManagedDir = `C:\ProgramData\ClaudeCode`

// SetLegacyManagedDirForTest points the legacy ProgramData probe at dir
// and returns a restore function. The CLI does not call it.
func SetLegacyManagedDirForTest(dir string) func() {
	prev := legacyManagedDir
	legacyManagedDir = dir
	return func() { legacyManagedDir = prev }
}

// Options controls discovery. The zero value scans repository scope only;
// the CLI uses it so a repository scan never reads the developer's home
// directory or system configuration implicitly.
type Options struct {
	// SkipRepo omits the repository. The zero value scans it.
	SkipRepo       bool
	IncludeUser    bool
	IncludeManaged bool
	// HomeDir overrides os.UserHomeDir.
	HomeDir string
	// Getenv overrides os.Getenv (for CLAUDE_CONFIG_DIR).
	Getenv func(string) string
	// ManagedDir overrides the OS managed settings directory.
	ManagedDir string
	// LegacyDir overrides the legacy ProgramData probe. Empty uses
	// C:\ProgramData\ClaudeCode. The CLI leaves it empty.
	LegacyDir string
	// Limits overrides DefaultLimits for repository discovery.
	Limits *Limits
	// FingerprintKey selects the keyed k1 "sig:" discriminator for
	// entries that lost a secret to redaction; nil selects s1.
	FingerprintKey *fpkey.Key
}

// Adapter discovers Claude Code config.
type Adapter struct {
	options Options
	limits  Limits
}

// New returns a Claude Code adapter.
func New(options Options) *Adapter {
	limits := DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessClaude }

// Classifies reports whether rel is a file this adapter reads from the
// path alone. Plugin files that match only after a plugin root is
// discovered are not included; discovery still reads those.
func (*Adapter) Classifies(rel string) bool { return classify(rel, nil) != roleNone }

// Detect reports whether the repository holds any file Claude Code reads,
// or a config-relevant path Tripcord cannot safely read.
func (a *Adapter) Detect(repoRoot string) bool {
	// User and managed scopes are outside the repository, so a repo with no
	// Claude files still has configuration to read when those scopes are on.
	if a.options.IncludeUser || a.options.IncludeManaged {
		return true
	}
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		return false
	}
	defer func() { _ = reader.Close() }()
	c := newCollector(a.options.FingerprintKey)
	files, err := a.listRepo(context.Background(), reader, c)
	if err != nil {
		return false
	}
	for _, rel := range files {
		if classify(rel, nil) != roleNone {
			return true
		}
	}
	return len(c.diags) > 0
}

// Discover reads every supported config file in the enabled scopes. It
// never runs hooks, starts MCP servers, expands variables, or invokes git
// or any other program. Problems with individual files are returned as a
// *adapters.DiagnosticError together with the items that could be read.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := newCollector(a.options.FingerprintKey)
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
	sort.SliceStable(c.items, func(i, j int) bool {
		x, y := c.items[i], c.items[j]
		if x.Scope != y.Scope {
			return x.Scope < y.Scope
		}
		if x.Path != y.Path {
			return x.Path < y.Path
		}
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		return string(x.Payload) < string(y.Payload)
	})
	if len(c.diags) > 0 {
		return c.items, &adapters.DiagnosticError{Diagnostics: c.diags}
	}
	return c.items, nil
}

func (a *Adapter) getenv(name string) string {
	if a.options.Getenv != nil {
		return a.options.Getenv(name)
	}
	return os.Getenv(name)
}

// userPaths returns the absolute and logical ("~/"-rooted) paths of the user
// settings file and ~/.claude.json. CLAUDE_CONFIG_DIR moves both.
func (a *Adapter) userPaths(c *collector) (home string, files [][2]string, ok bool) {
	home = a.options.HomeDir
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			c.warn(model.ScopeUser, "~", "cannot determine the home directory")
			return "", nil, false
		}
	}
	configDir := filepath.Join(home, ".claude")
	claudeJSON := filepath.Join(home, ".claude.json")
	outside := false
	if dir := strings.TrimSpace(a.getenv("CLAUDE_CONFIG_DIR")); dir != "" {
		if !filepath.IsAbs(dir) {
			c.warn(model.ScopeUser, "", "CLAUDE_CONFIG_DIR is not an absolute path; user configuration was not scanned")
			return "", nil, false
		}
		configDir = filepath.Clean(dir)
		claudeJSON = filepath.Join(configDir, ".claude.json")
		logicalDir := tildePath(home, configDir)
		outside = logicalDir != "~" && !strings.HasPrefix(logicalDir, "~/")
	}
	settings := filepath.Join(configDir, "settings.json")
	for _, p := range []string{settings, claudeJSON} {
		logical := tildePath(home, p)
		if outside {
			rel, err := filepath.Rel(configDir, p)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				c.warn(model.ScopeUser, "~/CLAUDE_CONFIG_DIR", "CLAUDE_CONFIG_DIR is outside the home directory; a file could not be named without its absolute path and was not scanned")
				return "", nil, false
			}
			logical = "~/CLAUDE_CONFIG_DIR/" + filepath.ToSlash(rel)
		}
		if !strings.HasPrefix(logical, "~/") {
			// outside is always false here: when it is true, logical was
			// already rewritten to "~/CLAUDE_CONFIG_DIR/..." above, which
			// always has this prefix. This is the home directory itself
			// being too short to root a "~/..." path under (empty, "/",
			// or similar), not a CLAUDE_CONFIG_DIR problem.
			c.warn(model.ScopeUser, "", "home directory is too short to scope user configuration under it; user configuration was not scanned")
			return "", nil, false
		}
		files = append(files, [2]string{p, logical})
	}
	if outside {
		c.warn(model.ScopeUser, "~/CLAUDE_CONFIG_DIR", "CLAUDE_CONFIG_DIR is outside the home directory; configuration is scanned and paths are shown as ~/CLAUDE_CONFIG_DIR")
	}
	return home, files, true
}

func (a *Adapter) discoverUser(c *collector) {
	home, files, ok := a.userPaths(c)
	if !ok {
		return
	}
	c.home = home
	settings, claudeJSON := files[0], files[1]
	raw, err := adapters.ReadLocal(settings[0], adapters.MaxConfigFileBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		c.warn(model.ScopeUser, settings[1], "cannot read: %v", err)
	default:
		newSrc(c, model.ScopeUser, settings[1], raw).settings(raw)
	}
	readClaudeJSON(c, home, claudeJSON[0], claudeJSON[1])
}

func defaultManagedDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		return `C:\Program Files\ClaudeCode`
	default:
		return "/etc/claude-code"
	}
}

func (a *Adapter) discoverManaged(c *collector) {
	a.noteLegacyManaged(c)
	dir := a.options.ManagedDir
	if dir == "" {
		dir = defaultManagedDir()
	}
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	logicalDir := filepath.ToSlash(dir)
	if err != nil || !info.IsDir() {
		c.warn(model.ScopeManaged, logicalDir, "managed settings directory is not readable")
		return
	}
	type managedFile struct {
		abs, logical string
		mcp          bool
	}
	files := []managedFile{
		{filepath.Join(dir, "managed-settings.json"), logicalDir + "/managed-settings.json", false},
		{filepath.Join(dir, "managed-mcp.json"), logicalDir + "/managed-mcp.json", true},
	}
	dropIns := filepath.Join(dir, "managed-settings.d")
	entries, err := os.ReadDir(dropIns)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		c.warn(model.ScopeManaged, logicalDir+"/managed-settings.d", "cannot list directory")
	default:
		count := 0
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			if count == maxManagedDropIns {
				c.warn(model.ScopeManaged, logicalDir+"/managed-settings.d", "more than %d drop-in files; the rest were not scanned", maxManagedDropIns)
				break
			}
			count++
			files = append(files, managedFile{filepath.Join(dropIns, entry.Name()), logicalDir + "/managed-settings.d/" + entry.Name(), false})
		}
	}
	for _, f := range files {
		raw, err := adapters.ReadLocal(f.abs, adapters.MaxConfigFileBytes)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			c.warn(model.ScopeManaged, f.logical, "cannot read: %v", err)
			continue
		}
		s := newSrc(c, model.ScopeManaged, f.logical, raw)
		if f.mcp {
			s.mcpFile(raw)
		} else {
			s.settings(raw)
		}
	}
}

// noteLegacyManaged reports the retired ProgramData directory when it
// exists. The note is informational: the directory is not read, and the
// scan's exit code does not change because of it.
func (a *Adapter) legacyDir() string {
	if a.options.LegacyDir != "" {
		return a.options.LegacyDir
	}
	return legacyManagedDir
}

func (a *Adapter) noteLegacyManaged(c *collector) {
	info, err := os.Stat(a.legacyDir())
	if err != nil || !info.IsDir() {
		return
	}
	c.note(model.ScopeManaged, "C:/ProgramData/ClaudeCode", true, "legacy managed settings directory exists and is not scanned; Claude Code reads C:/Program Files/ClaudeCode")
}
