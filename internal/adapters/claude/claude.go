// Package claude discovers Claude Code configuration without executing it.
package claude

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
	"go.yaml.in/yaml/v3"
)

const maxFileBytes = 1 << 20

// Options controls non-repository discovery. Repository discovery is always
// enabled. The CLI intentionally constructs Adapter with the zero value so
// scanning a repository never reads a developer's home directory or system
// configuration implicitly.
type Options struct {
	HomeDir        string
	ManagedPaths   []string
	IncludeUser    bool
	IncludeManaged bool
}

// Adapter discovers Claude Code config.
type Adapter struct {
	options Options
}

// New returns a Claude Code adapter. A zero Options value discovers only
// repository-scoped configuration.
func New(options Options) *Adapter {
	return &Adapter{options: options}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessClaude }

// Detect reports whether any repository-scoped Claude Code input exists.
func (*Adapter) Detect(repoRoot string) bool {
	for _, path := range repoPaths {
		if regularRepoFile(repoRoot, filepath.Join(repoRoot, filepath.FromSlash(path))) {
			return true
		}
	}
	return hasClaudeTreeInput(repoRoot)
}

// Discover reads supported config files. It never evaluates hooks, starts
// MCP servers, expands variables, or follows symlinks.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var items []model.ConfigItem
	for _, path := range repoPaths {
		found, err := a.parseFile(repoRoot, model.ScopeRepo, path, filepath.Join(repoRoot, filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		items = append(items, found...)
	}
	treeItems, err := a.discoverClaudeTree(ctx, repoRoot)
	if err != nil {
		return nil, err
	}
	items = append(items, treeItems...)
	if a.options.IncludeUser {
		userItems, err := a.discoverUser(ctx)
		if err != nil {
			return nil, err
		}
		items = append(items, userItems...)
	}
	if a.options.IncludeManaged {
		managedItems, err := a.discoverManaged(ctx)
		if err != nil {
			return nil, err
		}
		items = append(items, managedItems...)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Scope != items[j].Scope {
			return items[i].Scope < items[j].Scope
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return string(items[i].Payload) < string(items[j].Payload)
	})
	return items, nil
}

var repoPaths = []string{
	".claude/settings.json",
	".claude/settings.local.json",
	".mcp.json",
	"CLAUDE.md",
}

func hasClaudeTreeInput(repoRoot string) bool {
	for _, root := range []string{".claude/rules", ".claude/skills", ".claude/plugins"} {
		if info, err := os.Lstat(filepath.Join(repoRoot, filepath.FromSlash(root))); err == nil && !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return true
		}
	}
	return false
}

func regularRepoFile(repoRoot, path string) bool {
	if !containedBy(repoRoot, path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func containedBy(root, path string) bool {
	cleanRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	cleanPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func (a *Adapter) discoverClaudeTree(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	var items []model.ConfigItem
	for _, root := range []string{".claude/rules", ".claude/skills", ".claude/plugins"} {
		absolute := filepath.Join(repoRoot, filepath.FromSlash(root))
		info, err := os.Lstat(absolute)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("claude: inspect %s: %w", root, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			switch {
			case strings.HasPrefix(relative, ".claude/rules/") && strings.HasSuffix(relative, ".md"):
				found, err := a.parseFile(repoRoot, model.ScopeRepo, relative, path)
				if err != nil {
					return err
				}
				items = append(items, found...)
			case strings.HasPrefix(relative, ".claude/skills/") && strings.HasSuffix(relative, "/SKILL.md"):
				found, err := a.parseFile(repoRoot, model.ScopeRepo, relative, path)
				if err != nil {
					return err
				}
				items = append(items, found...)
			case strings.HasPrefix(relative, ".claude/plugins/") && strings.HasSuffix(relative, "/hooks/hooks.json"):
				found, err := a.parseFile(repoRoot, model.ScopeRepo, relative, path)
				if err != nil {
					return err
				}
				items = append(items, found...)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("claude: walk %s: %w", root, err)
		}
	}
	return items, nil
}

func (a *Adapter) discoverUser(ctx context.Context) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	home := a.options.HomeDir
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("claude: user home: %w", err)
		}
	}
	var items []model.ConfigItem
	for _, path := range []string{"~/.claude/settings.json", "~/.claude.json"} {
		absolute := filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(path, "~/")))
		found, err := a.parseFile("", model.ScopeUser, path, absolute)
		if err != nil {
			return nil, err
		}
		items = append(items, found...)
	}
	return items, nil
}

func (a *Adapter) discoverManaged(ctx context.Context) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	paths := a.options.ManagedPaths
	if len(paths) == 0 {
		paths = defaultManagedPaths()
	}
	var items []model.ConfigItem
	for _, path := range paths {
		found, err := a.parseFile("", model.ScopeManaged, filepath.ToSlash(path), path)
		if err != nil {
			return nil, err
		}
		items = append(items, found...)
	}
	return items, nil
}

func defaultManagedPaths() []string {
	switch {
	case runtime.GOOS == "darwin":
		return []string{"/Library/Application Support/ClaudeCode/managed-settings.json"}
	case runtime.GOOS == "windows":
		return []string{"C:/ProgramData/ClaudeCode/managed-settings.json"}
	default:
		return []string{"/etc/claude-code/managed-settings.json"}
	}
}

func (a *Adapter) parseFile(repoRoot string, scope model.Scope, logicalPath, path string) ([]model.ConfigItem, error) {
	if scope == model.ScopeRepo && !containedBy(repoRoot, path) {
		return nil, nil
	}
	raw, found, err := readFile(path)
	if err != nil || !found {
		return nil, err
	}
	sha := digest(raw)
	switch {
	case logicalPath == "CLAUDE.md" || strings.HasPrefix(logicalPath, ".claude/rules/"):
		return []model.ConfigItem{item(scope, logicalPath, sha, model.ConfigKindInstructions, map[string]any{"content": string(raw)})}, nil
	case strings.HasPrefix(logicalPath, ".claude/skills/") && strings.HasSuffix(logicalPath, "/SKILL.md"):
		return parseSkill(scope, logicalPath, sha, raw)
	case strings.HasPrefix(logicalPath, ".claude/plugins/") && strings.HasSuffix(logicalPath, "/hooks/hooks.json"):
		return parsePluginHooks(scope, logicalPath, sha, raw)
	case logicalPath == ".mcp.json" || logicalPath == "~/.claude.json":
		return parseMCP(scope, logicalPath, sha, raw)
	default:
		return parseSettings(scope, logicalPath, sha, raw)
	}
}

func readFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("claude: inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, nil
	}
	if info.Size() > maxFileBytes {
		return nil, false, fmt.Errorf("claude: %s exceeds %d byte limit", path, maxFileBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("claude: open %s: %w", path, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("claude: read %s: %w", path, err)
	}
	if len(raw) > maxFileBytes {
		return nil, false, fmt.Errorf("claude: %s exceeds %d byte limit", path, maxFileBytes)
	}
	return raw, true, nil
}

func parseSettings(scope model.Scope, path, sha string, raw []byte) ([]model.ConfigItem, error) {
	var settings map[string]json.RawMessage
	if err := decodeObject(raw, &settings); err != nil {
		return nil, fmt.Errorf("claude: parse %s: %w", path, err)
	}
	if settings == nil {
		return nil, fmt.Errorf("claude: parse %s: settings must be a JSON object", path)
	}
	var items []model.ConfigItem
	if hooks, ok := settings["hooks"]; ok {
		found, err := parseHooks(scope, path, sha, hooks)
		if err != nil {
			return nil, fmt.Errorf("claude: parse %s hooks: %w", path, err)
		}
		items = append(items, found...)
	}
	if mcp, ok := settings["mcpServers"]; ok {
		found, err := parseMCPValue(scope, path, sha, mcp)
		if err != nil {
			return nil, fmt.Errorf("claude: parse %s mcpServers: %w", path, err)
		}
		items = append(items, found...)
	}
	if permissions, ok := settings["permissions"]; ok {
		items = append(items, rawItem(scope, path, sha, model.ConfigKindPermissions, permissions))
	}
	for _, name := range []string{"env", "apiKeyHelper"} {
		if value, ok := settings[name]; ok {
			items = append(items, item(scope, path, sha, model.ConfigKindEnvSetup, map[string]any{name: decodeAny(value)}))
		}
	}
	return items, nil
}

func parseMCP(scope model.Scope, path, sha string, raw []byte) ([]model.ConfigItem, error) {
	var document map[string]json.RawMessage
	if err := decodeObject(raw, &document); err != nil {
		return nil, fmt.Errorf("claude: parse %s: %w", path, err)
	}
	if document == nil {
		return nil, fmt.Errorf("claude: parse %s: MCP config must be a JSON object", path)
	}
	value := json.RawMessage(raw)
	if servers, ok := document["mcpServers"]; ok {
		value = servers
	} else {
		return nil, nil
	}
	return parseMCPValue(scope, path, sha, value)
}

func parseMCPValue(scope model.Scope, path, sha string, raw json.RawMessage) ([]model.ConfigItem, error) {
	var servers map[string]json.RawMessage
	if err := decodeObject(raw, &servers); err != nil {
		return nil, err
	}
	if servers == nil {
		return nil, errors.New("MCP servers must be a JSON object")
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]model.ConfigItem, 0, len(names))
	for _, name := range names {
		var server map[string]any
		if err := json.Unmarshal(servers[name], &server); err != nil {
			return nil, fmt.Errorf("server %q: %w", name, err)
		}
		if server == nil {
			return nil, fmt.Errorf("server %q must be a JSON object", name)
		}
		server["name"] = name
		items = append(items, item(scope, path, sha, model.ConfigKindMCPServer, server))
	}
	return items, nil
}

func parseHooks(scope model.Scope, path, sha string, raw json.RawMessage) ([]model.ConfigItem, error) {
	var events map[string]json.RawMessage
	if err := decodeObject(raw, &events); err != nil {
		return nil, err
	}
	if events == nil {
		return nil, errors.New("hooks must be a JSON object")
	}
	eventNames := make([]string, 0, len(events))
	for name := range events {
		eventNames = append(eventNames, name)
	}
	sort.Strings(eventNames)
	var items []model.ConfigItem
	for _, event := range eventNames {
		var groups []struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		}
		if err := json.Unmarshal(events[event], &groups); err != nil {
			return nil, fmt.Errorf("event %q: %w", event, err)
		}
		for _, group := range groups {
			for _, hook := range group.Hooks {
				items = append(items, item(scope, path, sha, model.ConfigKindHook, map[string]any{
					"event": event, "matcher": group.Matcher, "command": hook.Command,
				}))
			}
		}
	}
	return items, nil
}

func parseSkill(scope model.Scope, path, sha string, raw []byte) ([]model.ConfigItem, error) {
	content := string(raw)
	items := []model.ConfigItem{item(scope, path, sha, model.ConfigKindSkill, map[string]any{"content": content})}
	if !strings.HasPrefix(content, "---\n") {
		return items, nil
	}
	end := strings.Index(content[4:], "\n---")
	if end < 0 {
		return nil, errors.New("skill frontmatter is missing its closing delimiter")
	}
	var frontmatter map[string]any
	if err := yaml.Unmarshal([]byte(content[4:4+end]), &frontmatter); err != nil {
		return nil, fmt.Errorf("skill frontmatter: %w", err)
	}
	if hooks, ok := frontmatter["hooks"]; ok {
		rawHooks, err := json.Marshal(hooks)
		if err != nil {
			return nil, fmt.Errorf("skill hooks: %w", err)
		}
		found, err := parseHooks(scope, path, sha, rawHooks)
		if err != nil {
			return nil, fmt.Errorf("skill hooks: %w", err)
		}
		items = append(items, found...)
	}
	return items, nil
}

func parsePluginHooks(scope model.Scope, path, sha string, raw []byte) ([]model.ConfigItem, error) {
	var document map[string]json.RawMessage
	if err := decodeObject(raw, &document); err != nil {
		return nil, fmt.Errorf("claude: parse %s: %w", path, err)
	}
	if document == nil {
		return nil, fmt.Errorf("claude: parse %s: hooks must be a JSON object", path)
	}
	if hooks, ok := document["hooks"]; ok {
		return parseHooks(scope, path, sha, hooks)
	}
	return parseHooks(scope, path, sha, raw)
}

func decodeObject(raw []byte, into any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func decodeAny(raw json.RawMessage) any {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	return value
}

func item(scope model.Scope, path, sha string, kind model.ConfigKind, payload map[string]any) model.ConfigItem {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return model.ConfigItem{Harness: model.HarnessClaude, Scope: scope, Path: path, SHA256: sha, Kind: kind, Payload: raw}
}

func rawItem(scope model.Scope, path, sha string, kind model.ConfigKind, payload json.RawMessage) model.ConfigItem {
	return model.ConfigItem{Harness: model.HarnessClaude, Scope: scope, Path: path, SHA256: sha, Kind: kind, Payload: append(json.RawMessage(nil), payload...)}
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
