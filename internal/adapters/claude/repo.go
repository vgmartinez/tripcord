package claude

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
)

// Limits bounds repository discovery. A hostile repository must not be able
// to make a scan read unbounded data; exceeding a limit is reported as a
// truncation diagnostic, never silently.
type Limits struct {
	MaxDepth   int   // directory depth below the repository root
	MaxEntries int   // directory entries visited
	MaxFiles   int   // configuration files read
	MaxBytes   int64 // total bytes read across configuration files
	MaxFile    int64 // bytes per configuration file
}

// DefaultLimits are the scan defaults.
func DefaultLimits() Limits {
	return Limits{MaxDepth: 32, MaxEntries: 200_000, MaxFiles: 2_000, MaxBytes: 64 << 20, MaxFile: adapters.MaxConfigFileBytes}
}

type fileRole int

const (
	roleNone fileRole = iota
	roleSettings
	roleMCP
	roleInstructions
	roleRule
	roleAgent
	roleCommand
	roleSkill
	roleMarketplace
	rolePluginManifest
	rolePluginHooks
)

// skillRoots are the directories whose */SKILL.md files are skills.
// skillRoots are Claude Code's own skill directories. .agents/skills and
// .github/skills are read by the generic adapter so their harness stays
// generic when another product scans the same files.
var skillRoots = [][]string{{".claude", "skills"}}

// candidateName reports whether a walk should remember rel at all. It is a
// cheap superset of the files classify can accept.
func candidateName(rel string) bool {
	segments := strings.Split(rel, "/")
	base := strings.ToLower(segments[len(segments)-1])
	switch base {
	case "claude.md", "claude.local.md", ".mcp.json", "skill.md", "hooks.json", "marketplace.json", "plugin.json", "settings.json", "settings.local.json":
		return true
	}
	return strings.HasSuffix(base, ".md") && (hasSegment(segments, "rules") || hasSegment(segments, "agents") || hasSegment(segments, "commands"))
}

// classify returns how Claude Code reads rel. pluginRoots are the
// repository-relative plugin directories ("" for the root).
func classify(rel string, pluginRoots map[string]bool) fileRole {
	segments := strings.Split(rel, "/")
	n := len(segments)
	base := strings.ToLower(segments[n-1])
	parent := ""
	if n >= 2 {
		parent = strings.ToLower(segments[n-2])
	}
	switch {
	case base == "claude.md" || base == "claude.local.md":
		return roleInstructions
	case parent == ".claude" && (base == "settings.json" || base == "settings.local.json"):
		return roleSettings
	case base == ".mcp.json":
		return roleMCP
	case parent == ".claude-plugin" && base == "marketplace.json":
		return roleMarketplace
	case parent == ".claude-plugin" && base == "plugin.json":
		return rolePluginManifest
	}
	if base == "skill.md" {
		for _, root := range skillRoots {
			if containsSequence(segments[:n-1], root) {
				return roleSkill
			}
		}
	}
	if strings.HasSuffix(base, ".md") {
		switch {
		case containsSequence(segments[:n-1], []string{".claude", "rules"}):
			return roleRule
		case containsSequence(segments[:n-1], []string{".claude", "agents"}):
			return roleAgent
		case containsSequence(segments[:n-1], []string{".claude", "commands"}):
			return roleCommand
		}
	}
	for root := range pluginRoots {
		prefix := root
		if prefix != "" {
			prefix += "/"
		}
		rest, ok := strings.CutPrefix(rel, prefix)
		if !ok {
			continue
		}
		switch {
		case rest == "hooks/hooks.json":
			return rolePluginHooks
		case strings.HasPrefix(rest, "skills/") && base == "SKILL.md":
			return roleSkill
		case strings.HasPrefix(rest, "agents/") && strings.HasSuffix(base, ".md"):
			return roleAgent
		case strings.HasPrefix(rest, "commands/") && strings.HasSuffix(base, ".md"):
			return roleCommand
		}
	}
	return roleNone
}

// configSegments mark directories where an escaping symlink would hide
// configuration Claude Code loads.
var configSegments = map[string]bool{".claude": true, ".claude-plugin": true, "skills": true, "agents": true, "commands": true, "hooks": true, "rules": true}

func configRelevant(rel string) bool {
	if candidateName(rel) {
		return true
	}
	for _, segment := range strings.Split(rel, "/") {
		if configSegments[segment] {
			return true
		}
	}
	return false
}

type repoWalk struct {
	ctx       context.Context
	reader    *adapters.SafeReader
	limits    Limits
	c         *collector
	files     []string
	entries   int
	truncated map[string]bool
}

func (w *repoWalk) truncate(reason string) {
	if w.truncated[reason] {
		return
	}
	w.truncated[reason] = true
	w.c.warn(model.ScopeRepo, "", "repository walk truncated: %s; configuration beyond the limit was not scanned", reason)
}

// walk lists dir ("." for the root). ancestors holds the directories on the
// current path so a symlink cycle is not followed.
func (w *repoWalk) walk(dir string, depth int, ancestors []fs.FileInfo) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	budget := w.limits.MaxEntries - w.entries
	if budget <= 0 {
		w.truncate("too many directory entries")
		return nil
	}
	entries, truncated, err := w.reader.ReadDir(dir, budget)
	if err != nil {
		rel := dir
		if rel == "." {
			rel = ""
		}
		w.c.warn(model.ScopeRepo, rel, "cannot list directory: %v", err)
		return nil
	}
	w.entries += len(entries)
	if truncated {
		w.truncate("too many directory entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		rel := name
		if dir != "." {
			rel = dir + "/" + name
		}
		mode := entry.Type()
		if mode&fs.ModeSymlink != 0 {
			info, err := w.reader.Stat(rel)
			if err != nil {
				if configRelevant(rel) {
					if errors.Is(err, adapters.ErrUnsafePath) {
						w.c.warn(model.ScopeRepo, rel, "symlink resolves outside the repository; Claude Code may load its target, which was not scanned")
					} else if !errors.Is(err, fs.ErrNotExist) {
						w.c.warn(model.ScopeRepo, rel, "cannot resolve symlink: %v", err)
					}
				}
				continue
			}
			mode = info.Mode().Type()
			if info.IsDir() {
				if err := w.descend(rel, name, depth, ancestors, info); err != nil {
					return err
				}
				continue
			}
		} else if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				w.c.warn(model.ScopeRepo, rel, "cannot inspect directory: %v", err)
				continue
			}
			if err := w.descend(rel, name, depth, ancestors, info); err != nil {
				return err
			}
			continue
		}
		if !candidateName(rel) {
			continue
		}
		if !mode.IsRegular() {
			w.c.warn(model.ScopeRepo, rel, "not a regular file; not read")
			continue
		}
		w.files = append(w.files, rel)
	}
	return nil
}

func (w *repoWalk) descend(rel, name string, depth int, ancestors []fs.FileInfo, info fs.FileInfo) error {
	if name == ".git" {
		return nil
	}
	for _, ancestor := range ancestors {
		if os.SameFile(ancestor, info) {
			return nil
		}
	}
	if depth+1 > w.limits.MaxDepth {
		w.truncate("directory nesting too deep")
		return nil
	}
	return w.walk(rel, depth+1, append(ancestors, info))
}

func (a *Adapter) listRepo(ctx context.Context, reader *adapters.SafeReader, c *collector) ([]string, error) {
	w := &repoWalk{ctx: ctx, reader: reader, limits: a.limits, c: c, truncated: map[string]bool{}}
	rootInfo, err := reader.Stat(".")
	if err != nil {
		return nil, err
	}
	if err := w.walk(".", 0, []fs.FileInfo{rootInfo}); err != nil {
		return nil, err
	}
	return w.files, nil
}

type repoRead struct {
	reader *adapters.SafeReader
	limits Limits
	c      *collector
	files  int
	bytes  int64
	done   map[string]bool

	warnedFiles bool
	warnedBytes bool
}

func (r *repoRead) read(rel string) ([]byte, bool) {
	if r.done[rel] {
		return nil, false
	}
	r.done[rel] = true
	if r.files >= r.limits.MaxFiles {
		if !r.warnedFiles {
			r.warnedFiles = true
			r.c.warn(model.ScopeRepo, "", "repository walk truncated: more than %d configuration files; the rest were not scanned", r.limits.MaxFiles)
		}
		return nil, false
	}
	r.files++
	limit := r.limits.MaxFile
	if remaining := r.limits.MaxBytes - r.bytes; remaining < limit {
		limit = remaining
	}
	raw, err := r.reader.ReadFile(rel, limit)
	if err != nil {
		if errors.Is(err, adapters.ErrFileTooBig) && limit < r.limits.MaxFile {
			if !r.warnedBytes {
				r.warnedBytes = true
				r.c.warn(model.ScopeRepo, "", "repository walk truncated: total configuration bytes exceed %d; the rest were not scanned", r.limits.MaxBytes)
			}
		} else {
			r.c.warn(model.ScopeRepo, rel, "cannot read: %v", err)
		}
		return nil, false
	}
	r.bytes += int64(len(raw))
	return raw, true
}

func (a *Adapter) discoverRepo(ctx context.Context, repoRoot string, c *collector) error {
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		c.warn(model.ScopeRepo, "", "cannot open repository: %v", err)
		return nil
	}
	defer func() { _ = reader.Close() }()
	files, err := a.listRepo(ctx, reader, c)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.warn(model.ScopeRepo, "", "cannot list repository: %v", err)
		return nil
	}
	r := &repoRead{reader: reader, limits: a.limits, c: c, done: map[string]bool{}}
	pluginRoots := map[string]bool{}
	for _, rel := range files {
		switch classify(rel, nil) {
		case rolePluginManifest:
			pluginRoots[pluginRootOf(rel)] = true
		case roleMarketplace:
			raw, ok := r.read(rel)
			if !ok {
				continue
			}
			s := newSrc(c, model.ScopeRepo, rel, raw)
			for _, root := range s.marketplace(raw, pluginRootOf(rel)) {
				pluginRoots[root] = true
			}
		}
	}
	for _, rel := range files {
		role := classify(rel, pluginRoots)
		if role == roleNone || role == roleMarketplace {
			continue
		}
		raw, ok := r.read(rel)
		if !ok {
			continue
		}
		s := newSrc(c, model.ScopeRepo, rel, raw)
		switch role {
		case roleSettings:
			s.settings(raw)
		case roleMCP:
			s.mcpFile(raw)
		case roleInstructions:
			s.markdown(model.ConfigKindInstructions, "instructions", raw)
		case roleRule:
			s.markdown(model.ConfigKindInstructions, "rule", raw)
		case roleAgent:
			s.markdown(model.ConfigKindInstructions, "agent", raw)
		case roleCommand:
			s.markdown(model.ConfigKindInstructions, "command", raw)
		case roleSkill:
			s.markdown(model.ConfigKindSkill, "skill", raw)
		case rolePluginHooks:
			s.pluginHooks(raw)
		case rolePluginManifest:
			for _, ref := range s.pluginManifest(raw) {
				r.readRef(ref)
			}
		case roleNone, roleMarketplace:
		}
	}
	return nil
}

// fileRef is a hooks or MCP file named by a plugin manifest.
type fileRef struct {
	rel  string
	role fileRole
}

func (r *repoRead) readRef(ref fileRef) {
	if r.done[ref.rel] {
		return
	}
	raw, ok := r.read(ref.rel)
	if !ok {
		return
	}
	s := newSrc(r.c, model.ScopeRepo, ref.rel, raw)
	switch ref.role {
	case rolePluginHooks:
		s.pluginHooks(raw)
	case roleMCP:
		s.mcpFile(raw)
	}
}

// pluginRootOf returns the plugin directory for ".../.claude-plugin/x.json".
func pluginRootOf(rel string) string {
	dir := path.Dir(path.Dir(rel))
	if dir == "." {
		return ""
	}
	return dir
}

// marketplace emits one plugin item per entry and returns the repository
// plugin directories its relative sources name.
func (s *src) marketplace(raw []byte, base string) []string {
	tree, warnings, err := decodeJSON(raw)
	s.warnAll(warnings)
	if err != nil {
		s.warn("invalid JSON: %v", err)
		return nil
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		s.warn("marketplace must be a JSON object")
		return nil
	}
	pluginBase := base
	if meta, ok := obj["metadata"].(map[string]any); ok {
		if root, ok := meta["pluginRoot"].(string); ok && root != "" {
			joined, ok := s.joinRef(base, root)
			if !ok {
				return nil
			}
			pluginBase = joined
		}
	}
	plugins, ok := obj["plugins"].([]any)
	if !ok {
		if _, present := obj["plugins"]; present {
			s.warn("marketplace plugins must be an array")
		}
		return nil
	}
	var roots []string
	for _, p := range plugins {
		entry, ok := p.(map[string]any)
		if !ok {
			s.warn("marketplace plugin entry must be an object")
			continue
		}
		name, _ := entry["name"].(string)
		sanitizedEntry, removed := s.safePayloadValue("marketplace", entry)
		payload := map[string]any{"setting": "marketplace", "value": sanitizedEntry}
		if source, ok := entry["source"].(string); ok {
			if root, ok := s.joinRef(pluginBase, source); ok {
				roots = append(roots, root)
				payload["plugin_root"] = root
			}
		}
		s.add(model.ConfigKindPlugin, withDiscriminator([]string{"plugin", name}, removed), payload)
		if hooks, ok := entry["hooks"].(map[string]any); ok {
			s.hooks(hooks)
		}
		if servers, ok := entry["mcpServers"].(map[string]any); ok {
			s.mcpServers(servers, "")
		}
	}
	return roots
}

// pluginManifest emits the plugin item and its inline hooks and MCP
// servers, and returns the hooks and MCP files it references by path.
func (s *src) pluginManifest(raw []byte) []fileRef {
	tree, warnings, err := decodeJSON(raw)
	s.warnAll(warnings)
	if err != nil {
		s.warn("invalid JSON: %v", err)
		return nil
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		s.warn("plugin manifest must be a JSON object")
		return nil
	}
	root := pluginRootOf(s.path)
	name, _ := obj["name"].(string)
	sanitizedObj, removed := s.safePayloadValue("plugin", obj)
	s.add(model.ConfigKindPlugin, withDiscriminator([]string{"plugin", name}, removed), map[string]any{"setting": "plugin", "value": sanitizedObj, "plugin_root": root})
	var refs []fileRef
	collect := func(value any, role fileRole, inline func(any)) {
		switch v := value.(type) {
		case nil:
		case string:
			if rel, ok := s.joinRef(root, v); ok {
				refs = append(refs, fileRef{rel: rel, role: role})
			}
		case []any:
			for _, item := range v {
				if ref, ok := item.(string); ok {
					if rel, ok := s.joinRef(root, ref); ok {
						refs = append(refs, fileRef{rel: rel, role: role})
					}
				} else {
					inline(item)
				}
			}
		default:
			inline(v)
		}
	}
	collect(obj["hooks"], rolePluginHooks, s.hooks)
	collect(obj["mcpServers"], roleMCP, func(v any) { s.mcpServers(v, "") })
	return refs
}

// pluginHooks normalizes hooks/hooks.json: {"hooks": {...}}.
func (s *src) pluginHooks(raw []byte) {
	tree, warnings, err := decodeJSON(raw)
	s.warnAll(warnings)
	if err != nil {
		s.warn("invalid JSON: %v", err)
		return
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		s.warn("plugin hooks.json is not a JSON object")
		return
	}
	hooks, ok := obj["hooks"]
	if !ok {
		s.warn("plugin hooks.json has no hooks object")
		return
	}
	if _, ok := hooks.(map[string]any); !ok {
		s.warn("plugin hooks.json hooks member is not an object")
		return
	}
	s.hooks(hooks)
}

// joinRef resolves a path a manifest names relative to base. Absolute and
// escaping references are reported, never followed.
func (s *src) joinRef(base, ref string) (string, bool) {
	if strings.Contains(ref, "://") {
		return "", false
	}
	ref = strings.ReplaceAll(ref, `\`, "/")
	if path.IsAbs(ref) || hasDriveLetter(ref) {
		s.warn("references absolute path %q; not scanned", ref)
		return "", false
	}
	for _, segment := range strings.Split(ref, "/") {
		if segment == ".." {
			s.warn("references %q outside its plugin directory; not scanned", ref)
			return "", false
		}
	}
	joined := path.Join(base, ref)
	if joined == "." {
		return "", true
	}
	return joined, true
}

func hasDriveLetter(p string) bool {
	return len(p) >= 2 && p[1] == ':' && (p[0]|0x20) >= 'a' && (p[0]|0x20) <= 'z'
}

func hasSegment(segments []string, want string) bool {
	for _, s := range segments {
		if s == want {
			return true
		}
	}
	return false
}

func containsSequence(segments, want []string) bool {
	for i := 0; i+len(want) <= len(segments); i++ {
		match := true
		for j := range want {
			if !strings.EqualFold(segments[i+j], want[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
