package kit

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

// Limits bounds repository discovery. A hostile repository must not be
// able to make a scan read unbounded data; exceeding a limit is reported
// as a truncation diagnostic, never silently, and each limit is reported
// once.
type Limits struct {
	MaxDepth   int   // directory depth below the repository root
	MaxEntries int   // directory entries visited
	MaxFiles   int   // configuration files read
	MaxBytes   int64 // total bytes read across configuration files
	MaxFile    int64 // bytes per configuration file
}

// DefaultLimits are the scan defaults, shared with the Claude adapter.
func DefaultLimits() Limits {
	return Limits{MaxDepth: 32, MaxEntries: 200_000, MaxFiles: 2_000, MaxBytes: 64 << 20, MaxFile: adapters.MaxConfigFileBytes}
}

// Matcher decides which repository paths a walk keeps.
type Matcher struct {
	// Candidate reports whether rel (slash-separated, repo-relative) is a
	// file the harness may load. Classification must be case-insensitive:
	// macOS and Windows resolve ".Cursor/Hooks.json" to the same file.
	Candidate func(rel string) bool
	// Relevant reports whether an unreadable or escaping symlink at rel
	// could hide configuration, so it is worth a diagnostic.
	Relevant func(rel string) bool
}

// Walk lists every regular file below the repository root that m accepts,
// in sorted order. Symlinks are followed only within the root (SafeReader
// enforces it); an escaping symlink at a relevant path is reported. .git
// is skipped and symlink cycles are cut.
func Walk(ctx context.Context, reader *adapters.SafeReader, limits Limits, c *Collector, m Matcher) ([]string, error) {
	return WalkScoped(ctx, reader, limits, c, model.ScopeRepo, "", m)
}

// WalkScoped is Walk for a root that need not be a repository: every
// diagnostic is tagged scope instead of always ScopeRepo, named "the
// repository" only when scope is ScopeRepo (otherwise "this directory"),
// and reported under pathPrefix joined to the file's path below root
// (pathPrefix itself for the root), instead of a bare repo-relative path.
// A user-scope skill directory (~/.agents/skills) is the first caller
// that is not a repository root; Walk is WalkScoped with the original
// repository behavior (scope ScopeRepo, no prefix) unchanged.
func WalkScoped(ctx context.Context, reader *adapters.SafeReader, limits Limits, c *Collector, scope model.Scope, pathPrefix string, m Matcher) ([]string, error) {
	w := &walker{ctx: ctx, reader: reader, limits: limits, c: c, m: m, scope: scope, pathPrefix: pathPrefix, truncated: map[string]bool{}}
	rootInfo, err := reader.Stat(".")
	if err != nil {
		return nil, err
	}
	if err := w.walk(".", 0, []fs.FileInfo{rootInfo}); err != nil {
		return nil, err
	}
	return w.files, nil
}

type walker struct {
	ctx        context.Context
	reader     *adapters.SafeReader
	limits     Limits
	c          *Collector
	m          Matcher
	scope      model.Scope
	pathPrefix string
	files      []string
	entries    int
	truncated  map[string]bool
}

// path joins rel (relative to the walked root, "" for the root itself) to
// pathPrefix, for a diagnostic or an item under a non-repository root.
func (w *walker) path(rel string) string {
	switch {
	case w.pathPrefix == "":
		return rel
	case rel == "":
		return w.pathPrefix
	default:
		return w.pathPrefix + "/" + rel
	}
}

// rootNoun names the walked root in a diagnostic: the existing wording
// for a repository, a generic one for anything else (a user-scope skill
// directory, say), since pathPrefix already names that root precisely.
func (w *walker) rootNoun() string {
	if w.scope == model.ScopeRepo {
		return "repository"
	}
	return "directory"
}

func (w *walker) truncate(reason string) {
	if w.truncated[reason] {
		return
	}
	w.truncated[reason] = true
	w.c.Warn(w.scope, w.path(""), "%s walk truncated: %s; configuration beyond the limit was not scanned", w.rootNoun(), reason)
}

func (w *walker) walk(dir string, depth int, ancestors []fs.FileInfo) error {
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
		w.c.Warn(w.scope, w.path(rel), "cannot list directory: %v", err)
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
				if w.m.Candidate(rel) || w.m.Relevant(rel) {
					if errors.Is(err, adapters.ErrUnsafePath) {
						w.c.Warn(w.scope, w.path(rel), "symlink resolves outside the %s; %s may load its target, which was not scanned", w.rootNoun(), w.c.product)
					} else if !errors.Is(err, fs.ErrNotExist) {
						w.c.Warn(w.scope, w.path(rel), "cannot resolve symlink: %v", err)
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
				w.c.Warn(w.scope, w.path(rel), "cannot inspect directory: %v", err)
				continue
			}
			if err := w.descend(rel, name, depth, ancestors, info); err != nil {
				return err
			}
			continue
		}
		if !w.m.Candidate(rel) {
			continue
		}
		if !mode.IsRegular() {
			w.c.Warn(w.scope, w.path(rel), "not a regular file; not read")
			continue
		}
		w.files = append(w.files, rel)
	}
	return nil
}

func (w *walker) descend(rel, name string, depth int, ancestors []fs.FileInfo, info fs.FileInfo) error {
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

// RepoReader reads repository files under the per-file, file-count, and
// total-byte budgets. Each budget is reported once.
type RepoReader struct {
	reader     *adapters.SafeReader
	limits     Limits
	c          *Collector
	scope      model.Scope
	pathPrefix string
	files      int
	bytes      int64
	done       map[string]bool

	warnedFiles bool
	warnedBytes bool
}

// NewRepoReader returns a budgeted reader over reader.
func NewRepoReader(reader *adapters.SafeReader, limits Limits, c *Collector) *RepoReader {
	return NewScopedReader(reader, limits, c, model.ScopeRepo, "")
}

// NewScopedReader is NewRepoReader for a root that need not be a
// repository: see WalkScoped for scope and pathPrefix.
func NewScopedReader(reader *adapters.SafeReader, limits Limits, c *Collector, scope model.Scope, pathPrefix string) *RepoReader {
	return &RepoReader{reader: reader, limits: limits, c: c, scope: scope, pathPrefix: pathPrefix, done: map[string]bool{}}
}

func (r *RepoReader) path(rel string) string {
	switch {
	case r.pathPrefix == "":
		return rel
	case rel == "":
		return r.pathPrefix
	default:
		return r.pathPrefix + "/" + rel
	}
}

func (r *RepoReader) rootNoun() string {
	if r.scope == model.ScopeRepo {
		return "repository"
	}
	return "directory"
}

// Read returns rel's content, or false after recording a diagnostic. A
// path is read at most once.
func (r *RepoReader) Read(rel string) ([]byte, bool) {
	if r.done[rel] {
		return nil, false
	}
	r.done[rel] = true
	if r.files >= r.limits.MaxFiles {
		if !r.warnedFiles {
			r.warnedFiles = true
			r.c.Warn(r.scope, r.path(""), "%s walk truncated: more than %d configuration files; the rest were not scanned", r.rootNoun(), r.limits.MaxFiles)
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
				r.c.Warn(r.scope, r.path(""), "%s walk truncated: total configuration bytes exceed %d; the rest were not scanned", r.rootNoun(), r.limits.MaxBytes)
			}
		} else {
			r.c.Warn(r.scope, r.path(rel), "cannot read: %v", err)
		}
		return nil, false
	}
	r.bytes += int64(len(raw))
	return raw, true
}

// Segments splits rel and lower-cases every segment, for case-insensitive
// classification.
func Segments(rel string) []string {
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		parts[i] = strings.ToLower(p)
	}
	return parts
}

// HasSequence reports whether segments contains want as consecutive
// elements. Both must already be lower-case.
func HasSequence(segments, want []string) bool {
	for i := 0; i+len(want) <= len(segments); i++ {
		match := true
		for j := range want {
			if segments[i+j] != want[j] {
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

// SkillFileMatcher is a Matcher for walking a skill directory itself
// (~/.agents/skills, ~/.codex/skills): every SKILL.md below the root is a
// skill, and every path below it is worth a symlink diagnostic, since
// there is no larger, less relevant tree around it to filter out.
var SkillFileMatcher = Matcher{
	Candidate: func(rel string) bool { return path.Base(rel) == "SKILL.md" },
	Relevant:  func(string) bool { return true },
}

// HasSegment reports whether segments contains want.
func HasSegment(segments []string, want string) bool {
	for _, s := range segments {
		if s == want {
			return true
		}
	}
	return false
}
