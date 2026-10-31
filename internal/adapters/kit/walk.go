package kit

import (
	"context"
	"errors"
	"io/fs"
	"os"
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
	w := &walker{ctx: ctx, reader: reader, limits: limits, c: c, m: m, truncated: map[string]bool{}}
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
	ctx       context.Context
	reader    *adapters.SafeReader
	limits    Limits
	c         *Collector
	m         Matcher
	files     []string
	entries   int
	truncated map[string]bool
}

func (w *walker) truncate(reason string) {
	if w.truncated[reason] {
		return
	}
	w.truncated[reason] = true
	w.c.Warn(model.ScopeRepo, "", "repository walk truncated: %s; configuration beyond the limit was not scanned", reason)
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
		w.c.Warn(model.ScopeRepo, rel, "cannot list directory: %v", err)
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
						w.c.Warn(model.ScopeRepo, rel, "symlink resolves outside the repository; %s may load its target, which was not scanned", w.c.product)
					} else if !errors.Is(err, fs.ErrNotExist) {
						w.c.Warn(model.ScopeRepo, rel, "cannot resolve symlink: %v", err)
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
				w.c.Warn(model.ScopeRepo, rel, "cannot inspect directory: %v", err)
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
			w.c.Warn(model.ScopeRepo, rel, "not a regular file; not read")
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
	reader *adapters.SafeReader
	limits Limits
	c      *Collector
	files  int
	bytes  int64
	done   map[string]bool

	warnedFiles bool
	warnedBytes bool
}

// NewRepoReader returns a budgeted reader over reader.
func NewRepoReader(reader *adapters.SafeReader, limits Limits, c *Collector) *RepoReader {
	return &RepoReader{reader: reader, limits: limits, c: c, done: map[string]bool{}}
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
			r.c.Warn(model.ScopeRepo, "", "repository walk truncated: more than %d configuration files; the rest were not scanned", r.limits.MaxFiles)
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
				r.c.Warn(model.ScopeRepo, "", "repository walk truncated: total configuration bytes exceed %d; the rest were not scanned", r.limits.MaxBytes)
			}
		} else {
			r.c.Warn(model.ScopeRepo, rel, "cannot read: %v", err)
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

// HasSegment reports whether segments contains want.
func HasSegment(segments []string, want string) bool {
	for _, s := range segments {
		if s == want {
			return true
		}
	}
	return false
}
