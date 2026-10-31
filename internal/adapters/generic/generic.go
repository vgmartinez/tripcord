// Package generic discovers skill files that more than one coding agent
// reads. Items use harness generic so a later Copilot adapter can scan the
// same paths without changing their fingerprints.
package generic

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/model"
)

// Limits bounds repository discovery. The numbers match the Claude adapter.
type Limits struct {
	MaxDepth   int
	MaxEntries int
	MaxFiles   int
	MaxBytes   int64
	MaxFile    int64
}

// DefaultLimits are the scan defaults.
func DefaultLimits() Limits {
	return Limits{MaxDepth: 32, MaxEntries: 200_000, MaxFiles: 2_000, MaxBytes: 64 << 20, MaxFile: adapters.MaxConfigFileBytes}
}

// Options controls discovery. The zero value scans the repository.
type Options struct {
	// SkipRepo omits the repository. User and managed scopes have no
	// shared skill files.
	SkipRepo bool
	Limits   *Limits
}

// Adapter discovers .agents/skills and .github/skills.
type Adapter struct {
	options Options
	limits  Limits
}

// New returns the shared skills adapter.
func New(options Options) *Adapter {
	limits := DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.SurfaceGeneric }

// Detect reports whether the repository has a shared skill file, or a
// skill path that cannot be read safely.
func (a *Adapter) Detect(repoRoot string) bool {
	if a.options.SkipRepo {
		return false
	}
	items, err := a.Discover(context.Background(), repoRoot)
	if len(items) > 0 {
		return true
	}
	var partial *adapters.DiagnosticError
	return errors.As(err, &partial) && len(partial.Diagnostics) > 0
}

// Discover reads SKILL.md files under .agents/skills and .github/skills
// at any depth. It never executes them.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.options.SkipRepo {
		return nil, nil
	}
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		return nil, &adapters.DiagnosticError{Diagnostics: []adapters.Diagnostic{{
			Harness: model.SurfaceGeneric,
			Scope:   model.ScopeRepo,
			Message: "cannot open repository: " + err.Error(),
		}}}
	}
	defer func() { _ = reader.Close() }()
	files, diags, err := walkSkills(ctx, reader, a.limits)
	if err != nil {
		return nil, err
	}
	var items []model.ConfigItem
	read := &skillRead{reader: reader, limits: a.limits}
	for _, rel := range files {
		raw, ok, diag := read.file(rel)
		if diag != nil {
			diags = append(diags, *diag)
		}
		if !ok {
			continue
		}
		parsed, problems := claude.NormalizeSkill(model.SurfaceGeneric, rel, raw)
		items = append(items, parsed...)
		diags = append(diags, problems...)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return string(items[i].Payload) < string(items[j].Payload)
	})
	if len(diags) > 0 {
		return items, &adapters.DiagnosticError{Diagnostics: diags}
	}
	return items, nil
}

// skillRoots are the shared skill directories. Claude's .claude/skills is
// not here.
var skillRoots = [][]string{{".agents", "skills"}, {".github", "skills"}}

func isSharedSkill(rel string) bool {
	if path.Base(rel) != "SKILL.md" {
		return false
	}
	segments := strings.Split(rel, "/")
	parent := segments[:len(segments)-1]
	for _, root := range skillRoots {
		if containsSequence(parent, root) {
			return true
		}
	}
	return false
}

func configRelevant(rel string) bool {
	if isSharedSkill(rel) {
		return true
	}
	for _, segment := range strings.Split(rel, "/") {
		switch segment {
		case ".agents", ".github", "skills":
			return true
		}
	}
	return false
}

func containsSequence(segments, want []string) bool {
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

type skillWalk struct {
	ctx       context.Context
	reader    *adapters.SafeReader
	limits    Limits
	files     []string
	diags     []adapters.Diagnostic
	entries   int
	truncated map[string]bool
}

func (w *skillWalk) warn(path, format string, args ...any) {
	w.diags = append(w.diags, adapters.Diagnostic{
		Harness: model.SurfaceGeneric,
		Scope:   model.ScopeRepo,
		Path:    path,
		Message: fmt.Sprintf(format, args...),
	})
}

func (w *skillWalk) truncate(reason string) {
	if w.truncated[reason] {
		return
	}
	w.truncated[reason] = true
	w.warn("", "repository walk truncated: %s; configuration beyond the limit was not scanned", reason)
}

func walkSkills(ctx context.Context, reader *adapters.SafeReader, limits Limits) ([]string, []adapters.Diagnostic, error) {
	w := &skillWalk{ctx: ctx, reader: reader, limits: limits, truncated: map[string]bool{}}
	rootInfo, err := reader.Stat(".")
	if err != nil {
		return nil, nil, err
	}
	if err := w.walk(".", 0, []fs.FileInfo{rootInfo}); err != nil {
		return nil, nil, err
	}
	return w.files, w.diags, nil
}

func (w *skillWalk) walk(dir string, depth int, ancestors []fs.FileInfo) error {
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
		w.warn(rel, "cannot list directory: %v", err)
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
						w.warn(rel, "symlink resolves outside the repository; its target was not scanned")
					} else if !errors.Is(err, fs.ErrNotExist) {
						w.warn(rel, "cannot resolve symlink: %v", err)
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
				w.warn(rel, "cannot inspect directory: %v", err)
				continue
			}
			if err := w.descend(rel, name, depth, ancestors, info); err != nil {
				return err
			}
			continue
		}
		if !isSharedSkill(rel) {
			continue
		}
		if !mode.IsRegular() {
			w.warn(rel, "not a regular file; not read")
			continue
		}
		w.files = append(w.files, rel)
	}
	return nil
}

func (w *skillWalk) descend(rel, name string, depth int, ancestors []fs.FileInfo, info fs.FileInfo) error {
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

type skillRead struct {
	reader *adapters.SafeReader
	limits Limits
	files  int
	bytes  int64
	warned bool
}

func (r *skillRead) file(rel string) ([]byte, bool, *adapters.Diagnostic) {
	if r.files >= r.limits.MaxFiles {
		if !r.warned {
			r.warned = true
			return nil, false, &adapters.Diagnostic{
				Harness: model.SurfaceGeneric, Scope: model.ScopeRepo,
				Message: fmt.Sprintf("repository walk truncated: more than %d configuration files; the rest were not scanned", r.limits.MaxFiles),
			}
		}
		return nil, false, nil
	}
	r.files++
	limit := r.limits.MaxFile
	if remaining := r.limits.MaxBytes - r.bytes; remaining < limit {
		limit = remaining
	}
	raw, err := r.reader.ReadFile(rel, limit)
	if err != nil {
		msg := "cannot read: " + err.Error()
		if errors.Is(err, adapters.ErrFileTooBig) && limit < r.limits.MaxFile {
			msg = fmt.Sprintf("repository walk truncated: total configuration bytes exceed %d; not scanned", r.limits.MaxBytes)
		}
		return nil, false, &adapters.Diagnostic{Harness: model.SurfaceGeneric, Scope: model.ScopeRepo, Path: rel, Message: msg}
	}
	r.bytes += int64(len(raw))
	return raw, true, nil
}
