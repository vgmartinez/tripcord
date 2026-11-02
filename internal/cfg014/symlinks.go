package cfg014

import (
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

// coveredDirHarness maps a directory an adapter classifies files under
// to the harness a symlink or gitlink at that directory is reported as.
// The names are the path segments, at the repository root or nested.
var coveredDirHarness = map[string]model.Harness{
	".agents":        model.SurfaceGeneric,
	".claude":        model.HarnessClaude,
	".claude-plugin": model.HarnessClaude,
	".codex":         model.HarnessCodex,
	".cursor":        model.HarnessCursor,
	".devcontainer":  model.SurfaceDevcontainer,
	".devin":         model.HarnessDevin,
	".gemini":        model.HarnessGemini,
	".github":        model.HarnessCopilot,
	".opencode":      model.HarnessOpenCode,
	".vscode":        model.SurfaceVSCode,
	".windsurf":      model.HarnessWindsurf,
}

// CoveredDirs returns the directory names TreeSymlinks should resolve.
func CoveredDirs() []string {
	names := make([]string, 0, len(coveredDirHarness))
	for name := range coveredDirHarness {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// ExtraHit is a path that counts as agent config because it is a symlink
// or gitlink at a covered directory, not because an adapter classifies
// the path as a file.
type ExtraHit struct {
	Path    string
	Harness model.Harness
}

// Remap rewrites a changed path under From so it is also classified as
// a path under To. From is a symlink target and To is the covered path.
type Remap struct {
	From string
	To   string
}

// SymlinkPlan decides which diff entries are covered symlinks or
// gitlinks, and which existing symlinks rewrite other changed paths.
// A non-empty reason means a covered symlink could not be resolved;
// that result is incomplete rather than a pass.
func SymlinkPlan(changes []prcontext.Change, links []prcontext.Symlink) (extra []ExtraHit, remaps []Remap, reason string) {
	for _, link := range links {
		if link.Unresolved || link.Target == "" {
			return nil, nil, "could not resolve symlink at " + link.Path
		}
		remaps = append(remaps, Remap{From: link.Target, To: link.Path})
	}
	for _, ch := range changes {
		if !addedOrModified(ch.Status) {
			continue
		}
		if ch.NewMode != prcontext.ModeSymlink && ch.NewMode != prcontext.ModeGitlink {
			continue
		}
		harness, ok := harnessForCovered(ch.Path)
		if !ok {
			continue
		}
		extra = append(extra, ExtraHit{Path: ch.Path, Harness: harness})
	}
	return extra, remaps, ""
}

func addedOrModified(status string) bool {
	if status == "" {
		return false
	}
	switch status[0] {
	case 'A', 'M', 'T', 'R', 'C':
		return true
	default:
		return false
	}
}

func harnessForCovered(rel string) (model.Harness, bool) {
	var found model.Harness
	ok := false
	for _, seg := range strings.Split(rel, "/") {
		h, exists := coveredDirHarness[seg]
		if !exists {
			continue
		}
		if !ok || h < found {
			found = h
			ok = true
		}
	}
	return found, ok
}

func remapPaths(paths []string, remaps []Remap) []string {
	if len(remaps) == 0 {
		return paths
	}
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range paths {
		add(p)
		for _, m := range remaps {
			switch {
			case p == m.From:
				add(m.To)
			case strings.HasPrefix(p, m.From+"/"):
				add(m.To + "/" + strings.TrimPrefix(p, m.From+"/"))
			}
		}
	}
	return out
}

func mergeHits(hits []classified, extra []ExtraHit) []classified {
	if len(extra) == 0 {
		return hits
	}
	byPath := map[string]model.Harness{}
	for _, hit := range hits {
		byPath[hit.path] = hit.harness
	}
	for _, e := range extra {
		if e.Path == "" || e.Harness == "" {
			continue
		}
		if prev, ok := byPath[e.Path]; !ok || e.Harness < prev {
			byPath[e.Path] = e.Harness
		}
	}
	out := make([]classified, 0, len(byPath))
	for p, harness := range byPath {
		out = append(out, classified{path: p, harness: harness})
	}
	slices.SortFunc(out, func(a, b classified) int {
		if c := strings.Compare(a.path, b.path); c != 0 {
			return c
		}
		return strings.Compare(string(a.harness), string(b.harness))
	})
	return out
}
