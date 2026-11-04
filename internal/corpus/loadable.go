package corpus

import (
	"path"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/devin"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/opencode"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
)

// wiredAdapters is every adapter package that exports RepoCandidate.
// TestEveryAdapterCandidateIsWired fails when a new one appears and this
// list, and candidate below, were not updated.
var wiredAdapters = []string{
	"claude",
	"codex",
	"copilot",
	"cursor",
	"devcontainer",
	"devin",
	"gemini",
	"generic",
	"opencode",
	"windsurf",
}

// loadable reports whether an adapter would read rel, or any suffix of
// rel, when that suffix is the path relative to a workspace root. Copilot
// and Dev Containers match only at the workspace root, so a nested
// .github or .devcontainer still counts: opening that directory is enough
// to load it. Paths inside a txtar member are not passed here.
func loadable(rel string) bool {
	rel = path.Clean(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	parts := strings.Split(rel, "/")
	for i := range parts {
		if candidate(strings.Join(parts[i:], "/")) {
			return true
		}
	}
	return false
}

func candidate(rel string) bool {
	// A bare mcp.json at a workspace root is loadable. No adapter
	// RepoCandidate names that exact file; .mcp.json and the
	// per-harness copies still come from those predicates.
	if rel == "mcp.json" {
		return true
	}
	switch {
	case claude.RepoCandidate(rel),
		codex.RepoCandidate(rel),
		copilot.RepoCandidate(rel),
		cursor.RepoCandidate(rel),
		devcontainer.RepoCandidate(rel),
		devin.RepoCandidate(rel),
		gemini.RepoCandidate(rel),
		generic.RepoCandidate(rel),
		opencode.RepoCandidate(rel),
		windsurf.RepoCandidate(rel):
		return true
	default:
		return false
	}
}
