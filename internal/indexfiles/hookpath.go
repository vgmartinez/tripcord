package indexfiles

import (
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

// RepoCandidate reports whether a repository scan reads rel without
// knowing plugin roots. Policy files are separate (see policyPath).
func RepoCandidate(rel string) bool {
	return claude.RepoCandidate(rel) ||
		codex.RepoCandidate(rel) ||
		copilot.RepoCandidate(rel) ||
		cursor.RepoCandidate(rel) ||
		devcontainer.RepoCandidate(rel) ||
		devin.RepoCandidate(rel) ||
		gemini.RepoCandidate(rel) ||
		generic.RepoCandidate(rel) ||
		opencode.RepoCandidate(rel) ||
		windsurf.RepoCandidate(rel)
}

// HookPath reports whether rel can be a file the repository adapters read,
// including a Claude plugin path under any prefix of rel. The pre-commit
// files regex is checked against every path for which this is true.
func HookPath(rel string) bool {
	if RepoCandidate(rel) || policyPath(rel) {
		return true
	}
	roots := map[string]bool{"": true}
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		roots[strings.Join(parts[:i], "/")] = true
	}
	return claude.Reads(rel, roots)
}

func policyPath(rel string) bool {
	return rel == ".tripcord/policy.yaml" || rel == ".tripcord/policy.local.yaml" || strings.HasPrefix(rel, ".tripcord/")
}
