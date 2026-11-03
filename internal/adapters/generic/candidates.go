package generic

import (
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
)

// RepoCandidate reports whether Discover reads rel from the repository.
func RepoCandidate(rel string) bool { return classify(rel) != roleNone }

// RepoRelevant reports whether an unreadable symlink at rel can hide
// shared skill, AGENTS.md, or editor task configuration.
func RepoRelevant(rel string) bool {
	segments := strings.Split(rel, "/")
	if segments[0] == ".vscode" {
		return true
	}
	for _, root := range skillRoots {
		if kit.HasSequence(segments, root) {
			return true
		}
	}
	return false
}
