package copilot

import "github.com/vgmartinez/tripcord/internal/adapters/kit"

// RepoCandidate reports whether Discover reads rel from the repository.
func RepoCandidate(rel string) bool { return classify(rel) != roleNone }

// RepoRelevant reports whether an unreadable symlink at rel can hide
// Copilot configuration.
func RepoRelevant(rel string) bool {
	segments := kit.Segments(rel)
	if segments[0] != ".github" {
		return false
	}
	return len(segments) == 1 || copilotDirs[segments[1]]
}
