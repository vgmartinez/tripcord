package devcontainer

import "github.com/vgmartinez/tripcord/internal/adapters/kit"

// RepoCandidate reports whether Discover reads rel from the repository.
func RepoCandidate(rel string) bool { return isConfig(rel) }

// RepoRelevant reports whether an unreadable symlink at rel can hide
// Dev Container configuration.
func RepoRelevant(rel string) bool {
	segments := kit.Segments(rel)
	return segments[0] == ".devcontainer" || (len(segments) == 1 && segments[0] == ".devcontainer.json")
}
