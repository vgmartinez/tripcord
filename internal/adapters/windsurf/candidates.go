package windsurf

import "github.com/vgmartinez/tripcord/internal/adapters/kit"

// RepoCandidate reports whether Discover reads rel from the repository.
func RepoCandidate(rel string) bool { return classify(rel) != roleNone }

// RepoRelevant reports whether an unreadable symlink at rel can hide
// Windsurf or Devin Local hook configuration.
func RepoRelevant(rel string) bool {
	segments := kit.Segments(rel)
	return kit.HasSegment(segments, ".devin") ||
		kit.HasSegment(segments, ".windsurf") ||
		(len(segments) == 1 && segments[0] == ".windsurfrules")
}
