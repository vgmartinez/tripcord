package opencode

import "github.com/vgmartinez/tripcord/internal/adapters/kit"

// RepoCandidate reports whether Discover reads rel from the repository.
// Nested plugin and tool modules are listed by the walk and not read.
func RepoCandidate(rel string) bool {
	role := classify(rel)
	return role != roleNone && role != roleNested
}

// RepoRelevant reports whether an unreadable symlink at rel can hide
// OpenCode configuration.
func RepoRelevant(rel string) bool {
	segments := kit.Segments(rel)
	base := segments[len(segments)-1]
	if base == "agents.md" || kit.HasSegment(segments, "node_modules") {
		return false
	}
	return kit.HasSegment(segments, ".opencode") || base == "opencode.json" || base == "opencode.jsonc"
}
