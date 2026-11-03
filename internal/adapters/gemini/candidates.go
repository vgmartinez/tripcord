package gemini

import "github.com/vgmartinez/tripcord/internal/adapters/kit"

// RepoCandidate reports whether Discover reads rel from the repository.
func RepoCandidate(rel string) bool { return classify(rel) != roleNone }

// RepoRelevant reports whether an unreadable symlink at rel can hide
// Gemini configuration.
func RepoRelevant(rel string) bool { return kit.HasSegment(kit.Segments(rel), ".gemini") }
