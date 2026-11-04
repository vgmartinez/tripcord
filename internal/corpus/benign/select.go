package benign

import (
	"slices"
	"strings"
)

// Select stratifies repos by harness and size and returns at most target
// of them, sorted by owner/repo. A repository with several harnesses can
// fill any one of those harness buckets, and it is chosen at most once.
// Inside a bucket, higher star counts come first.
func Select(repos []Repo, target int) []Repo {
	if target < 0 {
		target = 0
	}
	bands := []string{"small", "medium", "large"}
	type bucket struct {
		items []Repo
		i     int
	}
	buckets := map[string]map[string]*bucket{}
	for _, h := range Harnesses {
		buckets[h] = map[string]*bucket{}
		for _, band := range bands {
			buckets[h][band] = &bucket{}
		}
	}
	for _, r := range repos {
		band := SizeBand(r.SizeKB)
		seen := map[string]bool{}
		for _, h := range r.Harnesses {
			if !knownHarness(h) || seen[h] {
				continue
			}
			seen[h] = true
			buckets[h][band].items = append(buckets[h][band].items, r)
		}
	}
	for _, h := range Harnesses {
		for _, band := range bands {
			slices.SortFunc(buckets[h][band].items, func(a, b Repo) int {
				if a.Stars != b.Stars {
					return b.Stars - a.Stars
				}
				return strings.Compare(a.Name, b.Name)
			})
		}
	}
	chosen := map[string]bool{}
	var out []Repo
	for len(out) < target {
		progress := false
		for _, h := range Harnesses {
			for _, band := range bands {
				if len(out) >= target {
					break
				}
				b := buckets[h][band]
				for b.i < len(b.items) {
					r := b.items[b.i]
					b.i++
					if chosen[r.Name] {
						continue
					}
					chosen[r.Name] = true
					out = append(out, r)
					progress = true
					break
				}
			}
		}
		if !progress {
			break
		}
	}
	slices.SortFunc(out, func(a, b Repo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}
