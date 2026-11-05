package benign

import (
	"slices"
	"strings"
)

// DefaultMinPerHarness is the resume floor for each of the nine
// harnesses. Nine times 40 is 360, so the floor does not consume the
// 1,000-repository target; the crawl keeps filling after every harness
// has a row in that many repositories. Forty is enough for a few false
// positives to show (one is 2.5 percent) and low enough that a rarer
// harness does not stall the run. The -min-harness flag overrides it.
const DefaultMinPerHarness = 40

// Merge unions fresh into existing. An existing row keeps its commit
// SHA, license, and date unless repin is set. Harnesses are combined.
// A size band is filled in when the existing row has none. Rows only
// present in existing are kept. The result is sorted by owner/repo.
func Merge(existing, fresh []Repo, repin bool) []Repo {
	byName := map[string]Repo{}
	var order []string
	for _, r := range existing {
		if _, ok := byName[strings.ToLower(r.Name)]; ok {
			continue
		}
		byName[strings.ToLower(r.Name)] = r
		order = append(order, strings.ToLower(r.Name))
	}
	for _, r := range fresh {
		old, ok := byName[strings.ToLower(r.Name)]
		if !ok {
			byName[strings.ToLower(r.Name)] = r
			order = append(order, strings.ToLower(r.Name))
			continue
		}
		if repin {
			if r.SHA != "" {
				old.SHA = r.SHA
			}
			if r.Date != "" {
				old.Date = r.Date
			}
			if r.License != "" {
				old.License = r.License
			}
		}
		if old.Band == "" && r.Band != "" {
			old.Band = r.Band
		}
		if old.SizeKB == 0 && r.SizeKB != 0 {
			old.SizeKB = r.SizeKB
		}
		if r.Stars != 0 {
			old.Stars = r.Stars
		}
		old.Harnesses = unionHarnesses(old.Harnesses, r.Harnesses)
		byName[strings.ToLower(r.Name)] = old
	}
	out := make([]Repo, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	slices.SortFunc(out, func(a, b Repo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func unionHarnesses(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range append(append([]string{}, a...), b...) {
		if !knownHarness(h) || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// Integrate keeps every existing row, applies fresh metadata with
// Merge, and adds new rows only while the result is under target.
// Existing rows are never dropped to make the list shorter.
func Integrate(existing, fresh []Repo, target int, repin bool) []Repo {
	if target < 0 {
		target = 0
	}
	merged := Merge(existing, fresh, repin)
	exist := map[string]bool{}
	for _, r := range existing {
		exist[strings.ToLower(r.Name)] = true
	}
	var kept, extra []Repo
	for _, r := range merged {
		if exist[strings.ToLower(r.Name)] {
			kept = append(kept, r)
			continue
		}
		extra = append(extra, r)
	}
	room := target - len(kept)
	if room < 0 {
		room = 0
	}
	picked := Select(extra, room)
	out := append(kept, picked...)
	slices.SortFunc(out, func(a, b Repo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// ExitCode is the process status for one crawl. A rate limit is never
// success. A run that stopped short of the target is success only when
// partial is set. An empty result is not success.
func ExitCode(res Result, partial bool) int {
	if res.RateLimited || len(res.Repos) == 0 {
		return 1
	}
	if res.Incomplete && !partial {
		return 1
	}
	return 0
}
