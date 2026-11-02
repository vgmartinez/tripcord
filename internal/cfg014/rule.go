// Package cfg014 evaluates TC-CFG-014: an agent-config change in a pull
// request whose author pr-context already classified as a bot or agent,
// with no human approval.
//
// The rule is not a CEL expression over one config file. It needs the
// pull request author, the review list, and the diff, so pr-context runs
// it. There is no rules/TC-CFG-014.yaml.
package cfg014

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

const (
	// RuleID is the reserved id. It is not listed in rules/REGISTRY
	// because that file gains a line only when rules/<ID>.yaml exists.
	RuleID = "TC-CFG-014"
	// maxPaths is the most agent-config paths one finding will cite.
	// A larger set is incomplete rather than a finding that drops paths.
	maxPaths = 64
)

// Status is the rule result.
type Status string

const (
	// StatusClear means the rule does not apply, or a human approved it.
	StatusClear Status = "clear"
	// StatusMatch means agent config changed without human approval.
	StatusMatch Status = "match"
	// StatusIncomplete means the rule could not be decided. It is not a pass.
	StatusIncomplete Status = "incomplete"
)

// Classifier is the path check each adapter already uses. pr-context
// passes the real adapters; tests pass fakes.
type Classifier interface {
	Harness() model.Harness
	Classifies(rel string) bool
}

// Input is everything Evaluate needs. PathsKnown is false when the diff
// could not be read. Truncated is true when the diff was longer than the
// reader kept. Reviews.Available is false when the event had no reviews
// array. Head is the pull request head SHA; an approval counts only when
// its commit_id equals Head.
type Input struct {
	Agent       bool
	Author      string
	Head        string
	Paths       []string
	PathsKnown  bool
	Truncated   bool
	Reviews     prcontext.ReviewSet
	Classifiers []Classifier
	// Extra counts a symlink or gitlink at a covered directory even when
	// the path is not a file an adapter classifies.
	Extra []ExtraHit
	// Remaps rewrites changed paths that sit under a symlink target so
	// they are classified as paths under the covered directory.
	Remaps []Remap
	// SymlinkReason is set when a covered symlink could not be resolved.
	// The result is incomplete.
	SymlinkReason string
}

// Outcome is one evaluation. Finding is set only for StatusMatch.
// Reason is the incomplete diagnostic, or empty when the status is clear.
type Outcome struct {
	Status  Status
	Finding *model.Finding
	Reason  string
	Paths   []string
}

// Evaluate applies TC-CFG-014. A pull request pr-context did not classify
// as agent-authored is clear. So is an agent-authored pull request that
// does not change a classified path. Human approval is the latest
// non-COMMENTED review from a user, and that review has to be APPROVED
// on Head. user.type is User, the login does not end in [bot], and the
// login is not the pull request author's. Review state is compared
// case-insensitively. A qualifying review counts even when
// Reviews.Available is false, because a single exposed approval is
// positive evidence. Anything else, when a classified path changed and
// the reviews array is missing, is incomplete. A symlink or gitlink
// added or modified at a covered directory counts as a hit. A covered
// directory that is already a symlink is resolved in the changed paths;
// a target that cannot be resolved is incomplete.
func Evaluate(in Input) Outcome {
	if !in.Agent {
		return Outcome{Status: StatusClear}
	}
	if len(in.Classifiers) == 0 {
		return Outcome{Status: StatusIncomplete, Reason: "no adapter classified paths"}
	}
	if !in.PathsKnown {
		return Outcome{Status: StatusIncomplete, Reason: "changed paths could not be read"}
	}
	if in.SymlinkReason != "" {
		return Outcome{Status: StatusIncomplete, Reason: in.SymlinkReason}
	}
	hits := mergeHits(classifiedPaths(remapPaths(in.Paths, in.Remaps), in.Classifiers), in.Extra)
	approved := humanApproval(in.Author, in.Head, in.Reviews)
	if in.Truncated && len(hits) == 0 && !approved {
		return Outcome{Status: StatusIncomplete, Reason: "the diff was truncated before an agent-config path was found"}
	}
	if len(hits) == 0 {
		return Outcome{Status: StatusClear}
	}
	if approved {
		return Outcome{Status: StatusClear}
	}
	if len(hits) > maxPaths {
		return Outcome{Status: StatusIncomplete, Reason: fmt.Sprintf("more than %d agent-config paths changed", maxPaths)}
	}
	if !in.Reviews.Available {
		return Outcome{Status: StatusIncomplete, Reason: "review data is not available"}
	}
	finding, err := findingFor(hits)
	if err != nil {
		return Outcome{Status: StatusIncomplete, Reason: err.Error()}
	}
	paths := make([]string, len(hits))
	for i, hit := range hits {
		paths[i] = hit.path
	}
	return Outcome{Status: StatusMatch, Finding: &finding, Paths: paths}
}

type classified struct {
	path    string
	harness model.Harness
}

func classifiedPaths(paths []string, classifiers []Classifier) []classified {
	byPath := map[string]model.Harness{}
	for _, rel := range paths {
		var harness model.Harness
		found := false
		for _, classifier := range classifiers {
			if !classifier.Classifies(rel) {
				continue
			}
			name := classifier.Harness()
			if !found || name < harness {
				harness = name
				found = true
			}
		}
		if !found {
			continue
		}
		if prev, ok := byPath[rel]; !ok || harness < prev {
			byPath[rel] = harness
		}
	}
	out := make([]classified, 0, len(byPath))
	for path, harness := range byPath {
		out = append(out, classified{path: path, harness: harness})
	}
	slices.SortFunc(out, func(a, b classified) int {
		if c := strings.Compare(a.path, b.path); c != 0 {
			return c
		}
		return strings.Compare(string(a.harness), string(b.harness))
	})
	return out
}

func humanApproval(author, head string, reviews prcontext.ReviewSet) bool {
	for _, review := range latestReviews(reviews.Reviews) {
		if review.State != "APPROVED" || review.UserType != "User" {
			continue
		}
		login := review.Login
		if login == "" || strings.HasSuffix(strings.ToLower(login), "[bot]") {
			continue
		}
		if author != "" && strings.EqualFold(login, author) {
			continue
		}
		if !sameCommit(review.CommitID, head) {
			continue
		}
		return true
	}
	return false
}

// latestReviews keeps, for each login, that user's last review whose
// state is not COMMENTED. Reviews are ordered by submitted_at when both
// sides have a timestamp, and by array order otherwise. State is returned
// in upper case.
func latestReviews(reviews []prcontext.Review) []prcontext.Review {
	type row struct {
		review  prcontext.Review
		index   int
		when    time.Time
		hasWhen bool
	}
	grouped := map[string][]row{}
	var order []string
	for i, review := range reviews {
		state := strings.ToUpper(strings.TrimSpace(review.State))
		if state == "" || state == "COMMENTED" {
			continue
		}
		review.State = state
		key := strings.ToLower(review.Login)
		if _, ok := grouped[key]; !ok {
			order = append(order, key)
		}
		item := row{review: review, index: i}
		if when, ok := parseSubmitted(review.SubmittedAt); ok {
			item.when = when
			item.hasWhen = true
		}
		grouped[key] = append(grouped[key], item)
	}
	out := make([]prcontext.Review, 0, len(order))
	for _, key := range order {
		rows := grouped[key]
		slices.SortStableFunc(rows, func(a, b row) int {
			if a.hasWhen && b.hasWhen {
				if c := a.when.Compare(b.when); c != 0 {
					return c
				}
			}
			return a.index - b.index
		})
		out = append(out, rows[len(rows)-1].review)
	}
	return out
}

func parseSubmitted(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if when, err := time.Parse(layout, value); err == nil {
			return when, true
		}
	}
	return time.Time{}, false
}

func sameCommit(commitID, head string) bool {
	commitID = strings.TrimSpace(commitID)
	head = strings.TrimSpace(head)
	return commitID != "" && head != "" && strings.EqualFold(commitID, head)
}

func findingFor(hits []classified) (model.Finding, error) {
	first := hits[0]
	evidence := make([]model.Evidence, len(hits))
	for i, hit := range hits {
		evidence[i] = model.Evidence{Config: &model.ConfigRef{
			ID: string(hit.harness) + ":" + string(model.ScopeRepo) + ":" + hit.path,
		}}
	}
	finding := model.Finding{
		Schema:     model.SchemaFinding,
		Rule:       RuleID,
		Title:      "Agent configuration changed in an agent-authored pull request without human approval",
		Severity:   model.SeverityHigh,
		Decision:   model.DecisionDeny,
		Confidence: 1,
		Evidence:   evidence,
		Location: model.Location{
			Harness: first.harness,
			Scope:   model.ScopeRepo,
			Path:    first.path,
		},
		Refs: []string{"https://workos.com/blog/npm-worm-coding-agent-config-credentials"},
		Fix:  "Get an APPROVED review from a non-bot user who is not the pull request author before merging this agent configuration change.",
	}
	fingerprint, err := model.Fingerprint(finding.Rule, finding.Location, finding.Evidence)
	if err != nil {
		return model.Finding{}, fmt.Errorf("TC-CFG-014 finding: %w", err)
	}
	finding.Fingerprint = fingerprint
	if err := finding.Validate(); err != nil {
		return model.Finding{}, fmt.Errorf("TC-CFG-014 finding: %w", err)
	}
	return finding, nil
}
