package cfg014

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

type fakeClassifier struct {
	harness model.Harness
	paths   map[string]bool
}

func (f fakeClassifier) Harness() model.Harness { return f.harness }

func (f fakeClassifier) Classifies(rel string) bool { return f.paths[rel] }

func TestEvaluate(t *testing.T) {
	cursor := fakeClassifier{harness: model.HarnessCursor, paths: map[string]bool{".cursor/hooks.json": true}}
	const headSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	human := prcontext.Review{State: "APPROVED", Login: "Ada", UserType: "User", CommitID: headSHA}
	tests := []struct {
		name   string
		in     Input
		status Status
		reason string
	}{
		{
			name:   "human author",
			in:     Input{Agent: false, Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Classifiers: []Classifier{cursor}},
			status: StatusClear,
		},
		{
			name:   "agent changes an ordinary file",
			in:     Input{Agent: true, Paths: []string{"README"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true}, Classifiers: []Classifier{cursor}},
			status: StatusClear,
		},
		{
			name:   "agent config with a human approval",
			in:     Input{Agent: true, Author: "claude[bot]", Head: headSHA, Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{human}}, Classifiers: []Classifier{cursor}},
			status: StatusClear,
		},
		{
			name:   "lone approval still clears",
			in:     Input{Agent: true, Author: "claude[bot]", Head: headSHA, Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Reviews: []prcontext.Review{human}}, Classifiers: []Classifier{cursor}},
			status: StatusClear,
		},
		{
			name:   "empty reviews array matches",
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true}, Classifiers: []Classifier{cursor}},
			status: StatusMatch,
		},
		{
			name:   "author cannot approve their own change",
			in:     Input{Agent: true, Author: "Ada", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{human}}, Classifiers: []Classifier{cursor}},
			status: StatusMatch,
		},
		{
			name:   "bot approval does not count",
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{{State: "APPROVED", Login: "reviewer[bot]", UserType: "Bot"}}}, Classifiers: []Classifier{cursor}},
			status: StatusMatch,
		},
		{
			name:   "user type with a bot suffix does not count",
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{{State: "APPROVED", Login: "helper[bot]", UserType: "User"}}}, Classifiers: []Classifier{cursor}},
			status: StatusMatch,
		},
		{
			name:   "missing type does not count",
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{{State: "APPROVED", Login: "Ada"}}}, Classifiers: []Classifier{cursor}},
			status: StatusMatch,
		},
		{
			name:   "comment is not approval",
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{{State: "COMMENTED", Login: "Ada", UserType: "User"}}}, Classifiers: []Classifier{cursor}},
			status: StatusMatch,
		},
		{
			name:   "missing reviews are incomplete",
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Classifiers: []Classifier{cursor}},
			status: StatusIncomplete,
			reason: "review data is not available",
		},
		{
			name:   "unread diff is incomplete",
			in:     Input{Agent: true, Classifiers: []Classifier{cursor}},
			status: StatusIncomplete,
			reason: "changed paths could not be read",
		},
		{
			name:   "truncated diff with no classified path is incomplete",
			in:     Input{Agent: true, Paths: []string{"README"}, PathsKnown: true, Truncated: true, Reviews: prcontext.ReviewSet{Available: true}, Classifiers: []Classifier{cursor}},
			status: StatusIncomplete,
			reason: "truncated",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(tc.in)
			if got.Status != tc.status {
				t.Fatalf("status = %s, want %s (%s)", got.Status, tc.status, got.Reason)
			}
			if tc.reason != "" && !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("reason = %q, want it to contain %q", got.Reason, tc.reason)
			}
			if tc.status == StatusMatch {
				if got.Finding == nil || got.Finding.Rule != RuleID || got.Finding.Severity != model.SeverityHigh {
					t.Fatalf("finding = %+v", got.Finding)
				}
				if err := got.Finding.Validate(); err != nil {
					t.Fatal(err)
				}
			} else if got.Finding != nil {
				t.Fatalf("finding set on %s", tc.status)
			}
		})
	}
}

func TestPathCap(t *testing.T) {
	const headSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	over := pathCapInput(t, 65, headSHA)
	got := Evaluate(over)
	if got.Status != StatusMatch || got.Finding == nil {
		t.Fatalf("status = %s, want match (%s)", got.Status, got.Reason)
	}
	if len(got.Paths) != maxPaths || len(got.Finding.Evidence) != maxPaths {
		t.Fatalf("cited %d paths and %d evidence, want %d", len(got.Paths), len(got.Finding.Evidence), maxPaths)
	}
	if got.Paths[0] != ".cursor/hooks.json" || got.Paths[maxPaths-1] != ".cursor/rules/pad-63.md" {
		t.Fatalf("cited range = %s .. %s", got.Paths[0], got.Paths[maxPaths-1])
	}
	for _, path := range got.Paths {
		if !strings.Contains(got.Reason, path) {
			t.Fatalf("reason missing %s", path)
		}
	}
	if strings.Contains(got.Reason, "pad-64.md") || strings.Contains(got.Reason, "pad-65.md") {
		t.Fatalf("reason cites a path past the cap:\n%s", got.Reason)
	}
	if !strings.HasSuffix(got.Reason, "\nand 2 more") {
		t.Fatalf("reason = %q", got.Reason)
	}
	if err := got.Finding.Validate(); err != nil {
		t.Fatal(err)
	}

	missing := over
	missing.Reviews = prcontext.ReviewSet{}
	got = Evaluate(missing)
	if got.Status != StatusMatch || !strings.HasSuffix(got.Reason, "\nand 2 more") {
		t.Fatalf("missing reviews above the cap = %s (%q)", got.Status, got.Reason)
	}

	approved := over
	approved.Reviews.Reviews = []prcontext.Review{{
		State: "APPROVED", Login: "Ada", UserType: "User", CommitID: headSHA,
	}}
	got = Evaluate(approved)
	if got.Status != StatusClear || got.Finding != nil || got.Reason != "" {
		t.Fatalf("approved above the cap = %s finding=%v reason=%q", got.Status, got.Finding != nil, got.Reason)
	}

	exact := pathCapInput(t, 63, headSHA)
	got = Evaluate(exact)
	if got.Status != StatusMatch || got.Reason != "" || len(got.Paths) != maxPaths {
		t.Fatalf("exactly %d paths = %s cited %d reason %q", maxPaths, got.Status, len(got.Paths), got.Reason)
	}

	under := pathCapInput(t, 10, headSHA)
	got = Evaluate(under)
	if got.Status != StatusMatch || got.Reason != "" || len(got.Paths) != 11 {
		t.Fatalf("below the cap = %s cited %d reason %q", got.Status, len(got.Paths), got.Reason)
	}
	underMissing := under
	underMissing.Reviews = prcontext.ReviewSet{}
	got = Evaluate(underMissing)
	if got.Status != StatusIncomplete || got.Reason != "review data is not available" {
		t.Fatalf("below the cap without reviews = %s (%q)", got.Status, got.Reason)
	}
}

// pathCapInput classifies .cursor/hooks.json plus n rule files. n == 63
// is exactly maxPaths hits; n == 65 is the hook plus 65 rules.
func pathCapInput(t *testing.T, rules int, head string) Input {
	t.Helper()
	paths := make([]string, 0, rules+1)
	classified := map[string]bool{".cursor/hooks.json": true}
	paths = append(paths, ".cursor/hooks.json")
	for i := 1; i <= rules; i++ {
		path := fmt.Sprintf(".cursor/rules/pad-%02d.md", i)
		paths = append(paths, path)
		classified[path] = true
	}
	return Input{
		Agent:       true,
		Author:      "claude[bot]",
		Head:        head,
		Paths:       paths,
		PathsKnown:  true,
		Reviews:     prcontext.ReviewSet{Available: true},
		Classifiers: []Classifier{fakeClassifier{harness: model.HarnessCursor, paths: classified}},
	}
}

func TestCaseInsensitiveAuthorAndLogin(t *testing.T) {
	cursor := fakeClassifier{harness: model.HarnessCursor, paths: map[string]bool{".cursor/hooks.json": true}}
	got := Evaluate(Input{
		Agent:      true,
		Author:     "Ada",
		Paths:      []string{".cursor/hooks.json"},
		PathsKnown: true,
		Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{{
			State: "APPROVED", Login: "ada", UserType: "User",
		}}},
		Classifiers: []Classifier{cursor},
	})
	if got.Status != StatusMatch {
		t.Fatalf("status = %s, want match so the author cannot approve themselves under different case", got.Status)
	}
	const headSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	other := Evaluate(Input{
		Agent:      true,
		Author:     "claude[bot]",
		Head:       headSHA,
		Paths:      []string{".cursor/hooks.json"},
		PathsKnown: true,
		Reviews: prcontext.ReviewSet{Reviews: []prcontext.Review{{
			State: "approved", Login: "Grace", UserType: "User", CommitID: headSHA,
		}}},
		Classifiers: []Classifier{cursor},
	})
	if other.Status != StatusClear {
		t.Fatalf("lowercase state = %s, want clear; approved is normalized", other.Status)
	}
}

func TestStaleAndSupersededReviewsDoNotClear(t *testing.T) {
	cursor := fakeClassifier{harness: model.HarnessCursor, paths: map[string]bool{".cursor/hooks.json": true}}
	const (
		headSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		baseSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	base := Input{
		Agent:       true,
		Author:      "claude[bot]",
		Head:        headSHA,
		Paths:       []string{".cursor/hooks.json"},
		PathsKnown:  true,
		Classifiers: []Classifier{cursor},
	}
	approve := func(commit, state, at string) prcontext.Review {
		return prcontext.Review{State: state, Login: "Ada", UserType: "User", CommitID: commit, SubmittedAt: at}
	}
	tests := []struct {
		name    string
		reviews []prcontext.Review
		status  Status
	}{
		{
			name:    "approval of the base sha",
			reviews: []prcontext.Review{approve(baseSHA, "APPROVED", "")},
			status:  StatusMatch,
		},
		{
			name:    "approval of a random sha",
			reviews: []prcontext.Review{approve("0123456789abcdef0123456789abcdef01234567", "APPROVED", "")},
			status:  StatusMatch,
		},
		{
			name:    "approval with no commit id",
			reviews: []prcontext.Review{approve("", "APPROVED", "")},
			status:  StatusMatch,
		},
		{
			name: "approved then changes requested",
			reviews: []prcontext.Review{
				approve(headSHA, "APPROVED", "2026-01-01T00:00:00Z"),
				approve(headSHA, "CHANGES_REQUESTED", "2026-01-02T00:00:00Z"),
			},
			status: StatusMatch,
		},
		{
			name: "changes requested then approved, array order without timestamps",
			reviews: []prcontext.Review{
				approve(headSHA, "CHANGES_REQUESTED", ""),
				approve(headSHA, "approved", ""),
			},
			status: StatusClear,
		},
		{
			name: "approval followed by a comment still counts",
			reviews: []prcontext.Review{
				approve(headSHA, "APPROVED", "2026-01-01T00:00:00Z"),
				approve(headSHA, "COMMENTED", "2026-01-03T00:00:00Z"),
			},
			status: StatusClear,
		},
		{
			name: "later submitted_at wins over array order",
			reviews: []prcontext.Review{
				approve(headSHA, "CHANGES_REQUESTED", "2026-01-02T00:00:00Z"),
				approve(headSHA, "APPROVED", "2026-01-01T00:00:00Z"),
			},
			status: StatusMatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			in.Reviews = prcontext.ReviewSet{Available: true, Reviews: tc.reviews}
			got := Evaluate(in)
			if got.Status != tc.status {
				t.Fatalf("status = %s, want %s (%s)", got.Status, tc.status, got.Reason)
			}
		})
	}
}
