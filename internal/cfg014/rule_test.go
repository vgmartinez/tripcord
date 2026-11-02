package cfg014

import (
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
	human := prcontext.Review{State: "APPROVED", Login: "Ada", UserType: "User"}
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
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Available: true, Reviews: []prcontext.Review{human}}, Classifiers: []Classifier{cursor}},
			status: StatusClear,
		},
		{
			name:   "lone approval still clears",
			in:     Input{Agent: true, Author: "claude[bot]", Paths: []string{".cursor/hooks.json"}, PathsKnown: true, Reviews: prcontext.ReviewSet{Reviews: []prcontext.Review{human}}, Classifiers: []Classifier{cursor}},
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
	other := Evaluate(Input{
		Agent:      true,
		Author:     "claude[bot]",
		Paths:      []string{".cursor/hooks.json"},
		PathsKnown: true,
		Reviews: prcontext.ReviewSet{Reviews: []prcontext.Review{{
			State: "approved", Login: "Grace", UserType: "User",
		}}},
		Classifiers: []Classifier{cursor},
	})
	if other.Status != StatusIncomplete {
		t.Fatalf("lowercase state = %s, want incomplete; only APPROVED counts", other.Status)
	}
}
