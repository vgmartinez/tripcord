package cfg014

import (
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/prcontext"
)

func TestSymlinkPlan(t *testing.T) {
	extra, remaps, reason := SymlinkPlan(
		[]prcontext.Change{{
			Status:  "A",
			NewMode: prcontext.ModeSymlink,
			Path:    ".claude",
		}},
		[]prcontext.Symlink{{Path: ".claude", Target: "payload"}},
	)
	if reason != "" {
		t.Fatal(reason)
	}
	if len(extra) != 1 || extra[0].Path != ".claude" || extra[0].Harness != model.HarnessClaude {
		t.Fatalf("extra = %+v", extra)
	}
	if len(remaps) != 1 || remaps[0].From != "payload" || remaps[0].To != ".claude" {
		t.Fatalf("remaps = %+v", remaps)
	}

	_, _, reason = SymlinkPlan(nil, []prcontext.Symlink{{Path: ".claude", Unresolved: true}})
	if reason == "" {
		t.Fatal("unresolved symlink was accepted")
	}

	extra, _, reason = SymlinkPlan([]prcontext.Change{{
		Status:  "A",
		NewMode: prcontext.ModeGitlink,
		Path:    ".cursor",
	}}, nil)
	if reason != "" || len(extra) != 1 || extra[0].Harness != model.HarnessCursor {
		t.Fatalf("gitlink extra = %+v reason %s", extra, reason)
	}

	extra, _, _ = SymlinkPlan([]prcontext.Change{{
		Status:  "A",
		NewMode: prcontext.ModeSymlink,
		Path:    "notes",
	}}, nil)
	if len(extra) != 0 {
		t.Fatalf("ordinary symlink counted: %+v", extra)
	}

	extra, _, _ = SymlinkPlan([]prcontext.Change{{
		Status:  "D",
		OldMode: prcontext.ModeSymlink,
		NewMode: "000000",
		Path:    ".claude",
	}}, nil)
	if len(extra) != 0 {
		t.Fatalf("deleted symlink counted: %+v", extra)
	}
}

func TestRemapClassifiesTheSymlinkTarget(t *testing.T) {
	cursor := fakeClassifier{harness: model.HarnessCursor, paths: map[string]bool{".cursor/hooks.json": true}}
	claude := fakeClassifier{harness: model.HarnessClaude, paths: map[string]bool{".claude/settings.json": true}}
	got := Evaluate(Input{
		Agent:       true,
		Author:      "claude[bot]",
		Head:        "abc",
		Paths:       []string{"payload/settings.json"},
		PathsKnown:  true,
		Reviews:     prcontext.ReviewSet{Available: true},
		Classifiers: []Classifier{cursor, claude},
		Remaps:      []Remap{{From: "payload", To: ".claude"}},
	})
	if got.Status != StatusMatch {
		t.Fatalf("status = %s (%s)", got.Status, got.Reason)
	}
	if len(got.Paths) != 1 || got.Paths[0] != ".claude/settings.json" {
		t.Fatalf("paths = %v", got.Paths)
	}
}
