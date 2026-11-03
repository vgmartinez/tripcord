package hook

import (
	"errors"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestCallEvent(t *testing.T) {
	t.Parallel()
	ev := Call{
		Harness: model.HarnessClaude, Origin: "hook:PreToolUse", Tool: "WebFetch",
		Input: map[string]any{"url": "https://example.com/a?b=c", "prompt": "summarize"},
	}.Event([]byte("raw"), time.Unix(0, 0))
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	if ev.Kind != model.EventKindNet || len(ev.Net) != 1 || ev.Net[0].Host != "example.com" || ev.Session.ID != "unknown" {
		t.Errorf("got %+v", ev)
	}
	for tool, want := range map[string]model.EventKind{"Read": model.EventKindRead, "Edit": model.EventKindWrite, "Task": model.EventKindToolCall} {
		if got := (Call{Harness: model.HarnessClaude, Tool: tool}).Event(nil, time.Unix(0, 0)).Kind; got != want {
			t.Errorf("%s: kind %s, want %s", tool, got, want)
		}
	}
}

func TestFailed(t *testing.T) {
	t.Parallel()
	v := Failed(errors.New("boom"))
	if v.Decision != model.DecisionDeny || v.Exit() != exitcode.Block || v.Reason != "tripcord hook failed closed: boom" {
		t.Errorf("got %+v", v)
	}
}

func TestParseOnFailure(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"block", "error"} {
		if _, err := ParseOnFailure(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := ParseOnFailure("allow"); err == nil {
		t.Error("allow: want an error")
	}
}
