package hook

import (
	"errors"
	"path/filepath"
	"slices"
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

func TestCleanToolPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path, base string
		windows          bool
		want             string
	}{
		{name: "relative", path: ".env", base: "/proj", want: "/proj/.env"},
		{name: "dot slash", path: "./.env", base: "/proj", want: "/proj/.env"},
		{name: "parent", path: "foo/../.env", base: "/proj", want: "/proj/.env"},
		{name: "upper stays", path: ".ENV", base: "/proj", want: "/proj/.ENV"},
		{name: "upper windows", path: ".ENV", base: "/proj", windows: true, want: "/proj/.env"},
		{name: "trailing slash", path: "/abs/.env/", want: "/abs/.env"},
		{name: "trailing slash windows", path: "/Abs/.ENV/", windows: true, want: "/abs/.env"},
		{name: "absolute parent", path: "/abs/foo/../.env", want: "/abs/.env"},
		{name: "url userinfo stays", path: "( git clone https://u:secret@h.invalid/r", base: "/tmp/proj", want: "( git clone https://u:secret@h.invalid/r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := cleanToolPath(tc.path, tc.base, tc.windows); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEventNormalizesPaths(t *testing.T) {
	t.Parallel()
	ev := Call{
		Harness: model.HarnessClaude,
		Tool:    "Read",
		Dir:     "/proj",
		Paths:   []string{".env"},
		Input:   map[string]any{"file_path": "./.env", "path": "/abs/.env/"},
	}.Event([]byte("raw"), time.Unix(0, 0))
	want := []string{
		filepath.ToSlash(filepath.Clean(filepath.Join("/proj", ".env"))),
		filepath.ToSlash(filepath.Clean("/abs/.env/")),
	}
	if !slices.Equal(ev.Paths, want) {
		t.Fatalf("paths = %q, want %q", ev.Paths, want)
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
