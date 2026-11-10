package main

import (
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
)

// TestTemplateChangeNeedsRepin keeps the writer witness sound: an older
// scanner trusts that a pin it knows only ever wrote the renders it
// compiled for that pin (known_renders.json), so a template change must
// come with a new WorkflowPin. It runs on every pull request.
//
// Without history it checks that this tree's renders are in
// known_renders.json under WorkflowPin. With history (always in CI,
// where TestVetAndTestFetchesFullHistory keeps fetch-depth 0) it also
// checks against main: every pin main's known_renders.json lists keeps
// exactly its renders, so a template change cannot be added under a pin
// main already has.
func TestTemplateChangeNeedsRepin(t *testing.T) {
	known := embedded.KnownRenders()
	if !known[embedded.WorkflowPin].Includes(embedded.CurrentRenders()) {
		t.Fatal("this tree's init writes a render known_renders.json lacks under WorkflowPin: a template change needs a repin (set WorkflowPin, append the old pin to KnownWorkflowPins, run go run ./scripts/knownrenders)")
	}
	root := filepath.Join("..", "..")
	if !pinHistoryAvailable(t, root) {
		return
	}
	ref := mainRef(t, root)
	raw, err := gitOutput(root, "show", ref+":"+embedded.KnownRendersPath)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "exists on disk, but not in") {
			t.Logf("%s has no %s yet: nothing to compare", ref, embedded.KnownRendersPath)
			return
		}
		t.Fatal(err)
	}
	onMain, err := embedded.ParseKnownRenders([]byte(raw))
	if err != nil {
		t.Fatalf("%s:%s: %v", ref, embedded.KnownRendersPath, err)
	}
	for _, pin := range slices.Sorted(maps.Keys(onMain.Pins)) {
		head, ok := known[pin]
		switch {
		case !ok:
			t.Errorf("pin %s is in %s's known_renders.json but not in this tree's: entries are never removed", pin, ref)
		case !reflect.DeepEqual(normalizeRenderSet(head), normalizeRenderSet(onMain.Pins[pin])):
			t.Errorf("template changed: repin WorkflowPin. The renders of pin %s differ from %s's; a pin %s already has never gains or loses a render", pin, ref, ref)
		}
	}
}

func normalizeRenderSet(s embedded.RenderSet) embedded.RenderSet {
	var out embedded.RenderSet
	out.Add(s)
	for k, v := range out.Hooks {
		if len(v) == 0 {
			delete(out.Hooks, k)
		}
	}
	return out
}
