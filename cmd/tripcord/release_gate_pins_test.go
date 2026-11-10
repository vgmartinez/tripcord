package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/embedded"
)

var knownPinsBlock = regexp.MustCompile(`(?s)var KnownWorkflowPins = \[\]string\{(.*?)\}`)
var quotedSHA = regexp.MustCompile(`"([0-9a-f]{40})"`)

// knownPinsAt is KnownWorkflowPins as rev's internal/embedded/pins.go
// declares it, or nil when rev has no such file.
func knownPinsAt(t *testing.T, rev string) []string {
	t.Helper()
	src, err := gitShowAt(t, rev, "internal/embedded/pins.go")
	if err != nil {
		return nil
	}
	m := knownPinsBlock.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s:internal/embedded/pins.go declares no KnownWorkflowPins", rev)
	}
	var pins []string
	for _, q := range quotedSHA.FindAllStringSubmatch(m[1], -1) {
		pins = append(pins, q[1])
	}
	return pins
}

// TestReleaseGateKnownWorkflowPins keeps a release from vouching for a
// workflow pin that does not hold up: every KnownWorkflowPins entry, and
// WorkflowPin, is a commit on main at or after the embed check whose
// tripcord-pr.yml pins an action with the embed check and the base
// input; the list is in history order, never holds an excluded pin, and
// only grows relative to main. It runs only with TRIPCORD_RELEASE_GATE=1.
func TestReleaseGateKnownWorkflowPins(t *testing.T) {
	for _, pin := range embedded.KnownWorkflowPins {
		if slices.Contains(embedded.ExcludedWorkflowPins, pin) {
			t.Errorf("KnownWorkflowPins holds excluded pin %s", pin)
		}
	}
	if os.Getenv("TRIPCORD_RELEASE_GATE") != "1" {
		t.Log("release gate not requested; set TRIPCORD_RELEASE_GATE=1 to run it")
		return
	}
	root := filepath.Join("..", "..")
	if reason, _ := pinHistoryProblem(root); reason != "" {
		t.Fatalf("release gate: %s", reason)
	}
	ref := mainRef(t, root)
	all := append(slices.Clone(embedded.KnownWorkflowPins), embedded.WorkflowPin)
	for _, pin := range all {
		if err := gitRun(root, "cat-file", "-e", pin+"^{commit}"); err != nil {
			t.Errorf("release gate: pin %s is not in this clone", pin)
			continue
		}
		if err := gitRun(root, "merge-base", "--is-ancestor", pin, ref); err != nil {
			t.Errorf("release gate: pin %s is not on %s", pin, ref)
			continue
		}
		if err := gitRun(root, "merge-base", "--is-ancestor", embedCheckMinimum, pin); err != nil {
			t.Errorf("release gate: pin %s does not descend from the embed check %s", pin, embedCheckMinimum[:7])
			continue
		}
		workflow, err := gitShowAt(t, pin, ".github/workflows/tripcord-pr.yml")
		if err != nil {
			t.Errorf("release gate: pin %s has no tripcord-pr.yml: %v", pin, err)
			continue
		}
		for _, action := range actionPins(t, "tripcord-pr.yml@"+pin[:7], workflow) {
			check, err := gitShowAt(t, action, "internal/embedded/check.go")
			if err != nil || !strings.Contains(check, "func Check(") {
				t.Errorf("release gate: pin %s runs action %s, which has no embed check", pin, action[:7])
			}
			raw, err := gitShowAt(t, action, ".github/actions/tripcord/action.yml")
			var doc struct {
				Inputs map[string]any `yaml:"inputs"`
			}
			if err != nil || yaml.Unmarshal([]byte(raw), &doc) != nil || doc.Inputs["base"] == nil {
				t.Errorf("release gate: pin %s runs action %s, which has no base input", pin, action[:7])
			}
		}
	}
	for i := 1; i < len(all); i++ {
		if err := gitRun(root, "merge-base", "--is-ancestor", all[i-1], all[i]); err != nil {
			t.Errorf("release gate: KnownWorkflowPins is not in history order: %s is not an ancestor of %s", all[i-1][:7], all[i][:7])
		}
	}
	if onMain := knownPinsAt(t, ref); len(onMain) > len(embedded.KnownWorkflowPins) || !slices.Equal(onMain, embedded.KnownWorkflowPins[:len(onMain)]) {
		t.Errorf("release gate: KnownWorkflowPins %v does not extend %s's %v: entries are only appended", embedded.KnownWorkflowPins, ref, onMain)
	}
}
