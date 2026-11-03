package main

import (
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/project"
)

var actionPinPattern = regexp.MustCompile(`uses: ` + regexp.QuoteMeta(project.Repository) + `/\.github/actions/tripcord@([0-9a-f]{40})\b`)

// actionPins is every composite action commit workflow pins.
func actionPins(t *testing.T, name, workflow string) []string {
	t.Helper()
	var pins []string
	for _, m := range actionPinPattern.FindAllStringSubmatch(workflow, -1) {
		pins = append(pins, m[1])
	}
	if len(pins) == 0 {
		t.Fatalf("%s pins no %s/.github/actions/tripcord commit", name, project.Repository)
	}
	return pins
}

func gitShowAt(t *testing.T, rev, rel string) (string, error) {
	t.Helper()
	out, err := exec.Command("git", "-C", filepath.Join("..", ".."), "--no-optional-locks", "show", rev+":"+rel).Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "", errors.New(strings.TrimSpace(string(exit.Stderr)))
	}
	return string(out), err
}

// TestReleaseGatePinnedActionHasEmbedCheck keeps a release from shipping
// workflows whose pinned action cannot see what this release's embed
// relies on: the TC-CFG-016 embed check (internal/embedded) and the
// action's base input, which makes the scan compare a pull request with
// its base. Two pins lead to the action: the reusable workflow commit
// the generated tripcord.yml calls (embedded.WorkflowPin), and the
// action commit this tree's reusable workflows call. Both must be
// re-pinned after this change merges. It runs only with
// TRIPCORD_RELEASE_GATE=1, and needs those commits in the clone.
func TestReleaseGatePinnedActionHasEmbedCheck(t *testing.T) {
	pins := map[string][]string{}
	for _, name := range []string{"tripcord-pr.yml", "tripcord-pr-comment.yml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, pin := range actionPins(t, name, string(raw)) {
			pins[pin] = append(pins[pin], "this tree's "+name)
		}
	}
	if os.Getenv("TRIPCORD_RELEASE_GATE") != "1" {
		t.Log("release gate not requested; set TRIPCORD_RELEASE_GATE=1 to run it")
		return
	}
	template, err := gitShowAt(t, embedded.WorkflowPin, ".github/workflows/tripcord-pr.yml")
	if err != nil {
		t.Fatalf("release gate: the generated tripcord.yml calls tripcord-pr.yml@%s, which this clone cannot read: %v", embedded.WorkflowPin[:7], err)
	}
	for _, pin := range actionPins(t, "tripcord-pr.yml@"+embedded.WorkflowPin[:7], template) {
		pins[pin] = append(pins[pin], "the generated tripcord.yml (through tripcord-pr.yml@"+embedded.WorkflowPin[:7]+")")
	}
	for _, pin := range slices.Sorted(maps.Keys(pins)) {
		via := strings.Join(slices.Compact(slices.Sorted(slices.Values(pins[pin]))), " and ")
		action, err := gitShowAt(t, pin, ".github/actions/tripcord/action.yml")
		if err != nil {
			t.Errorf("release gate: the action at %s, pinned by %s, cannot be read in this clone: %v", pin[:7], via, err)
			continue
		}
		var doc struct {
			Inputs map[string]any `yaml:"inputs"`
		}
		if err := yaml.Unmarshal([]byte(action), &doc); err != nil {
			t.Errorf("release gate: action.yml@%s: %v", pin[:7], err)
			continue
		}
		if _, ok := doc.Inputs["base"]; !ok {
			t.Errorf("release gate: the action at %s, pinned by %s, has no base input: pull requests are scanned without the base comparison", pin[:7], via)
		}
		if check, err := gitShowAt(t, pin, "internal/embedded/check.go"); err != nil || !strings.Contains(check, "func Check(") {
			t.Errorf("release gate: the action at %s, pinned by %s, builds a tripcord without the embed check (TC-CFG-016)", pin[:7], via)
		}
	}
}
