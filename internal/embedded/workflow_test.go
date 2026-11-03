package embedded

import (
	"os/exec"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestWorkflowPinNamesReusableWorkflow checks that WorkflowPin is a
// commit of this repository, reachable from HEAD, that has the reusable
// workflow the generated workflow calls.
func TestWorkflowPinNamesReusableWorkflow(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	shallow, err := exec.Command(git, "--no-optional-locks", "rev-parse", "--is-shallow-repository").Output()
	if err != nil {
		t.Skip("not a git checkout")
	}
	if strings.TrimSpace(string(shallow)) == "true" {
		t.Skip("shallow clone: the pinned commit may be missing")
	}
	if out, err := exec.Command(git, "--no-optional-locks", "cat-file", "-e", WorkflowPin+":.github/workflows/tripcord-pr.yml").CombinedOutput(); err != nil {
		t.Fatalf("%s has no .github/workflows/tripcord-pr.yml: %v %s", WorkflowPin, err, out)
	}
	if out, err := exec.Command(git, "--no-optional-locks", "merge-base", "--is-ancestor", WorkflowPin, "HEAD").CombinedOutput(); err != nil {
		t.Fatalf("%s is not an ancestor of HEAD: %v %s", WorkflowPin, err, out)
	}
}

func TestWorkflowShape(t *testing.T) {
	raw := Workflow()
	if strings.Contains(string(raw), "pull_request_target:") {
		t.Fatal("workflow uses pull_request_target")
	}
	var wf struct {
		On          map[string]any    `yaml:"on"`
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			Permissions map[string]string `yaml:"permissions"`
			Uses        string            `yaml:"uses"`
			With        map[string]string `yaml:"with"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if len(wf.On) != 1 || wf.On["pull_request"] == nil {
		t.Fatalf("on = %v", wf.On)
	}
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Fatalf("workflow permissions = %v", wf.Permissions)
	}
	scan := wf.Jobs["scan"]
	if scan.Uses != ReusableWorkflow || len(WorkflowPin) != 40 {
		t.Fatalf("uses = %q", scan.Uses)
	}
	want := map[string]string{"contents": "read", "pull-requests": "read", "security-events": "write"}
	for k, v := range want {
		if scan.Permissions[k] != v {
			t.Fatalf("job permissions = %v", scan.Permissions)
		}
	}
	if len(scan.Permissions) != len(want) || scan.With["fail-on"] != "high" {
		t.Fatalf("job = %+v", scan)
	}
}
