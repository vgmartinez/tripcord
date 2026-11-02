package githubaction_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestTripcordWorkflowContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "tripcord-pr.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "pull_request_target") {
		t.Fatal("workflow uses pull_request_target")
	}
	if strings.Contains(text, "secrets: inherit") {
		t.Fatal("workflow inherits secrets")
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	doc := mapping(t, &root)
	if got := mapping(t, doc["permissions"]); len(got) != 0 {
		t.Fatalf("workflow-level permissions = %v, want none so jobs do not inherit a broader token", keys(got))
	}
	triggers := mapping(t, doc["on"])
	if len(triggers) != 1 || triggers["workflow_call"] == nil {
		t.Fatalf("triggers = %v, want only workflow_call", keys(triggers))
	}
	call := mapping(t, triggers["workflow_call"])
	inputs := mapping(t, call["inputs"])
	wantDefaults := map[string]string{
		"ref":          "",
		"binary":       "",
		"path":         ".",
		"fail-on":      "",
		"upload-sarif": "true",
		"comment":      "false",
		"github-token": "",
	}
	if len(inputs) != len(wantDefaults) {
		t.Fatalf("inputs = %v, want %v", keys(inputs), keysOf(wantDefaults))
	}
	for name, want := range wantDefaults {
		input := mapping(t, inputs[name])
		got := ""
		if def := input["default"]; def != nil {
			got = def.Value
		}
		if got != want {
			t.Errorf("input %s default = %q, want %q", name, got, want)
		}
		if strings.Contains(got, "${{") {
			t.Errorf("input %s default interpolates an expression", name)
		}
		if scalar(input["type"]) != "string" {
			t.Errorf("input %s type = %q, want string", name, scalar(input["type"]))
		}
	}

	outputs := mapping(t, call["outputs"])
	outputValue := map[string]string{}
	for _, name := range []string{"is_agent", "agents"} {
		out := mapping(t, outputs[name])
		if out["value"] == nil || out["value"].Value == "" {
			t.Errorf("workflow does not expose output %s", name)
		}
		outputValue[name] = scalar(out["value"])
	}
	if len(outputs) != 2 {
		t.Fatalf("outputs = %v, want is_agent and agents", keys(outputs))
	}

	const (
		checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
		action   = "vgmartinez/tripcord/.github/actions/tripcord@276967b41056547c363b4d52378dbffaa7d33d95"
	)
	pin := regexp.MustCompile(`^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$`)
	jobs := mapping(t, doc["jobs"])
	if len(jobs) != 4 {
		t.Fatalf("jobs = %v, want the four permission combinations", keys(jobs))
	}
	seenIf := map[string]bool{}
	var withText string
	for id, node := range jobs {
		job := mapping(t, node)
		ifExpr := ""
		if job["if"] != nil {
			ifExpr = job["if"].Value
		}
		seenIf[ifExpr] = true
		if !strings.Contains(outputValue["is_agent"], "jobs."+id+".outputs.is_agent") {
			t.Errorf("is_agent output omits job %s", id)
		}
		if !strings.Contains(outputValue["agents"], "jobs."+id+".outputs.agents") {
			t.Errorf("agents output omits job %s", id)
		}
		checkWorkflowPerms(t, id, ifExpr, mapping(t, job["permissions"]))
		steps := seq(t, job["steps"])
		if len(steps) != 2 {
			t.Fatalf("job %s has %d steps, want checkout and the action", id, len(steps))
		}
		checkoutStep := mapping(t, steps[0])
		if checkoutStep["uses"] == nil || checkoutStep["uses"].Value != checkout {
			t.Fatalf("job %s checkout uses %v, want %s", id, scalar(checkoutStep["uses"]), checkout)
		}
		checkoutWith := mapping(t, checkoutStep["with"])
		if scalar(checkoutWith["fetch-depth"]) != "0" {
			t.Fatalf("job %s fetch-depth = %q, want 0", id, scalar(checkoutWith["fetch-depth"]))
		}
		if scalar(checkoutWith["persist-credentials"]) != "false" {
			t.Fatalf("job %s persists checkout credentials", id)
		}
		actionStep := mapping(t, steps[1])
		if actionStep["uses"] == nil || actionStep["uses"].Value != action {
			t.Fatalf("job %s action uses %v, want %s", id, scalar(actionStep["uses"]), action)
		}
		if scalar(actionStep["id"]) != "tripcord" {
			t.Fatalf("job %s action id = %q, want tripcord", id, scalar(actionStep["id"]))
		}
		actionWith := mapping(t, actionStep["with"])
		for name := range wantDefaults {
			got := scalar(actionWith[name])
			if !strings.Contains(got, "inputs."+name) {
				t.Errorf("job %s does not pass input %s through to the action: %q", id, name, got)
			}
		}
		if scalar(actionWith["github-token"]) != "${{ inputs.github-token != '' && inputs.github-token || github.token }}" {
			t.Fatalf("job %s github-token = %q", id, scalar(actionWith["github-token"]))
		}
		encoded := encodeScalars(actionWith)
		if withText == "" {
			withText = encoded
		} else if encoded != withText {
			t.Fatalf("job %s passes different inputs than the other jobs", id)
		}
		for _, step := range []map[string]*yaml.Node{checkoutStep, actionStep} {
			run := scalar(step["run"])
			if strings.Contains(run, "${{") {
				t.Fatalf("job %s interpolates an expression into run", id)
			}
			uses := scalar(step["uses"])
			if uses != "" && !pin.MatchString(uses) {
				t.Errorf("job %s uses unpinned action %q", id, uses)
			}
		}
	}
	for _, want := range []string{
		"inputs.upload-sarif != 'true' && inputs.comment != 'true'",
		"inputs.upload-sarif != 'true' && inputs.comment == 'true'",
		"inputs.upload-sarif == 'true' && inputs.comment != 'true'",
		"inputs.upload-sarif == 'true' && inputs.comment == 'true'",
	} {
		if !seenIf[want] {
			t.Errorf("missing job condition %s", want)
		}
	}
	for _, version := range []string{"# v7.0.1"} {
		if !strings.Contains(text, version) {
			t.Errorf("workflow is missing pin comment %s", version)
		}
	}
}

func checkWorkflowPerms(t *testing.T, id, ifExpr string, perms map[string]*yaml.Node) {
	t.Helper()
	sarif := strings.Contains(ifExpr, "inputs.upload-sarif == 'true'")
	comment := strings.Contains(ifExpr, "inputs.comment == 'true'")
	allowed := map[string]bool{"contents": true, "pull-requests": true, "security-events": true}
	for name := range perms {
		if !allowed[name] {
			t.Errorf("job %s grants %s, which is outside contents, pull-requests, and security-events", id, name)
		}
	}
	if scalar(perms["contents"]) != "read" {
		t.Errorf("job %s contents = %q, want read", id, scalar(perms["contents"]))
	}
	switch {
	case sarif && scalar(perms["security-events"]) != "write":
		t.Errorf("job %s enables SARIF without security-events: write", id)
	case !sarif && perms["security-events"] != nil:
		t.Errorf("job %s grants security-events while SARIF upload is off", id)
	}
	switch {
	case comment && scalar(perms["pull-requests"]) != "write":
		t.Errorf("job %s comments without pull-requests: write", id)
	case !comment && scalar(perms["pull-requests"]) != "read":
		t.Errorf("job %s pull-requests = %q, want read when comment is off", id, scalar(perms["pull-requests"]))
	}
}

func mapping(t *testing.T, n *yaml.Node) map[string]*yaml.Node {
	t.Helper()
	if n == nil {
		t.Fatal("missing YAML node")
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) != 1 {
			t.Fatalf("document has %d children", len(n.Content))
		}
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode || len(n.Content)%2 != 0 {
		t.Fatalf("want mapping, got kind %d", n.Kind)
	}
	out := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1]
	}
	return out
}

func seq(t *testing.T, n *yaml.Node) []*yaml.Node {
	t.Helper()
	if n == nil || n.Kind != yaml.SequenceNode {
		t.Fatal("want sequence")
	}
	return n.Content
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func keys(m map[string]*yaml.Node) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func encodeScalars(m map[string]*yaml.Node) string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(scalar(m[name]))
		b.WriteByte('\n')
	}
	return b.String()
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
