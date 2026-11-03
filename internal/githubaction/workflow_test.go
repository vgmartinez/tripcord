package githubaction_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	workflowCheckout  = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	workflowScript    = "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
	workflowAction    = "vgmartinez/tripcord/.github/actions/tripcord@141db48dc10a3df719b20cf2f357e184d629c046"
	workflowActionPin = workflowAction + " # main@141db48"
)

func TestTripcordWorkflowContract(t *testing.T) {
	scan := readWorkflow(t, "tripcord-pr.yml")
	comment := readWorkflow(t, "tripcord-pr-comment.yml")
	scanScript, scanWith := checkOneJobWorkflow(t, scan, map[string]string{
		"contents":        "read",
		"pull-requests":   "read",
		"security-events": "write",
	})
	commentScript, commentWith := checkOneJobWorkflow(t, comment, map[string]string{
		"contents":        "read",
		"pull-requests":   "write",
		"security-events": "write",
	})
	if scanScript != commentScript {
		t.Fatal("review scripts differ between the scan and comment workflows")
	}
	checkReviewsScript(t, scanScript)
	if scanWith != commentWith {
		t.Fatal("the workflows pass different inputs to the action")
	}
}

func TestDocumentedCallerPermissionsCoverJobs(t *testing.T) {
	root := filepath.Join("..", "..")
	docs, err := os.ReadFile(filepath.Join(root, "docs", "github-action.md"))
	if err != nil {
		t.Fatal(err)
	}
	docCallers := callersOf(t, string(docs))
	for _, name := range []string{"tripcord-pr.yml", "tripcord-pr-comment.yml"} {
		jobs := nestedJobPermissions(t, root, name, map[string]bool{})
		if len(jobs) == 0 {
			t.Fatalf("%s has no jobs", name)
		}
		examples := docCallers[name]
		if len(examples) == 0 {
			t.Fatalf("docs have no caller for %s", name)
		}
		want := maxPermissions(jobs)
		for _, example := range examples {
			for id, perms := range jobs {
				if gaps := permissionGaps(example, perms); len(gaps) != 0 {
					t.Errorf("documented caller of %s does not cover job %s: %s", name, id, strings.Join(gaps, "; "))
				}
			}
			if !samePerms(example, want) {
				t.Errorf("documented caller of %s = %v, want the exact permissions %v", name, example, want)
			}
		}
	}

}

type workflowFile struct {
	text string
	jobs []workflowJob
}

type workflowJob struct {
	id     string
	perms  *yaml.Node
	ifNode *yaml.Node
	with   *yaml.Node
	uses   []useSite
}

type useSite struct {
	uses  string
	perms *yaml.Node
}

func readWorkflow(t *testing.T, name string) workflowFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return workflowFile{text: string(data), jobs: jobsOf(t, &root)}
}

func checkOneJobWorkflow(t *testing.T, wf workflowFile, wantPerms map[string]string) (string, string) {
	t.Helper()
	text := wf.text
	if strings.Contains(text, "pull_request_target") {
		t.Fatal("workflow uses pull_request_target")
	}
	if strings.Contains(text, "secrets: inherit") {
		t.Fatal("workflow inherits secrets")
	}
	if !strings.Contains(text, workflowActionPin) {
		t.Fatal("action pin is missing # main@141db48")
	}
	for _, version := range []string{"# v7.0.1", "# v9.0.0"} {
		if !strings.Contains(text, version) {
			t.Errorf("workflow is missing pin comment %s", version)
		}
	}

	var root yaml.Node
	if err := yaml.Unmarshal([]byte(text), &root); err != nil {
		t.Fatal(err)
	}
	doc := mapping(t, &root)
	if got := permMap(t, doc["permissions"]); !samePerms(got, wantPerms) {
		t.Fatalf("workflow permissions = %v, want %v", got, wantPerms)
	}
	triggers := mapping(t, doc["on"])
	if len(triggers) != 1 || triggers["workflow_call"] == nil {
		t.Fatalf("triggers = %v, want only workflow_call", keys(triggers))
	}
	call := mapping(t, triggers["workflow_call"])
	inputs := mapping(t, call["inputs"])
	wantDefaults := actionInputDefaults(t)
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
	for _, name := range []string{"is_agent", "agents"} {
		out := mapping(t, outputs[name])
		got := scalar(out["value"])
		if got != "${{ jobs.scan.outputs."+name+" }}" {
			t.Errorf("output %s = %q", name, got)
		}
	}
	if len(outputs) != 2 {
		t.Fatalf("outputs = %v, want is_agent and agents", keys(outputs))
	}

	jobs := mapping(t, doc["jobs"])
	if len(jobs) != 1 || jobs["scan"] == nil {
		t.Fatalf("jobs = %v, want one job named scan", keys(jobs))
	}
	job := mapping(t, jobs["scan"])
	if job["if"] != nil {
		t.Fatal("scan job has an if condition; permissions would still be required when it is skipped")
	}
	if got := permMap(t, job["permissions"]); !samePerms(got, wantPerms) {
		t.Fatalf("job permissions = %v, want %v", got, wantPerms)
	}

	pin := regexp.MustCompile(`^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$`)
	steps := seq(t, job["steps"])
	if len(steps) != 3 {
		t.Fatalf("scan has %d steps, want checkout, reviews, and the action", len(steps))
	}
	checkoutStep := mapping(t, steps[0])
	if scalar(checkoutStep["uses"]) != workflowCheckout {
		t.Fatalf("checkout uses %q", scalar(checkoutStep["uses"]))
	}
	checkoutWith := mapping(t, checkoutStep["with"])
	if scalar(checkoutWith["fetch-depth"]) != "0" {
		t.Fatalf("fetch-depth = %q, want 0", scalar(checkoutWith["fetch-depth"]))
	}
	if scalar(checkoutWith["persist-credentials"]) != "false" {
		t.Fatal("checkout persists credentials")
	}

	reviewsStep := mapping(t, steps[1])
	if scalar(reviewsStep["id"]) != "reviews" {
		t.Fatalf("reviews step id = %q", scalar(reviewsStep["id"]))
	}
	if scalar(reviewsStep["uses"]) != workflowScript {
		t.Fatalf("reviews uses %q", scalar(reviewsStep["uses"]))
	}
	script := scalar(mapping(t, reviewsStep["with"])["script"])
	if script == "" {
		t.Fatal("reviews step has no script")
	}

	actionStep := mapping(t, steps[2])
	if scalar(actionStep["uses"]) != workflowAction {
		t.Fatalf("action uses %q", scalar(actionStep["uses"]))
	}
	if scalar(actionStep["id"]) != "tripcord" {
		t.Fatalf("action id = %q", scalar(actionStep["id"]))
	}
	if actionStep["continue-on-error"] != nil {
		t.Fatal("action step continues on error, so a TC-CFG-014 denial would not fail the job")
	}
	actionWith := mapping(t, actionStep["with"])
	for _, name := range []string{"ref", "binary", "path", "fail-on", "upload-sarif", "comment", "github-token"} {
		got := scalar(actionWith[name])
		if !strings.Contains(got, "inputs."+name) {
			t.Errorf("action input %s = %q, want the workflow input", name, got)
		}
	}
	if scalar(actionWith["github-token"]) != "${{ inputs.github-token != '' && inputs.github-token || github.token }}" {
		t.Fatalf("github-token = %q", scalar(actionWith["github-token"]))
	}
	if scalar(actionWith["reviews-file"]) != "${{ steps.reviews.outputs.reviews-file }}" {
		t.Fatalf("reviews-file = %q", scalar(actionWith["reviews-file"]))
	}
	if strings.Contains(text, "assert-fixture") || strings.Contains(text, "git init") || strings.Contains(text, "mkdir -p") {
		t.Fatal("workflow still plants a fixture or creates the scan directory")
	}

	for _, step := range []map[string]*yaml.Node{checkoutStep, reviewsStep, actionStep} {
		if strings.Contains(scalar(step["run"]), "${{") {
			t.Fatal("step interpolates an expression into run")
		}
		uses := scalar(step["uses"])
		if uses != "" && !pin.MatchString(uses) {
			t.Errorf("uses unpinned action %q", uses)
		}
	}
	return script, encodeScalars(actionWith)
}

func actionInputDefaults(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "actions", "tripcord", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]string, len(action.Inputs))
	for name, input := range action.Inputs {
		if name == "reviews-file" {
			continue
		}
		out[name] = input.Default
	}
	// A workflow_call default cannot be an expression. An empty token
	// falls through to github.token at the action step.
	out["github-token"] = ""
	return out
}

func TestCICallerUsesPinnedRemoteAction(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, gone := range []string{"assert-fixture", "tripcord-ci-fixture", "git init", "./.github/workflows/tripcord-pr.yml"} {
		if strings.Contains(text, gone) {
			t.Fatalf("ci.yml still contains %s", gone)
		}
	}
	if !strings.Contains(text, workflowActionPin) {
		t.Fatal("caller is not pinned to main@141db48")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	job := mapping(t, mapping(t, mapping(t, &root)["jobs"])["tripcord-caller"])
	if scalar(job["if"]) != "github.event_name == 'pull_request'" {
		t.Fatalf("caller if = %q, want pull_request", scalar(job["if"]))
	}
	wantPerms := map[string]string{
		"contents":      "read",
		"pull-requests": "read",
	}
	if got := permMap(t, job["permissions"]); !samePerms(got, wantPerms) {
		t.Fatalf("caller permissions = %v, want %v", got, wantPerms)
	}
	var actionStep, assertStep map[string]*yaml.Node
	sawReviews := false
	for _, step := range seq(t, job["steps"]) {
		parsed := mapping(t, step)
		switch scalar(parsed["id"]) {
		case "reviews":
			sawReviews = true
			checkReviewsScript(t, scalar(mapping(t, parsed["with"])["script"]))
		case "tripcord":
			actionStep = parsed
		}
		if scalar(parsed["name"]) == "Assert remote scan" {
			assertStep = parsed
		}
	}
	if !sawReviews || actionStep == nil || assertStep == nil {
		t.Fatal("caller is missing reviews, the remote action, or the assertion")
	}
	if scalar(actionStep["uses"]) != workflowAction {
		t.Fatalf("caller uses %q", scalar(actionStep["uses"]))
	}
	if scalar(actionStep["continue-on-error"]) != "true" {
		t.Fatal("caller action does not continue on error")
	}
	with := mapping(t, actionStep["with"])
	if scalar(with["path"]) != "testdata/ci-caller" {
		t.Fatalf("path = %q, want testdata/ci-caller", scalar(with["path"]))
	}
	if scalar(with["reviews-file"]) != "${{ steps.reviews.outputs.reviews-file }}" {
		t.Fatalf("reviews-file = %q", scalar(with["reviews-file"]))
	}
	if scalar(with["upload-sarif"]) != "false" {
		t.Fatalf("upload-sarif = %q, want false", scalar(with["upload-sarif"]))
	}
	run := scalar(assertStep["run"])
	for _, want := range []string{
		"outcome is not failure",
		"scan exit-code is not 1",
		"TC-CFG-001",
		"testdata/ci-caller/",
		"0|1",
		"no is_agent output",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("assertion missing %s", want)
		}
	}
}

func TestActionlintJobIsChecksumPinned(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	job := mapping(t, mapping(t, mapping(t, &root)["jobs"])["actionlint"])
	if got := permMap(t, job["permissions"]); !samePerms(got, map[string]string{"contents": "read"}) {
		t.Fatalf("actionlint permissions = %v, want contents: read", got)
	}
	steps := seq(t, job["steps"])
	if len(steps) != 2 {
		t.Fatalf("actionlint has %d steps, want checkout and the linter", len(steps))
	}
	checkout := mapping(t, steps[0])
	if scalar(checkout["uses"]) != workflowCheckout {
		t.Fatalf("checkout uses %q", scalar(checkout["uses"]))
	}
	if scalar(mapping(t, checkout["with"])["persist-credentials"]) != "false" {
		t.Fatal("actionlint checkout persists credentials")
	}
	run := scalar(mapping(t, steps[1])["run"])
	for _, want := range []string{
		"https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
		"8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
		"sha256sum -c -",
		"actionlint",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("actionlint step missing %s", want)
		}
	}
	if strings.Contains(run, "${{") {
		t.Fatal("actionlint step interpolates an expression into run")
	}
}

func TestPreCommitHookContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks []map[string]any
	if err := yaml.Unmarshal(data, &hooks); err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 {
		t.Fatalf("hooks = %d, want 1", len(hooks))
	}
	hook := hooks[0]
	for name, want := range map[string]string{
		"id":             "tripcord-config",
		"language":       "golang",
		"entry":          "tripcord scan --staged",
		"pass_filenames": "true",
		"require_serial": "true",
		"always_run":     "true",
	} {
		got := fmt.Sprint(hook[name])
		if got != want {
			t.Errorf("hook %s = %q, want %q", name, got, want)
		}
	}
	// Tripcord, not a pre-commit files regex, decides what counts as
	// configuration (a referenced or symlinked file can matter without
	// its own path or extension looking like config). The hook must not
	// carry a files regex. types is explicitly empty: the default [file]
	// is an AND filter and would drop a symlink (identify tags it
	// symlink, not file) even with types_or set. types_or then keeps a
	// regular file or a symlink, so --all-files passes both.
	if _, ok := hook["files"]; ok {
		t.Errorf("hook has files = %v, want no files regex", hook["files"])
	}
	types, ok := hook["types"].([]any)
	if !ok || len(types) != 0 {
		t.Errorf("hook types = %#v, want an empty list", hook["types"])
	}
	gotOr, ok := hook["types_or"].([]any)
	wantOr := []string{"file", "symlink"}
	if !ok || len(gotOr) != len(wantOr) {
		t.Errorf("hook types_or = %#v, want %v", hook["types_or"], wantOr)
	} else {
		for i, want := range wantOr {
			if fmt.Sprint(gotOr[i]) != want {
				t.Errorf("hook types_or[%d] = %v, want %s", i, gotOr[i], want)
			}
		}
	}
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "pre-commit.md"))
	if err != nil {
		t.Fatal(err)
	}
	pin := regexp.MustCompile(`rev: ([0-9a-f]{40}) # main@([0-9a-f]{7,40})`)
	match := pin.FindStringSubmatch(string(docs))
	if match == nil {
		t.Fatal("docs pre-commit example does not pin rev to a full SHA with a main comment")
	}
	if !strings.HasPrefix(match[1], match[2]) {
		t.Fatalf("docs pin %s does not match comment %s", match[1], match[2])
	}
	// The pin must be a commit that actually ships the hook. 6944e28 is
	// in history and has no .pre-commit-hooks.yaml, so this fails closed
	// on that old pin. A local shallow clone that does not have the
	// commit object skips. CI must fail instead, so a depth-1 checkout
	// cannot hide a stale pin.
	requirePinnedHookManifest(t, filepath.Join("..", ".."), match[1])
}

// ciRequiresPinnedObject reports whether a missing pin must fail the
// test. GitHub Actions sets CI and GITHUB_ACTIONS; either being
// non-empty means this is CI, and the checkout needs fetch-depth: 0.
func ciRequiresPinnedObject(getenv func(string) string) bool {
	return getenv("CI") != "" || getenv("GITHUB_ACTIONS") != ""
}

// requirePinnedHookManifest checks that sha's tree contains
// .pre-commit-hooks.yaml and that the manifest declares tripcord-config.
// A missing commit object skips on a local run and fails in CI.
func requirePinnedHookManifest(t *testing.T, root, sha string) {
	t.Helper()
	if !gitObjectExists(t, root, sha) {
		if ciRequiresPinnedObject(os.Getenv) {
			t.Fatalf("pinned rev %s is not in the local git object database; the checkout needs fetch-depth: 0", sha)
		}
		t.Skipf("pinned rev %s is not in the local git object database; skipping the .pre-commit-hooks.yaml check (shallow clone)", sha)
	}
	if !gitObjectExists(t, root, sha+":.pre-commit-hooks.yaml") {
		t.Fatalf("pinned rev %s does not contain .pre-commit-hooks.yaml", sha)
	}
	show := exec.Command("git", "--no-pager", "show", sha+":.pre-commit-hooks.yaml")
	show.Dir = root
	body, err := show.Output()
	if err != nil {
		t.Fatalf("git show %s:.pre-commit-hooks.yaml: %v", sha, err)
	}
	var hooks []map[string]any
	if err := yaml.Unmarshal(body, &hooks); err != nil {
		t.Fatalf("pinned .pre-commit-hooks.yaml: %v", err)
	}
	for _, hook := range hooks {
		if fmt.Sprint(hook["id"]) == "tripcord-config" {
			return
		}
	}
	t.Fatalf("pinned rev %s .pre-commit-hooks.yaml has no tripcord-config hook", sha)
}

// gitObjectExists reports whether git cat-file -e accepts spec. A missing
// git binary fails the test; a missing object returns false.
func gitObjectExists(t *testing.T, root, spec string) bool {
	t.Helper()
	cmd := exec.Command("git", "cat-file", "-e", spec)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true
	}
	if _, ok := err.(*exec.ExitError); ok {
		return false
	}
	t.Fatalf("git cat-file -e %s: %v\n%s", spec, err, out)
	return false
}

func TestCIRequiresPinnedObject(t *testing.T) {
	getenv := func(string) string { return "" }
	if ciRequiresPinnedObject(getenv) {
		t.Fatal("empty environment wants a local skip")
	}
	for _, key := range []string{"CI", "GITHUB_ACTIONS"} {
		set := key
		getenv = func(got string) string {
			if got == set {
				return "true"
			}
			return ""
		}
		if !ciRequiresPinnedObject(getenv) {
			t.Fatalf("%s non-empty wants the checkout to fail", key)
		}
	}
}

func checkReviewsScript(t *testing.T, script string) {
	t.Helper()
	for _, want := range []string{
		"github.paginate",
		"github.rest.pulls.listReviews",
		"context.repo",
		"context.payload.pull_request",
		"pull_number: pullRequest.number",
		"process.env.RUNNER_TEMP",
		"JSON.stringify(reviews)",
		"core.setOutput",
		"try {",
		"catch {",
		`core.warning("Tripcord reviews skipped: this event has no pull request.")`,
		`core.warning("Tripcord reviews skipped: unable to read pull request reviews.")`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("reviews script missing %s", want)
		}
	}
	for _, forbidden := range []string{
		"${{",
		"console.",
		"core.info",
		"core.debug",
		"core.notice",
		".body",
		"error.message",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("reviews script contains %s", forbidden)
		}
	}
}

func nestedJobPermissions(t *testing.T, root, name string, seen map[string]bool) map[string]map[string]string {
	t.Helper()
	if seen[name] {
		t.Fatalf("workflow cycle at %s", name)
	}
	seen[name] = true
	data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var docNode yaml.Node
	if err := yaml.Unmarshal(data, &docNode); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	doc := mapping(t, &docNode)
	workflowPerms := doc["permissions"]
	out := map[string]map[string]string{}
	for id, node := range mapping(t, doc["jobs"]) {
		job := mapping(t, node)
		perms := job["permissions"]
		if perms == nil {
			perms = workflowPerms
		}
		if perms == nil {
			t.Fatalf("%s job %s has no permissions", name, id)
		}
		out[name+":"+id] = permMap(t, perms)
		for _, site := range collectUses(t, node) {
			next := calledWorkflow(site.uses)
			if next == "" || !strings.HasPrefix(site.uses, "./.github/workflows/") {
				continue
			}
			for childID, child := range nestedJobPermissions(t, root, next, seen) {
				out[childID] = child
			}
		}
	}
	return out
}

func callersOf(t *testing.T, text string) map[string][]map[string]string {
	t.Helper()
	out := map[string][]map[string]string{}
	for _, fence := range yamlFences(text) {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(fence), &node); err != nil {
			t.Fatalf("parse documented yaml: %v\n%s", err, fence)
		}
		for _, site := range collectUses(t, &node) {
			name := calledWorkflow(site.uses)
			if name != "tripcord-pr.yml" && name != "tripcord-pr-comment.yml" {
				continue
			}
			if site.perms == nil {
				t.Fatalf("documented caller of %s has no permissions:\n%s", name, fence)
			}
			out[name] = append(out[name], permMap(t, site.perms))
		}
	}
	return out
}

func collectUses(t *testing.T, n *yaml.Node) []useSite {
	t.Helper()
	if n == nil {
		return nil
	}
	var out []useSite
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			out = append(out, collectUses(t, child)...)
		}
	case yaml.MappingNode:
		var uses string
		var perms *yaml.Node
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i].Value
			val := n.Content[i+1]
			switch key {
			case "uses":
				uses = scalar(val)
			case "permissions":
				perms = val
			}
			out = append(out, collectUses(t, val)...)
		}
		if uses != "" {
			out = append(out, useSite{uses: uses, perms: perms})
		}
	case yaml.ScalarNode, yaml.AliasNode:
		return out
	default:
		t.Fatalf("yaml kind %d", n.Kind)
		return nil
	}
	return out
}

func jobsOf(t *testing.T, root *yaml.Node) []workflowJob {
	t.Helper()
	doc := mapping(t, root)
	var jobs []workflowJob
	for id, node := range mapping(t, doc["jobs"]) {
		job := mapping(t, node)
		jobs = append(jobs, workflowJob{
			id:     id,
			perms:  job["permissions"],
			ifNode: job["if"],
			with:   job["with"],
			uses:   collectUses(t, node),
		})
	}
	return jobs
}

func calledWorkflow(uses string) string {
	const marker = ".github/workflows/"
	i := strings.LastIndex(uses, marker)
	if i < 0 {
		return ""
	}
	name := uses[i+len(marker):]
	if at := strings.IndexByte(name, '@'); at >= 0 {
		name = name[:at]
	}
	if name != "tripcord-pr.yml" && name != "tripcord-pr-comment.yml" {
		return ""
	}
	return name
}

func permMap(t *testing.T, n *yaml.Node) map[string]string {
	t.Helper()
	raw := mapping(t, n)
	out := make(map[string]string, len(raw))
	for name, node := range raw {
		out[name] = scalar(node)
		if permRank(out[name]) < 0 {
			t.Fatalf("permission %s = %q", name, out[name])
		}
	}
	return out
}

func permRank(v string) int {
	switch v {
	case "", "none":
		return 0
	case "read":
		return 1
	case "write":
		return 2
	default:
		return -1
	}
}

func maxPermissions(jobs map[string]map[string]string) map[string]string {
	out := map[string]string{}
	for _, perms := range jobs {
		for scope, value := range perms {
			if permRank(value) > permRank(out[scope]) {
				out[scope] = value
			}
		}
	}
	return out
}

func permissionGaps(caller, job map[string]string) []string {
	var gaps []string
	for scope, want := range job {
		if permRank(caller[scope]) < permRank(want) {
			gaps = append(gaps, fmt.Sprintf("%s caller %q job %q", scope, caller[scope], want))
		}
	}
	sort.Strings(gaps)
	return gaps
}

func samePerms(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for name, value := range want {
		if got[name] != value {
			return false
		}
	}
	return true
}

func yamlFences(text string) []string {
	var out []string
	rest := text
	for {
		i := strings.Index(rest, "```yaml\n")
		if i < 0 {
			return out
		}
		rest = rest[i+len("```yaml\n"):]
		j := strings.Index(rest, "```")
		if j < 0 {
			return out
		}
		out = append(out, rest[:j])
		rest = rest[j+3:]
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
