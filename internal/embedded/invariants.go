package embedded

import (
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/project"
)

// Invariant ids: the properties every Tripcord version keeps in what
// init writes, so a scanner of any version can hold an embed to them.
// An invariant may be tightened in a later version but never loosened:
// a loosened one makes every older scanner flag the newer embed.
// TestInvariantsHoldForInit checks init's own output against all of them.
const (
	InvariantShebang       = "B1" // #!/bin/sh, then set -eu before any command
	InvariantVersion       = "B2" // one TRIPCORD_VERSION, the embed.json version
	InvariantSums          = "B3" // one arm per pinned platform, no other 64-hex literal
	InvariantChecksumGate  = "B4" // the checksum comparison fails the run
	InvariantGuardEntry    = "H1" // the pre-tool entry runs bootstrap.sh hook
	InvariantClaudeBlock   = "H2" // Claude: matcher *, onFailure block
	InvariantCursorClosed  = "H3" // Cursor: failClosed true, no narrowing matcher
	InvariantCopilotShape  = "H4" // Copilot: command, cwd ., timeoutSec >= 60
	InvariantOnFailure     = "H5" // the guard passes --on-failure block
	InvariantTrigger       = "W1" // pull_request, never pull_request_target or workflow_run
	InvariantPaths         = "W2" // the paths filter keeps the embed's own paths
	InvariantReusableJob   = "W3" // exactly one job: the reusable call, no steps, if, or secrets
	InvariantFailOn        = "W4" // fail-on low, medium, or high
	InvariantInputs        = "W5" // with holds only fail-on
	InvariantPermissions   = "W6" // workflow and job permissions are the generated set
	InvariantSetupStep     = "S1" // the setup step runs install, unconditionally
	InvariantWriterWitness = "witness"
)

// Invariants lists every invariant id. It only grows.
var Invariants = []string{
	InvariantShebang, InvariantVersion, InvariantSums, InvariantChecksumGate,
	InvariantGuardEntry, InvariantClaudeBlock, InvariantCursorClosed, InvariantCopilotShape, InvariantOnFailure,
	InvariantTrigger, InvariantPaths, InvariantReusableJob, InvariantFailOn, InvariantInputs, InvariantPermissions,
	InvariantSetupStep,
}

const copilotMinTimeoutSec = 60

var hex64 = regexp.MustCompile(`[0-9a-f]{64}`)

// bootstrapInvariant is the first invariant bootstrap.sh breaks, or "".
// m is nil when embed.json cannot be read as a known schema; B2 and B3
// need its pin and are then skipped.
func bootstrapInvariant(raw []byte, m *Manifest) string {
	lines := strings.Split(string(raw), "\n")
	if len(lines) == 0 || lines[0] != "#!/bin/sh" {
		return InvariantShebang
	}
	for _, line := range lines[1:] {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if t != "set -eu" {
			return InvariantShebang
		}
		break
	}
	if m != nil {
		if strings.Count(string(raw), "TRIPCORD_VERSION=") != 1 || count(lines, "TRIPCORD_VERSION='"+m.Version+"'") != 1 {
			return InvariantVersion
		}
		sums := slices.Collect(maps.Values(m.SHA256))
		for platform, sum := range m.SHA256 {
			if count(lines, "    "+platform+") printf '%s\\n' '"+sum+"' ;;") != 1 {
				return InvariantSums
			}
		}
		for _, d := range hex64.FindAllString(string(raw), -1) {
			if !slices.Contains(sums, d) {
				return InvariantSums
			}
		}
	}
	for i, line := range lines {
		if line == `if [ "$got" != "$want" ]; then` && i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "fail ") {
			return ""
		}
	}
	return InvariantChecksumGate
}

func count(lines []string, want string) int {
	n := 0
	for _, l := range lines {
		if l == want {
			n++
		}
	}
	return n
}

// preToolEvent is the hooks key of h's pre-tool guard.
func preToolEvent(h model.Harness) string {
	for _, e := range HookEntries(h) {
		if strings.EqualFold(e.Event, "preToolUse") {
			return e.Event
		}
	}
	return ""
}

// hookInvariant is the first invariant hook entry n, under event of h,
// breaks, or "". Only the pre-tool guard carries invariants: the
// session-start entry only fills the cache.
func hookInvariant(h model.Harness, event string, n *node) string {
	if event != preToolEvent(h) {
		return ""
	}
	if !runsGuard(n) {
		return InvariantGuardEntry
	}
	var command string
	switch h {
	case model.HarnessClaude:
		if m, _ := n.get("matcher").str(); m != "*" {
			return InvariantClaudeBlock
		}
		var guard *node
		for _, hook := range n.get("hooks").items {
			if runsGuard(hook) {
				guard = hook
				break
			}
		}
		if guard == nil {
			return InvariantGuardEntry
		}
		if v, _ := guard.get("onFailure").str(); v != "block" {
			return InvariantClaudeBlock
		}
		command, _ = guard.get("command").str()
	case model.HarnessCursor:
		if f := n.get("failClosed"); f == nil || string(f.raw) != "true" {
			return InvariantCursorClosed
		}
		if m := n.get("matcher"); m != nil {
			if s, _ := m.str(); s != "*" {
				return InvariantCursorClosed
			}
		}
		command, _ = n.get("command").str()
	case model.HarnessCopilot:
		typ, _ := n.get("type").str()
		cwd, _ := n.get("cwd").str()
		timeout := n.get("timeoutSec")
		secs := -1
		if timeout != nil && timeout.kind == kindScalar {
			if v, err := strconv.Atoi(string(timeout.raw)); err == nil {
				secs = v
			}
		}
		if typ != "command" || cwd != "." || secs < copilotMinTimeoutSec {
			return InvariantCopilotShape
		}
		command, _ = n.get("bash").str()
	default:
		return ""
	}
	if !blocksOnFailure(command) {
		return InvariantOnFailure
	}
	return ""
}

// blocksOnFailure reports whether command passes --on-failure block
// after bootstrap.sh hook.
func blocksOnFailure(command string) bool {
	_, rest, ok := strings.Cut(command, BootstrapPath)
	if !ok {
		return false
	}
	fields := strings.Fields(rest)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--on-failure" && fields[i+1] == "block" {
			return true
		}
	}
	return false
}

// embedTriggerPaths are the paths every generated workflow's
// pull_request filter has held. The set only grows.
var embedTriggerPaths = []string{".tripcord/**", ".claude/**", ".cursor/**", ".github/**"}

// workflowFailOn are the fail-on values that fail a high finding.
var workflowFailOn = []string{"low", "medium", "high"}

// workflowPermissions is the workflow-level set init writes.
var workflowPermissions = map[string]string{"contents": "read"}

// jobPermissions is the job-level set init writes. The called workflow
// runs as this job, so a broader grant here is the token the job gets.
var jobPermissions = map[string]string{
	"contents":        "read",
	"pull-requests":   "read",
	"security-events": "write",
}

// workflowJobKeys are the only keys the generated job has.
var workflowJobKeys = map[string]bool{"permissions": true, "uses": true, "with": true}

// workflowTopKeys are the only keys the generated workflow has.
var workflowTopKeys = map[string]bool{"name": true, "on": true, "permissions": true, "jobs": true}

// perm is a permissions value. scalar is set for `write-all` and any
// other non-mapping, which is never the generated shape.
type perm struct {
	present bool
	scalar  string
	pairs   map[string]string
}

func (p perm) matches(want map[string]string) bool {
	return p.present && p.scalar == "" && maps.Equal(p.pairs, want)
}

func readPerm(n *yaml.Node) perm {
	if n == nil {
		return perm{}
	}
	if n.Kind == yaml.ScalarNode {
		return perm{present: true, scalar: n.Value}
	}
	if n.Kind != yaml.MappingNode {
		return perm{present: true, scalar: "invalid"}
	}
	p := perm{present: true, pairs: map[string]string{}}
	for i := 0; i+1 < len(n.Content); i += 2 {
		v := n.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			return perm{present: true, scalar: "invalid"}
		}
		p.pairs[n.Content[i].Value] = v.Value
	}
	return p
}

// workflowJob is one job of a parsed tripcord.yml.
type workflowJob struct {
	uses       string
	hasIf      bool
	hasSteps   bool
	hasSecrets bool
	unknownKey bool
	with       map[string]string
	perms      perm
}

// parsedWorkflow is a tripcord.yml read as YAML.
type parsedWorkflow struct {
	on         *yaml.Node
	perms      perm
	secrets    bool
	unknownKey bool
	badJob     bool
	jobs       []workflowJob
}

func parseWorkflow(raw []byte) (parsedWorkflow, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return parsedWorkflow{}, false
	}
	top := doc.Content[0]
	wf := parsedWorkflow{on: mapValue(top, "on"), perms: readPerm(mapValue(top, "permissions")), secrets: mapValue(top, "secrets") != nil}
	for i := 0; i+1 < len(top.Content); i += 2 {
		if !workflowTopKeys[top.Content[i].Value] {
			wf.unknownKey = true
		}
	}
	jobs := mapValue(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return wf, true
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			wf.badJob = true
			continue
		}
		j := workflowJob{
			with:       map[string]string{},
			hasIf:      mapValue(job, "if") != nil,
			hasSteps:   mapValue(job, "steps") != nil,
			hasSecrets: mapValue(job, "secrets") != nil,
			perms:      readPerm(mapValue(job, "permissions")),
		}
		for k := 0; k+1 < len(job.Content); k += 2 {
			if !workflowJobKeys[job.Content[k].Value] {
				j.unknownKey = true
			}
		}
		if u := mapValue(job, "uses"); u != nil && u.Kind == yaml.ScalarNode {
			j.uses = u.Value
		}
		if w := mapValue(job, "with"); w != nil && w.Kind == yaml.MappingNode {
			for k := 0; k+1 < len(w.Content); k += 2 {
				if w.Content[k+1].Kind == yaml.ScalarNode {
					j.with[w.Content[k].Value] = w.Content[k+1].Value
				} else {
					j.unknownKey = true
				}
			}
		}
		wf.jobs = append(wf.jobs, j)
	}
	return wf, true
}

// emptyEvent reports whether a trigger value carries no filter. init
// writes `pull_request:` with nothing under it.
func emptyEvent(n *yaml.Node) bool {
	if n == nil || n.Kind == 0 || n.Tag == "!!null" {
		return true
	}
	if n.Kind == yaml.ScalarNode && (n.Value == "" || n.Value == "null" || n.Value == "~") {
		return true
	}
	return n.Kind == yaml.MappingNode && len(n.Content) == 0
}

// workflowInvariant is the first invariant tripcord.yml breaks, or "".
// The pin itself is judged by checker.workflowPin. The shape is what
// init emits: one reusable job, the generated permissions, pull_request
// with no filter, no secrets, and with holding only fail-on.
func workflowInvariant(raw []byte) string {
	wf, ok := parseWorkflow(raw)
	if !ok {
		return InvariantTrigger
	}
	if id := triggerInvariant(wf.on); id != "" {
		return id
	}
	if wf.secrets || wf.unknownKey || wf.badJob || len(wf.jobs) != 1 {
		return InvariantReusableJob
	}
	job := wf.jobs[0]
	if job.hasIf || job.hasSteps || job.hasSecrets || job.unknownKey || !strings.HasPrefix(job.uses, project.Repository+"/"+ReusableWorkflowPath+"@") {
		return InvariantReusableJob
	}
	if !slices.Contains(workflowFailOn, job.with["fail-on"]) {
		return InvariantFailOn
	}
	if len(job.with) != 1 {
		return InvariantInputs
	}
	if !wf.perms.matches(workflowPermissions) || !job.perms.matches(jobPermissions) {
		return InvariantPermissions
	}
	return ""
}

// triggerInvariant is W1 or W2 for on. The generated workflow is
// `pull_request` with no filter. A paths filter that drops one of the
// embed's own paths is W2; any other departure from that shape is W1.
func triggerInvariant(on *yaml.Node) string {
	if on == nil || on.Kind != yaml.MappingNode || len(on.Content) != 2 || on.Content[0].Value != "pull_request" {
		return InvariantTrigger
	}
	pr := on.Content[1]
	if pr != nil && pr.Kind == yaml.MappingNode {
		if paths := mapValue(pr, "paths"); paths != nil {
			var have []string
			for _, p := range paths.Content {
				have = append(have, p.Value)
			}
			for _, want := range embedTriggerPaths {
				if !slices.Contains(have, want) {
					return InvariantPaths
				}
			}
		}
		if mapValue(pr, "paths-ignore") != nil || mapValue(pr, "branches") != nil || mapValue(pr, "branches-ignore") != nil {
			return InvariantPaths
		}
	}
	if !emptyEvent(pr) {
		return InvariantTrigger
	}
	return ""
}

// stepInvariant is S1 when the Copilot setup step does not run the
// install command unconditionally, or "".
func stepInvariant(step *yaml.Node) string {
	if step == nil || step.Kind != yaml.MappingNode {
		return InvariantSetupStep
	}
	run := mapValue(step, "run")
	if run == nil || run.Kind != yaml.ScalarNode || strings.TrimSpace(run.Value) != installCommand {
		return InvariantSetupStep
	}
	if mapValue(step, "if") != nil {
		return InvariantSetupStep
	}
	if c := mapValue(step, "continue-on-error"); c != nil && c.Value != "false" {
		return InvariantSetupStep
	}
	return ""
}
