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
	InvariantReusableJob   = "W3" // one job calls tripcord-pr.yml, with no if
	InvariantFailOn        = "W4" // fail-on low, medium, or high
	InvariantInputs        = "W5" // no binary, ref, or path other than .
	InvariantSetupStep     = "S1" // the setup step runs install, unconditionally
	InvariantWriterWitness = "witness"
)

// Invariants lists every invariant id. It only grows.
var Invariants = []string{
	InvariantShebang, InvariantVersion, InvariantSums, InvariantChecksumGate,
	InvariantGuardEntry, InvariantClaudeBlock, InvariantCursorClosed, InvariantCopilotShape, InvariantOnFailure,
	InvariantTrigger, InvariantPaths, InvariantReusableJob, InvariantFailOn, InvariantInputs,
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

// workflowJob is one job of a parsed tripcord.yml.
type workflowJob struct {
	uses  string
	hasIf bool
	with  map[string]string
}

// parsedWorkflow is a tripcord.yml read as YAML.
type parsedWorkflow struct {
	on   *yaml.Node
	jobs []workflowJob
}

func parseWorkflow(raw []byte) (parsedWorkflow, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return parsedWorkflow{}, false
	}
	top := doc.Content[0]
	wf := parsedWorkflow{on: mapValue(top, "on")}
	jobs := mapValue(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return wf, true
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		j := workflowJob{with: map[string]string{}, hasIf: mapValue(job, "if") != nil}
		if u := mapValue(job, "uses"); u != nil && u.Kind == yaml.ScalarNode {
			j.uses = u.Value
		}
		if w := mapValue(job, "with"); w != nil && w.Kind == yaml.MappingNode {
			for k := 0; k+1 < len(w.Content); k += 2 {
				j.with[w.Content[k].Value] = w.Content[k+1].Value
			}
		}
		wf.jobs = append(wf.jobs, j)
	}
	return wf, true
}

// reusableJobs are the jobs that call a tripcord-pr.yml.
func (wf parsedWorkflow) reusableJobs() []workflowJob {
	var out []workflowJob
	for _, j := range wf.jobs {
		if strings.Contains(j.uses, ReusableWorkflowPath+"@") || strings.Contains(j.uses, "tripcord-pr.yml") {
			out = append(out, j)
		}
	}
	return out
}

// workflowInvariant is the first invariant tripcord.yml breaks, or "".
// The pin itself is judged by checker.workflowPin.
func workflowInvariant(raw []byte) string {
	wf, ok := parseWorkflow(raw)
	if !ok {
		return InvariantTrigger
	}
	on := wf.on
	if on == nil || on.Kind != yaml.MappingNode || mapValue(on, "pull_request_target") != nil || mapValue(on, "workflow_run") != nil {
		return InvariantTrigger
	}
	pr := mapValue(on, "pull_request")
	if pr == nil {
		return InvariantTrigger
	}
	if pr.Kind == yaml.MappingNode {
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
	jobs := wf.reusableJobs()
	if len(jobs) != 1 || jobs[0].hasIf || !strings.HasPrefix(jobs[0].uses, project.Repository+"/"+ReusableWorkflowPath+"@") {
		return InvariantReusableJob
	}
	if !slices.Contains(workflowFailOn, jobs[0].with["fail-on"]) {
		return InvariantFailOn
	}
	if _, ok := jobs[0].with["binary"]; ok {
		return InvariantInputs
	}
	if _, ok := jobs[0].with["ref"]; ok {
		return InvariantInputs
	}
	if p, ok := jobs[0].with["path"]; ok && p != "." {
		return InvariantInputs
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
