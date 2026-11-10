package embedded

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// KnownRendersPath is the generated table of every render an init that
// wrote a pin in {WorkflowPin} ∪ KnownWorkflowPins produced, relative
// to the repository root. go run ./scripts/knownrenders rewrites it.
const KnownRendersPath = "internal/embedded/known_renders.json"

// KnownRendersSchema is the schema id of known_renders.json.
const KnownRendersSchema = "tripcord.known-renders/v1"

//go:embed known_renders.json
var knownRendersJSON []byte

// RenderSet is the digests of what init writes for each surface the
// embed check compares, independent of the pinned release.
type RenderSet struct {
	// Bootstrap is the SHA-256 of bootstrap.sh with its TRIPCORD_VERSION
	// line and checksum arms replaced (BootstrapTemplateDigest).
	Bootstrap []string `json:"bootstrap"`
	// Workflow is the SHA-256 of tripcord.yml with its pin replaced
	// (WorkflowTemplateDigest).
	Workflow []string `json:"workflow"`
	// Hooks maps "<harness>/<event>" to HookEntry.SHA256 values.
	Hooks map[string][]string `json:"hooks"`
	// CopilotStep is the digest of the copilot-setup-steps.yml step.
	CopilotStep []string `json:"copilotStep"`
}

// KnownRendersFile is known_renders.json.
type KnownRendersFile struct {
	Schema string               `json:"schema"`
	Pins   map[string]RenderSet `json:"pins"`
}

var knownRenders = mustKnownRenders(knownRendersJSON)

func mustKnownRenders(raw []byte) KnownRendersFile {
	f, err := ParseKnownRenders(raw)
	if err != nil {
		panic(err)
	}
	return f
}

// ParseKnownRenders parses known_renders.json.
func ParseKnownRenders(raw []byte) (KnownRendersFile, error) {
	var f KnownRendersFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return KnownRendersFile{}, err
	}
	if f.Schema != KnownRendersSchema {
		return KnownRendersFile{}, errors.New("known_renders.json: schema is not " + KnownRendersSchema)
	}
	return f, nil
}

// KnownRenders returns a copy of the compiled table, keyed by pin.
func KnownRenders() map[string]RenderSet {
	out := make(map[string]RenderSet, len(knownRenders.Pins))
	for pin, set := range knownRenders.Pins {
		out[pin] = set.clone()
	}
	return out
}

func (s RenderSet) clone() RenderSet {
	c := RenderSet{
		Bootstrap:   slices.Clone(s.Bootstrap),
		Workflow:    slices.Clone(s.Workflow),
		CopilotStep: slices.Clone(s.CopilotStep),
		Hooks:       map[string][]string{},
	}
	for k, v := range s.Hooks {
		c.Hooks[k] = slices.Clone(v)
	}
	return c
}

// Add merges o into s, keeping every list sorted and unique.
func (s *RenderSet) Add(o RenderSet) {
	s.Bootstrap = mergeSorted(s.Bootstrap, o.Bootstrap)
	s.Workflow = mergeSorted(s.Workflow, o.Workflow)
	s.CopilotStep = mergeSorted(s.CopilotStep, o.CopilotStep)
	if s.Hooks == nil {
		s.Hooks = map[string][]string{}
	}
	for k, v := range o.Hooks {
		s.Hooks[k] = mergeSorted(s.Hooks[k], v)
	}
}

// Includes reports whether every digest of o is in s.
func (s RenderSet) Includes(o RenderSet) bool {
	sub := func(a, b []string) bool {
		for _, d := range b {
			if !slices.Contains(a, d) {
				return false
			}
		}
		return true
	}
	if !sub(s.Bootstrap, o.Bootstrap) || !sub(s.Workflow, o.Workflow) || !sub(s.CopilotStep, o.CopilotStep) {
		return false
	}
	for k, v := range o.Hooks {
		if !sub(s.Hooks[k], v) {
			return false
		}
	}
	return true
}

func mergeSorted(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

func hookKey(h model.Harness, event string) string { return string(h) + "/" + event }

// historical reports whether d is a render some known pin's init wrote
// for the surface pick selects.
func historical(d string, pick func(RenderSet) []string) bool {
	for _, set := range knownRenders.Pins {
		if slices.Contains(pick(set), d) {
			return true
		}
	}
	return false
}

var (
	bootstrapVersionLine = regexp.MustCompile(`(?m)^TRIPCORD_VERSION='[^'\n]*'$`)
	bootstrapSumArm      = regexp.MustCompile(`(?m)^    [a-z0-9-]+\) printf '%s\\n' '[0-9a-f]{64}' ;;\n`)
	workflowPinComment   = regexp.MustCompile(`main@[0-9a-f]{7}\b`)
	workflowUsesLine     = regexp.MustCompile(`(?m)^(\s*uses:).*$`)
)

// BootstrapTemplateDigest is the SHA-256 of bootstrap.sh with the
// pinned version and checksum arms replaced by placeholders, so renders
// of one template for different pins share it.
func BootstrapTemplateDigest(raw []byte) string {
	s := bootstrapVersionLine.ReplaceAllString(string(raw), "TRIPCORD_VERSION='@VERSION@'")
	s = bootstrapSumArm.ReplaceAllString(s, "")
	return digest([]byte(s))
}

// WorkflowTemplateDigest is the SHA-256 of tripcord.yml with every
// uses: value and the pin's main@ comment replaced by placeholders.
// checker.workflowPin judges each job's uses: on its own.
func WorkflowTemplateDigest(raw []byte) string {
	s := workflowPinComment.ReplaceAllString(string(raw), "main@@PIN7@")
	s = workflowUsesLine.ReplaceAllString(s, "${1} @USES@")
	return digest([]byte(s))
}

// templatePin is any valid pin: the template digests do not depend on it.
var templatePin = Pin{Version: "0.0.0", SHA256: map[string]string{Platforms[0]: strings.Repeat("0", 64)}}

// CurrentRenders is what this build of init writes.
func CurrentRenders() RenderSet {
	s := RenderSet{
		Bootstrap:   []string{BootstrapTemplateDigest(Bootstrap(templatePin))},
		Workflow:    []string{WorkflowTemplateDigest(Workflow())},
		CopilotStep: []string{copilotStep().digest()},
		Hooks:       map[string][]string{},
	}
	for _, h := range HookHarnesses {
		for _, e := range HookEntries(h) {
			s.Hooks[hookKey(h, e.Event)] = []string{e.SHA256()}
		}
	}
	return s
}

// ObserveRenders reads what an init wrote under root (every hook
// harness wired, Copilot included) and returns its render digests. The
// knownrenders generator runs it on the output of each historical init.
func ObserveRenders(root string) (RenderSet, error) {
	s := RenderSet{Hooks: map[string][]string{}}
	read := func(rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	}
	raw, err := read(BootstrapPath)
	if err != nil {
		return s, err
	}
	s.Bootstrap = []string{BootstrapTemplateDigest(lf(raw))}
	if raw, err = read(WorkflowPath); err != nil {
		return s, err
	}
	s.Workflow = []string{WorkflowTemplateDigest(lf(raw))}
	t := &revision{files: map[string]file{}}
	for _, h := range HookHarnesses {
		raw, err := read(HookPath(h))
		if err != nil {
			return s, err
		}
		t.files[HookPath(h)] = file{raw: raw}
		hooks, ok := t.hooks(h)
		if !ok {
			return s, errors.New(HookPath(h) + ": hooks do not parse")
		}
		for _, event := range slices.Sorted(maps.Keys(hooks)) {
			list, _ := hooks[event].([]any)
			for _, v := range list {
				if n := anyNode(v); namesTripcord(n) {
					s.Hooks[hookKey(h, event)] = mergeSorted(s.Hooks[hookKey(h, event)], []string{hookDigest(event, n)})
				}
			}
		}
	}
	raw, err = read(CopilotSetupStepsPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return s, err
	}
	if err == nil {
		steps, ok := setupSteps(file{raw: raw})
		if !ok {
			return s, errors.New(CopilotSetupStepsPath + ": steps do not parse")
		}
		for _, step := range steps {
			if n := yamlNode(step); namesTripcord(n) {
				s.CopilotStep = mergeSorted(s.CopilotStep, []string{n.digest()})
			}
		}
	}
	return s, nil
}

// HookEntryDigest is the digest embed.json records for one hook entry:
// event, a NUL, and the entry's canonical JSON.
func HookEntryDigest(event string, entry []byte) (string, error) {
	doc, _, err := kit.DecodeJSON(entry, kit.StrictJSON, "hook")
	if err != nil {
		return "", err
	}
	return hookDigest(event, anyNode(doc)), nil
}
