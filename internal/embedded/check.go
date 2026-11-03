package embedded

import (
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// Guard states a TC-CFG-016 item reports.
const (
	// StateMissing: the file, or the hook or step in it, is not there.
	StateMissing = "missing"
	// StateChanged: the file, hook, or step differs from what init
	// writes for the recorded pin, and from what the manifest records.
	StateChanged = "changed"
	// StateStale: it is what the manifest records, but not what this
	// build of init writes: an older Tripcord wrote it.
	StateStale = "stale"
	// StateUnreadable: the file could not be read or parsed.
	StateUnreadable = "unreadable"
	// StateRemoved: the base revision had it and this change removes it.
	StateRemoved = "removed"
	// StateDropped: this change drops a harness the base manifest wired.
	StateDropped = "dropped"
	// StateRepinned: this change changes the pinned version or a
	// checksum. Re-pinning bootstrap.sh and embed.json together is the
	// one bootstrap edit the single-revision check cannot see.
	StateRepinned = "repinned"
)

// Guard subjects that are not a hook event.
const (
	subjectBootstrap = "bootstrap"
	subjectManifest  = "manifest"
	subjectWorkflow  = "workflow"
	subjectStep      = "setup-step"
	subjectHarnesses = "manifest-harnesses"
	subjectPin       = "manifest-pin"
)

// CheckOptions selects what Check compares.
type CheckOptions struct {
	// Only, when not empty, limits the harness wiring checked to these
	// harnesses. Embed files shared by every harness are always checked.
	Only []model.Harness
	// Base reads a file of the base revision a change is compared with
	// (scan --since or --base). It returns an error wrapping
	// fs.ErrNotExist for a path the base does not have. Nil checks the
	// revision on its own.
	Base func(rel string) ([]byte, error)
}

// file is one file read for the check. state is "" when raw was read.
type file struct {
	raw   []byte
	state string
}

func (f file) exists() bool { return f.state != StateMissing }

// revision is the files of one revision the check reads.
type revision struct {
	files    map[string]file
	manifest Manifest
	// manifestOK is true when embed.json parses as a manifest with a
	// valid pin.
	manifestOK bool
}

// checkedPaths are every file the check reads.
var checkedPaths = []string{BootstrapPath, ManifestPath, WorkflowPath, ClaudeSettingsPath, CursorHooksPath, CopilotHooksPath, CopilotSetupStepsPath}

func newRevision(read func(rel string) (file, error)) (*revision, error) {
	t := &revision{files: map[string]file{}}
	for _, p := range checkedPaths {
		f, err := read(p)
		if err != nil {
			return nil, err
		}
		t.files[p] = f
	}
	if m := t.files[ManifestPath]; m.state == "" {
		t.manifest, t.manifestOK = parseManifest(m.raw)
	}
	return t, nil
}

func parseManifest(raw []byte) (Manifest, bool) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Schema != ManifestSchema || m.Pin().Validate() != nil {
		return Manifest{}, false
	}
	return m, true
}

// embedded reports whether t holds the embed's own files.
func (t *revision) embedded() bool {
	return t.files[BootstrapPath].exists() || t.files[ManifestPath].exists()
}

// leftovers reports whether t holds anything else init --embed writes:
// the workflow, or a hook that runs .tripcord/bootstrap.sh. A hook that
// runs tripcord some other way is the documented manual wiring, not an
// embed, so it does not count.
func (t *revision) leftovers() bool {
	if t.files[WorkflowPath].exists() {
		return true
	}
	for _, h := range HookHarnesses {
		hooks, ok := t.hooks(h)
		if !ok {
			continue
		}
		for _, list := range hooks {
			if runsBootstrap(anyNode(list)) {
				return true
			}
		}
	}
	return false
}

func runsBootstrap(n *node) bool {
	if s, ok := n.str(); ok {
		return strings.Contains(s, BootstrapPath)
	}
	return slices.ContainsFunc(n.items, runsBootstrap)
}

// hooks is the hooks object of h's wiring file. ok is false when the
// file is missing or does not parse.
func (t *revision) hooks(h model.Harness) (map[string]any, bool) {
	f := t.files[HookPath(h)]
	if f.state != "" {
		return nil, false
	}
	syntax := kit.StrictJSON
	if h == model.HarnessCursor {
		syntax = kit.JSONC
	}
	doc, _, err := kit.DecodeJSON(f.raw, syntax, string(h))
	top, isObject := doc.(map[string]any)
	if err != nil || !isObject {
		return nil, false
	}
	hooks, _ := top["hooks"].(map[string]any)
	return hooks, true
}

// hadTripcordHook reports whether hooks.<event> in t names tripcord.
func (t *revision) hadTripcordHook(h model.Harness, event string) bool {
	hooks, ok := t.hooks(h)
	return ok && namesTripcord(anyNode(hooks[event]))
}

// Check returns one repository config item for every part of a Tripcord
// embed that is missing, changed, stale, or unreadable in root, and,
// with opts.Base, every part a change removes or weakens relative to
// the base. The items are TC-CFG-016 permissions items (setting
// GuardSetting).
//
// root is embedded when it has bootstrap.sh or embed.json, or anything
// else only init --embed writes (the workflow, or a hook that runs
// .tripcord/bootstrap.sh), or when the base is embedded. bootstrap.sh and
// the workflow are compared with what init renders from the pin
// embed.json records, so a manifest whose recorded digests were edited
// to match does not pass them. Hooks are checked for the harnesses the
// manifest records, every hook harness when there is none, and, with a
// base, the harnesses the base manifest records as well.
func Check(root string, opts CheckOptions) ([]model.ConfigItem, error) {
	r, err := adapters.NewSafeReader(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	head, err := newRevision(func(rel string) (file, error) {
		raw, err := r.ReadFile(rel, adapters.MaxConfigFileBytes)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return file{state: StateMissing}, nil
		case err != nil:
			return file{state: StateUnreadable}, nil
		}
		return file{raw: raw}, nil
	})
	if err != nil {
		return nil, err
	}
	var base *revision
	if opts.Base != nil {
		base, err = newRevision(func(rel string) (file, error) {
			raw, err := opts.Base(rel)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				return file{state: StateMissing}, nil
			case err != nil:
				return file{}, err
			}
			return file{raw: raw}, nil
		})
		if err != nil {
			return nil, err
		}
		if !base.embedded() {
			base = nil
		}
	}
	if base == nil && !head.embedded() && !head.leftovers() {
		return nil, nil
	}
	c := &checker{head: head, base: base, only: opts.Only}
	c.manifest()
	c.ownFile(subjectBootstrap, BootstrapPath, func(m Manifest) []byte { return Bootstrap(m.Pin()) })
	c.ownFile(subjectWorkflow, WorkflowPath, func(Manifest) []byte { return Workflow() })
	wired := c.wired()
	for _, h := range HookHarnesses {
		if slices.Contains(wired, h) && c.selected(h) {
			c.hookHarness(h)
		}
	}
	if slices.Contains(wired, model.HarnessCopilot) && c.head.manifestOK && c.selected(model.HarnessCopilot) {
		c.setupStep()
	}
	return c.items, c.err
}

type checker struct {
	head, base *revision
	only       []model.Harness
	items      []model.ConfigItem
	err        error
}

func (c *checker) selected(h model.Harness) bool {
	return len(c.only) == 0 || slices.Contains(c.only, h)
}

// wired is the hook harnesses to check, plus copilot when it is wired.
func (c *checker) wired() []model.Harness {
	var names []string
	switch {
	case c.head.manifestOK:
		names = c.head.manifest.Harnesses
	case c.base != nil && c.base.manifestOK:
		names = c.base.manifest.Harnesses
	default:
		return HookHarnesses
	}
	if c.base != nil && c.base.manifestOK {
		names = append(slices.Clone(names), c.base.manifest.Harnesses...)
	}
	var out []model.Harness
	for _, h := range Harnesses {
		if slices.Contains(names, string(h)) {
			out = append(out, h)
		}
	}
	return out
}

// absent is the state of something the head does not have: removed when
// the base had it.
func (c *checker) absent(baseHad bool) string {
	if c.base != nil && baseHad {
		return StateRemoved
	}
	return StateMissing
}

func (c *checker) manifest() {
	f := c.head.files[ManifestPath]
	switch {
	case !f.exists():
		c.add(model.SurfaceGeneric, ManifestPath, subjectManifest, "", c.absent(c.base != nil && c.base.files[ManifestPath].exists()), f.raw, nil)
		return
	case !c.head.manifestOK:
		c.add(model.SurfaceGeneric, ManifestPath, subjectManifest, "", StateUnreadable, f.raw, nil)
		return
	}
	if c.base == nil || !c.base.manifestOK {
		return
	}
	was, now := c.base.manifest, c.head.manifest
	var dropped []string
	for _, h := range was.Harnesses {
		if !slices.Contains(now.Harnesses, h) {
			dropped = append(dropped, h)
		}
	}
	if len(dropped) > 0 {
		c.add(model.SurfaceGeneric, ManifestPath, subjectHarnesses, "", StateDropped, f.raw, map[string]string{"harnesses": strings.Join(dropped, ",")})
	}
	if was.Version != now.Version || !maps.Equal(was.SHA256, now.SHA256) {
		c.add(model.SurfaceGeneric, ManifestPath, subjectPin, "", StateRepinned, f.raw, map[string]string{"from": was.Version, "to": now.Version})
	}
}

// ownFile checks a file only init writes against render(manifest).
// Without a valid manifest there is no pin to render from, and the
// manifest item already reports that.
func (c *checker) ownFile(subject, path string, render func(Manifest) []byte) {
	f := c.head.files[path]
	switch {
	case !f.exists():
		c.add(model.SurfaceGeneric, path, subject, "", c.absent(c.base != nil && c.base.files[path].exists()), nil, nil)
	case f.state != "":
		c.add(model.SurfaceGeneric, path, subject, "", StateUnreadable, nil, nil)
	case c.head.manifestOK:
		want := digest(render(c.head.manifest))
		if state := compare(digest(f.raw), want, c.head.manifest.recordedFile(path, "")); state != "" {
			c.add(model.SurfaceGeneric, path, subject, "", state, f.raw, nil)
		}
	}
}

// compare is "" when got is want, stale when got is what the manifest
// recorded and that is not want, and changed otherwise.
func compare(got, want, recorded string) string {
	switch {
	case got == want:
		return ""
	case recorded != "" && got == recorded:
		return StateStale
	default:
		return StateChanged
	}
}

func (c *checker) hookHarness(h model.Harness) {
	path := HookPath(h)
	f := c.head.files[path]
	hooks, parsed := c.head.hooks(h)
	recorded := map[string]string{}
	if c.head.manifestOK {
		for _, hook := range c.head.manifest.Hooks {
			if hook.Harness == string(h) {
				recorded[hook.Event] = hook.SHA256
			}
		}
	}
	for _, e := range HookEntries(h) {
		var state string
		switch {
		case !f.exists():
			state = c.absent(c.base != nil && c.base.hadTripcordHook(h, e.Event))
		case !parsed:
			state = StateUnreadable
		default:
			state = entryState(e, hooks, recorded[e.Event])
			if state == StateMissing {
				state = c.absent(c.base != nil && c.base.hadTripcordHook(h, e.Event))
			}
		}
		if state != "" {
			c.add(h, path, e.Event, e.Event, state, f.raw, nil)
		}
	}
}

// entryState is "" when hooks.<e.Event> holds an entry identical to e.
// An entry whose digest the manifest records, when that is not e's, is
// stale; any other entry that names tripcord is changed.
func entryState(e HookEntry, hooks map[string]any, recorded string) string {
	list, _ := hooks[e.Event].([]any)
	state := StateMissing
	for _, v := range list {
		n := anyNode(v)
		if n.equal(e.entry) {
			return ""
		}
		switch {
		case recorded != "" && recorded != e.SHA256() && hookDigest(e.Event, n) == recorded:
			state = StateStale
		case state == StateMissing && namesTripcord(n):
			state = StateChanged
		}
	}
	return state
}

func hookDigest(event string, n *node) string {
	return digest(append([]byte(event+"\x00"), n.canonical()...))
}

// setupStep checks the step init adds to copilot-setup-steps.yml.
func (c *checker) setupStep() {
	f := c.head.files[CopilotSetupStepsPath]
	baseHad := c.base != nil && c.base.hasTripcordStep()
	if !f.exists() {
		c.add(model.HarnessCopilot, CopilotSetupStepsPath, subjectStep, "", c.absent(baseHad), nil, nil)
		return
	}
	steps, ok := setupSteps(f)
	if !ok {
		c.add(model.HarnessCopilot, CopilotSetupStepsPath, subjectStep, "", StateUnreadable, f.raw, nil)
		return
	}
	want := copilotStep().digest()
	recorded := c.head.manifest.recordedFile(CopilotSetupStepsPath, copilotStepName)
	state := StateMissing
	for _, step := range steps {
		if isCopilotStep(step) {
			return
		}
		n := yamlNode(step)
		switch {
		case recorded != "" && recorded != want && n.digest() == recorded:
			state = StateStale
		case state == StateMissing && namesTripcord(n):
			state = StateChanged
		}
	}
	if state == StateMissing {
		state = c.absent(baseHad)
	}
	c.add(model.HarnessCopilot, CopilotSetupStepsPath, subjectStep, "", state, f.raw, nil)
}

func (t *revision) hasTripcordStep() bool {
	steps, ok := setupSteps(t.files[CopilotSetupStepsPath])
	return ok && slices.ContainsFunc(steps, func(s *yaml.Node) bool { return namesTripcord(yamlNode(s)) })
}

// setupSteps is jobs.copilot-setup-steps.steps of f.
func setupSteps(f file) ([]*yaml.Node, bool) {
	if f.state != "" {
		return nil, false
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(f.raw, &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, false
	}
	steps := mapValue(mapValue(mapValue(doc.Content[0], "jobs"), "copilot-setup-steps"), "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return nil, false
	}
	return steps.Content, true
}

func (c *checker) add(h model.Harness, path, subject, event, state string, raw []byte, extra map[string]string) {
	if c.err != nil {
		return
	}
	key, err := json.Marshal([]string{GuardSetting, subject})
	if err != nil {
		c.err = err
		return
	}
	payload := map[string]string{
		"setting": GuardSetting,
		"subject": subject,
		"state":   state,
		"key":     string(key),
	}
	if event != "" {
		payload["event"] = event
	}
	maps.Copy(payload, extra)
	body, err := json.Marshal(payload)
	if err != nil {
		c.err = err
		return
	}
	c.items = append(c.items, model.ConfigItem{
		Harness: h,
		Scope:   model.ScopeRepo,
		Path:    path,
		SHA256:  digest(raw),
		Kind:    model.ConfigKindPermissions,
		Payload: body,
		// Whether this item exists depends on every file the check
		// reads: a staged change to any of them must report it.
		SourcePaths: slices.Clone(checkedPaths),
	})
}

// anyNode converts a kit.DecodeJSON value into a node.
func anyNode(v any) *node {
	switch t := v.(type) {
	case map[string]any:
		n := &node{kind: kindObject}
		for _, k := range slices.Sorted(maps.Keys(t)) {
			n.set(k, anyNode(t[k]))
		}
		return n
	case []any:
		n := &node{kind: kindArray}
		for _, item := range t {
			n.items = append(n.items, anyNode(item))
		}
		return n
	case json.Number:
		return &node{kind: kindScalar, raw: []byte(t.String())}
	default:
		raw, err := marshalScalar(t)
		if err != nil {
			raw = []byte("null")
		}
		return &node{kind: kindScalar, raw: raw}
	}
}
