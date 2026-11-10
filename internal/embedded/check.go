package embedded

import (
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
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
	// writes for the recorded pin, and from what the manifest records,
	// or bootstrap.sh, embed.json, or .tripcord is a symlink.
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
	// StateWeakened: this change weakens the repository policy
	// relative to the base (aspect names how).
	StateWeakened = "weakened"
	// StateLocalDisabled: a settings.local.json the repository tracks
	// sets disableAllHooks. The harness applies it over the shared
	// settings, so committing it turns every hook off for everyone.
	StateLocalDisabled = "local-disabled"
	// StateLocalPolicy: the repository tracks, or a staged change
	// stages, .tripcord/policy.local.yaml. That file is a per-checkout
	// layer; a tracked copy overrides everyone's effective policy
	// instead of only its own, so the scan never loads it (see
	// cmd/tripcord's SkipLocal wiring) and reports it here instead.
	StateLocalPolicy = "local-policy"
)

// Local settings files: personal, and so not checked, unless the
// repository tracks them. Copilot CLI reads both.
const (
	ClaudeLocalSettingsPath  = ".claude/settings.local.json"
	CopilotLocalSettingsPath = ".github/copilot/settings.local.json"
)

var localSettings = []struct {
	harness model.Harness
	path    string
}{
	{model.HarnessClaude, ClaudeLocalSettingsPath},
	{model.HarnessCopilot, CopilotLocalSettingsPath},
}

// Guard subjects that are not a hook event.
const (
	subjectBootstrap     = "bootstrap"
	subjectManifest      = "manifest"
	subjectWorkflow      = "workflow"
	subjectStep          = "setup-step"
	subjectHarnesses     = "manifest-harnesses"
	subjectPin           = "manifest-pin"
	subjectLocal         = "local-settings"
	subjectPolicy        = "policy"
	subjectPolicyLocal   = "policy-local"
	subjectGitattributes = "gitattributes"
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
	// Tracked reports whether the repository tracks rel (it is in the
	// git index). A settings.local.json that is not tracked is personal
	// and is not checked. Nil tracks nothing.
	Tracked func(rel string) bool
	// TrackedCaseVariants, when set, lists every path the repository
	// tracks (or, for a --staged scan, stages) whose name matches rel
	// except for ASCII/Unicode case: the shape a case-insensitive
	// checkout (macOS, Windows) would also resolve rel to, even though
	// git's own tracking, and a Linux checkout, never folds case. It
	// includes rel itself when the repository tracks it exactly, so
	// policyLocal uses it alone, in place of Tracked, once it is set;
	// only .tripcord/policy.local.yaml needs this, since it is the one
	// file a case-insensitive host's own os.ReadFile can resolve to a
	// differently-cased committed file behind git's back. Nil falls
	// back to Tracked's exact match only.
	TrackedCaseVariants func(rel string) []string
	// IndexTree is true when root holds only the git index's content (a
	// --staged scan's private tree), read with no checkout smudge or
	// autocrlf filter: a file with CRLF line endings there did not pass
	// through one, however it looks, so it is hashed as its raw bytes
	// with no uniform-CRLF leniency at all.
	IndexTree bool
}

// file is one file read for the check. state is "" when raw was read.
type file struct {
	raw   []byte
	state string
	// linked is true when the file, or the .tripcord directory that
	// holds it, is a symlink. bootstrap.sh resolves its own directory
	// to find the repository, so a link makes it run, and scan,
	// another tree.
	linked bool
}

func (f file) exists() bool { return f.state != StateMissing }

// revision is the files of one revision the check reads.
type revision struct {
	files    map[string]file
	manifest Manifest
	// manifestOK is true when embed.json parses as a manifest with a
	// valid pin.
	manifestOK bool
	// blob is true when every file here was read as a git blob (the
	// base revision, always, or the head with CheckOptions.IndexTree):
	// no checkout filter ran, so CRLF is never given uniform-autocrlf
	// leniency; see lf and ownFile.
	blob bool
}

// checkedPaths are every file the check reads.
var checkedPaths = []string{BootstrapPath, ManifestPath, WorkflowPath, ClaudeSettingsPath, CursorHooksPath, CopilotHooksPath, CopilotSetupStepsPath, GitattributesPath}

// sourcePaths are every file whose content a guard item depends on.
var sourcePaths = append(slices.Clone(checkedPaths), ClaudeLocalSettingsPath, CopilotLocalSettingsPath, PolicyLocalPath)

func newRevision(blob bool, read func(rel string) (file, error)) (*revision, error) {
	t := &revision{files: map[string]file{}, blob: blob}
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

func isSymlink(root, rel string) bool {
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil && info.Mode()&fs.ModeSymlink != 0
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

// leftover is what remains of an embed whose own files are gone.
type leftover struct {
	workflow bool
	// harnesses have a hook that runs .tripcord/bootstrap.sh in hook
	// mode: Tripcord's guard.
	harnesses []model.Harness
}

func (l leftover) any() bool { return l.workflow || len(l.harnesses) > 0 }

// leftovers is what t holds that only init --embed writes: the
// workflow, or a hook that runs the guard through bootstrap.sh. A hook
// that runs tripcord some other way is the documented manual wiring,
// and a hook that only runs bootstrap.sh session-start installs the
// binary without guarding anything; neither counts.
func (t *revision) leftovers() leftover {
	l := leftover{workflow: t.files[WorkflowPath].exists()}
	for _, h := range HookHarnesses {
		hooks, ok := t.hooks(h)
		if !ok {
			continue
		}
		for _, list := range hooks {
			if runsGuard(anyNode(list)) {
				l.harnesses = append(l.harnesses, h)
				break
			}
		}
	}
	return l
}

// runsGuard reports whether n holds a command that runs bootstrap.sh
// with the hook mode argument, as one command string or as an argv
// array.
func runsGuard(n *node) bool {
	if s, ok := n.str(); ok {
		_, rest, found := strings.Cut(s, BootstrapPath)
		return found && slices.Contains(strings.Fields(rest), "hook")
	}
	if n.kind == kindArray {
		for i, item := range n.items {
			if s, ok := item.str(); ok && strings.Contains(s, BootstrapPath) {
				for _, next := range n.items[i+1:] {
					if arg, ok := next.str(); ok && arg == "hook" {
						return true
					}
				}
			}
		}
	}
	return slices.ContainsFunc(n.items, runsGuard)
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
// root is embedded when it has bootstrap.sh or embed.json, or when the
// base is embedded. Without either, a leftover only init --embed writes
// (the workflow, or a hook that runs the guard through bootstrap.sh)
// reports the embed's own files, the workflow when it is the leftover,
// and the wiring of the harnesses with such a hook. bootstrap.sh and
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
	head, err := newRevision(opts.IndexTree, func(rel string) (file, error) {
		linked := strings.HasPrefix(rel, ".tripcord/") && (isSymlink(root, ".tripcord") || isSymlink(root, rel))
		raw, err := r.ReadFile(rel, adapters.MaxConfigFileBytes)
		switch {
		case linked:
			return file{raw: raw, linked: true}, nil
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
		base, err = newRevision(true, func(rel string) (file, error) {
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
	c := &checker{head: head, base: base, only: opts.Only}
	active := base != nil || head.embedded()
	if !active {
		if left := head.leftovers(); left.any() {
			c.leftover = &left
			active = true
		}
	}
	if active {
		c.manifest()
		c.ownFile(subjectBootstrap, BootstrapPath, func(m Manifest) []byte { return Bootstrap(m.Pin()) })
		if c.leftover == nil || c.leftover.workflow {
			c.ownFile(subjectWorkflow, WorkflowPath, func(Manifest) []byte { return Workflow() })
		}
		if c.leftover == nil {
			c.gitattributes()
		}
		wired := c.wired()
		for _, h := range HookHarnesses {
			if slices.Contains(wired, h) && c.selected(h) {
				c.hookHarness(h)
			}
		}
		if c.wantsSetupStep(wired) {
			c.setupStep()
		}
	}
	// A pull request can commit a settings.local.json, or
	// policy.local.yaml, whether or not the base was embedded, so base
	// mode always checks them.
	if (active || opts.Base != nil) && opts.Tracked != nil {
		c.localSettings(r, opts.Tracked)
		c.policyLocal(r, opts.Tracked, opts.TrackedCaseVariants)
	}
	return c.items, c.err
}

// PolicyWeakened returns one TC-CFG-016 item for each aspect in which
// a change weakens the repository policy (policy.Weakened), on
// .tripcord/policy.yaml. raw is that file's content in the change.
func PolicyWeakened(aspects []string, raw []byte) ([]model.ConfigItem, error) {
	c := &checker{}
	for _, a := range aspects {
		c.add(model.SurfaceGeneric, PolicyPath, subjectPolicy+":"+a, "", StateWeakened, raw, map[string]string{"aspect": a})
	}
	for i := range c.items {
		c.items[i].SourcePaths = []string{PolicyPath}
	}
	return c.items, c.err
}

// localSettings checks the settings.local.json files the repository
// tracks. Claude Code and Copilot CLI apply them over the shared
// settings, so a committed one is shared configuration. Both harnesses
// merge hooks across files rather than letting a local one replace the
// shared file's, so only disableAllHooks is checked here; a local hook
// for an event Tripcord also wires still runs alongside it.
func (c *checker) localSettings(r *adapters.SafeReader, tracked func(string) bool) {
	for _, l := range localSettings {
		if !c.selected(l.harness) {
			continue
		}
		raw, err := r.ReadFile(l.path, adapters.MaxConfigFileBytes)
		if err != nil || !tracked(l.path) {
			continue
		}
		doc, _, err := kit.DecodeJSON(raw, kit.StrictJSON, string(l.harness))
		top, isObject := doc.(map[string]any)
		if err != nil || !isObject {
			continue
		}
		if off, _ := top["disableAllHooks"].(bool); off {
			c.add(l.harness, l.path, subjectLocal, "", StateLocalDisabled, raw, nil)
		}
	}
}

// policyLocal reports a git-tracked, or staged, .tripcord/policy.local.yaml,
// and any case variant of it (a differently-cased .tripcord/Policy.local.yaml
// or .TRIPCORD/policy.local.yaml). Either is a per-checkout layer; a copy the
// repository tracks overrides the effective policy for everyone who checks
// the branch out, not only the person who committed it -- a case variant
// does so on a case-insensitive checkout (macOS, Windows), where the policy
// loader's own os.ReadFile(PolicyLocalPath) resolves to it behind git's
// back, even though git's tracking of PolicyLocalPath itself (what tracked
// checks) never folds case -- so the scan does not load either (see
// cmd/tripcord's SkipLocal wiring) and reports every one of them here
// instead, each at its own real path, whatever the host filesystem.
func (c *checker) policyLocal(r *adapters.SafeReader, tracked func(string) bool, caseVariants func(string) []string) {
	paths := []string{}
	switch {
	case caseVariants != nil:
		paths = caseVariants(PolicyLocalPath)
	case tracked(PolicyLocalPath):
		paths = []string{PolicyLocalPath}
	}
	for _, p := range paths {
		raw, err := r.ReadFile(p, adapters.MaxConfigFileBytes)
		if err != nil {
			continue
		}
		c.add(model.SurfaceGeneric, p, subjectPolicyLocal, "", StateLocalPolicy, raw, nil)
	}
}

type checker struct {
	head, base *revision
	// leftover is set when only pieces of an embed remain: the check
	// then reports the embed's own files and the wiring of the
	// harnesses those pieces name, not harnesses nothing wired.
	leftover *leftover
	only     []model.Harness
	items    []model.ConfigItem
	err      error
}

func (c *checker) selected(h model.Harness) bool {
	return len(c.only) == 0 || slices.Contains(c.only, h)
}

// wired is the hook harnesses to check, plus copilot when it is wired.
func (c *checker) wired() []model.Harness {
	var names []string
	switch {
	case c.leftover != nil:
		return c.leftover.harnesses
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
	case f.linked:
		c.add(model.SurfaceGeneric, ManifestPath, subjectManifest, "", StateChanged, f.raw, nil)
		return
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
	case f.linked:
		c.add(model.SurfaceGeneric, path, subject, "", StateChanged, f.raw, nil)
	case !f.exists():
		c.add(model.SurfaceGeneric, path, subject, "", c.absent(c.base != nil && c.base.files[path].exists()), nil, nil)
	case f.state != "":
		c.add(model.SurfaceGeneric, path, subject, "", StateUnreadable, nil, nil)
	case c.head.manifestOK:
		want := digest(render(c.head.manifest))
		if state := compare(digest(c.head.contentBytes(f.raw)), want, c.head.manifest.recordedFile(path, "")); state != "" {
			c.add(model.SurfaceGeneric, path, subject, "", state, f.raw, nil)
		}
	}
}

// contentBytes is raw with CRLF normalized to LF, unless t.blob: a git
// blob was read with no checkout filter, so a CRLF there is never given
// the uniform-autocrlf-checkout leniency lf otherwise applies.
func (t *revision) contentBytes(raw []byte) []byte {
	if t.blob {
		return raw
	}
	return lf(raw)
}

// gitattributesTargets are the paths gitattributesLines pins to
// text eol=lf.
func gitattributesTargets() []string {
	return []string{BootstrapPath, ManifestPath, WorkflowPath, CopilotHooksPath}
}

// gitattributesState is the text and eol attributes raw resolves for
// path, matching only the exact literal pattern mergeGitattributes
// writes ("/"+path): Git resolves an attribute by the last matching
// pattern in the file, per attribute name, so a later line for the same
// pattern overrides an earlier one, including ours.
func gitattributesState(raw []byte, path string) (text, eol string) {
	pattern := "/" + path
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") || fields[0] != pattern {
			continue
		}
		for _, attr := range fields[1:] {
			switch {
			case attr == "text":
				text = "text"
			case attr == "-text" || attr == "!text":
				text = attr
			case strings.HasPrefix(attr, "eol="):
				eol = attr
			}
		}
	}
	return text, eol
}

// gitattributesOK reports whether raw resolves text eol=lf for every
// path gitattributesTargets lists.
func gitattributesOK(raw []byte) bool {
	for _, path := range gitattributesTargets() {
		text, eol := gitattributesState(raw, path)
		if text != "text" || eol != "eol=lf" {
			return false
		}
	}
	return true
}

// gitattributes checks that .gitattributes still pins every embed file
// bash runs, or that the check hashes, to text eol=lf: removing those
// lines, or a later line that overrides text or eol for the same
// pattern (-text, eol=crlf), lets a checkout, or a committed file,
// carry a CR that bash sees but a uniformly-converted digest would not.
func (c *checker) gitattributes() {
	f := c.head.files[GitattributesPath]
	switch {
	case f.linked:
		c.add(model.SurfaceGeneric, GitattributesPath, subjectGitattributes, "", StateChanged, f.raw, nil)
		return
	case !f.exists():
		baseHad := c.base != nil && c.base.files[GitattributesPath].exists() && gitattributesOK(c.base.files[GitattributesPath].raw)
		c.add(model.SurfaceGeneric, GitattributesPath, subjectGitattributes, "", c.absent(baseHad), nil, nil)
		return
	case f.state != "":
		c.add(model.SurfaceGeneric, GitattributesPath, subjectGitattributes, "", StateUnreadable, nil, nil)
		return
	}
	if !gitattributesOK(f.raw) {
		c.add(model.SurfaceGeneric, GitattributesPath, subjectGitattributes, "", StateChanged, f.raw, nil)
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

// wantsSetupStep reports the Copilot setup step only when it is part of
// the guard. Default init does not write that file, so a repository
// that never opted in is not reported for a step it was never given. A
// step the head or base manifest records, or a step still present in
// the file, stays checked.
func (c *checker) wantsSetupStep(wired []model.Harness) bool {
	if !slices.Contains(wired, model.HarnessCopilot) || !c.selected(model.HarnessCopilot) {
		return false
	}
	return manifestRecordsStep(c.head) || manifestRecordsStep(c.base) ||
		c.head.hasTripcordStep() || (c.base != nil && c.base.hasTripcordStep())
}

func manifestRecordsStep(t *revision) bool {
	return t != nil && t.manifestOK && t.manifest.recordedFile(CopilotSetupStepsPath, copilotStepName) != ""
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
		SourcePaths: slices.Clone(sourcePaths),
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
