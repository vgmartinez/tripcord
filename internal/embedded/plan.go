package embedded

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Options selects what init writes.
type Options struct {
	// Embed writes the bootstrap script, workflow, manifest, and harness
	// wiring. Without it, init writes only the policy file.
	Embed bool
	// Harnesses limits the wiring to these harnesses. Empty is every
	// harness in Harnesses.
	Harnesses []model.Harness
	// Pin is the version bootstrap.sh runs from the cache. Required with
	// Embed. bootstrap.sh does not download that version.
	Pin Pin
	// Force rewrites a file whose merge would reformat it or replace a
	// conflicting value. It never overrides a file that cannot be parsed.
	Force bool
	// CloudSetup writes the cloud-agent install wiring: Cursor's
	// environment.json install command, the Copilot setup step, and the
	// Devin blueprint entry. Off by default. Known gap: bootstrap.sh
	// install downloads nothing, so this wiring does not install Tripcord.
	CloudSetup bool
}

// Change is one file init would write. Old is nil when the file does
// not exist.
type Change struct {
	Path string
	Old  []byte
	New  []byte
	Mode fs.FileMode
}

// Unchanged reports whether the file already has the planned content.
func (c Change) Unchanged() bool { return c.Old != nil && bytes.Equal(c.Old, c.New) }

// FileError is a file init cannot merge. Forceable is true when
// --force would let the merge proceed.
type FileError struct {
	Path      string
	Reason    string
	Forceable bool
}

func (e *FileError) Error() string {
	if e.Forceable {
		return e.Path + ": " + e.Reason + " (rerun with --force to rewrite it)"
	}
	return e.Path + ": " + e.Reason
}

// OptionError is an invalid Options value.
type OptionError struct{ err error }

func (e *OptionError) Error() string { return e.err.Error() }

func (e *OptionError) Unwrap() error { return e.err }

// PlanError lists every file init cannot merge. Nothing is written.
type PlanError struct{ Files []*FileError }

func (e *PlanError) Error() string {
	msgs := make([]string, len(e.Files))
	for i, f := range e.Files {
		msgs[i] = f.Error()
	}
	return strings.Join(msgs, "\n")
}

type step struct {
	path  string
	mode  fs.FileMode
	merge func(old []byte, exists bool) ([]byte, error)
}

// Plan computes every file init writes in dir, without writing. It
// fails, with no changes, when any target is unsafe (ErrUnsafePath),
// cannot be read, or cannot be merged (*PlanError).
func Plan(dir string, opts Options) ([]Change, error) {
	if opts.Embed {
		if err := opts.Pin.Validate(); err != nil {
			return nil, &OptionError{err: err}
		}
	}
	harnesses := opts.Harnesses
	if len(harnesses) == 0 {
		harnesses = Harnesses
	}
	for _, h := range harnesses {
		if !slices.Contains(Harnesses, h) {
			return nil, &OptionError{err: fmt.Errorf("--harness: init cannot wire %q; want one of %s", h, harnessList())}
		}
	}
	t, err := openTree(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.close() }()
	steps := []step{{path: PolicyPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
		if exists {
			return old, nil
		}
		return DefaultPolicy(), nil
	}}}
	if opts.Embed {
		steps = append(steps, embedSteps(opts, harnesses)...)
	}
	var changes []Change
	var failed []*FileError
	for _, s := range steps {
		old, exists, mode, err := t.read(s.path)
		if err != nil {
			return nil, err
		}
		next, err := s.merge(old, exists)
		var hard *unmergeable
		switch {
		case errors.As(err, &hard):
			failed = append(failed, &FileError{Path: s.path, Reason: hard.reason})
			continue
		case errors.Is(err, errConflict):
			failed = append(failed, &FileError{Path: s.path, Reason: strings.TrimPrefix(err.Error(), errConflict.Error()+": "), Forceable: true})
			continue
		case err != nil:
			return nil, fmt.Errorf("%s: %w", s.path, err)
		}
		if !exists {
			old = nil
			mode = s.mode
		} else if s.mode&0o111 != 0 {
			mode |= 0o111
		}
		changes = append(changes, Change{Path: s.path, Old: old, New: next, Mode: mode})
	}
	if len(failed) > 0 {
		return nil, &PlanError{Files: failed}
	}
	return changes, nil
}

func embedSteps(opts Options, harnesses []model.Harness) []step {
	force := opts.Force
	steps := []step{
		{path: BootstrapPath, mode: 0o755, merge: func(old []byte, exists bool) ([]byte, error) {
			return ownFile(old, exists, Bootstrap(opts.Pin), force, "--force re-pins it to this --version and --sha256")
		}},
		{path: ManifestPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
			return mergeManifest(old, exists, opts.Pin, harnesses, force, opts.CloudSetup)
		}},
		{path: WorkflowPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
			return ownFile(old, exists, Workflow(), force, "--force replaces it")
		}},
		{path: GitattributesPath, mode: 0o644, merge: mergeGitattributes},
		{path: GitignorePath, mode: 0o644, merge: mergeGitignore},
	}
	for _, h := range Harnesses {
		if !slices.Contains(harnesses, h) {
			continue
		}
		switch h {
		case model.HarnessClaude:
			steps = append(steps, step{path: ClaudeSettingsPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
				return mergeHooks(old, exists, HookEntries(h), hookFile{disableKey: "disableAllHooks"}, force)
			}})
		case model.HarnessCursor:
			steps = append(steps, step{path: CursorHooksPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
				return mergeHooks(old, exists, HookEntries(h), hookFile{version: true}, force)
			}})
			if opts.CloudSetup {
				steps = append(steps, step{path: CursorEnvironmentPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
					return mergeCursorEnvironment(old, exists, force)
				}})
			}
		case model.HarnessCopilot:
			steps = append(steps, step{path: CopilotHooksPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
				return mergeHooks(old, exists, HookEntries(h), hookFile{version: true, disableKey: "disableAllHooks"}, force)
			}})
			if opts.CloudSetup {
				steps = append(steps, step{path: CopilotSetupStepsPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
					return mergeSetupSteps(old, exists, force)
				}})
			}
		case model.HarnessDevin:
			if opts.CloudSetup {
				steps = append(steps, step{path: DevinBlueprintPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
					return mergeBlueprint(old, exists, force)
				}})
			}
		case model.HarnessCodex:
			steps = append(steps, step{path: AgentsPath, mode: 0o644, merge: func(old []byte, exists bool) ([]byte, error) {
				return mergeAgents(old, exists, force)
			}})
		default:
			panic("unhandled init harness " + string(h))
		}
	}
	return steps
}

// mergeManifest records the union of the harnesses already wired and
// the ones this run wires.
func mergeManifest(old []byte, exists bool, pin Pin, harnesses []model.Harness, force, cloudSetup bool) ([]byte, error) {
	all := slices.Clone(harnesses)
	if exists {
		var m Manifest
		if err := json.Unmarshal(old, &m); err != nil || m.Schema != ManifestSchema {
			if !force {
				return nil, conflictf("not a %s manifest", ManifestSchema)
			}
		}
		for _, h := range m.Harnesses {
			if slices.Contains(Harnesses, model.Harness(h)) && !slices.Contains(all, model.Harness(h)) {
				all = append(all, model.Harness(h))
			}
		}
	}
	// Record the setup step only for a copilot harness this run wires.
	// A harness kept from an older manifest is not given a digest for a
	// file this run did not write.
	return newManifest(pin, all, cloudSetup && slices.Contains(harnesses, model.HarnessCopilot)).node().encode("  "), nil
}

// Apply writes every change that is not already in place. It returns
// the paths it wrote.
func Apply(dir string, changes []Change) ([]string, error) {
	t, err := openTree(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = t.close() }()
	var wrote []string
	for _, c := range changes {
		if c.Unchanged() {
			continue
		}
		if err := t.write(c.Path, c.New, c.Mode); err != nil {
			return wrote, err
		}
		wrote = append(wrote, c.Path)
	}
	return wrote, nil
}

func harnessList() string {
	names := make([]string, len(Harnesses))
	for i, h := range Harnesses {
		names[i] = string(h)
	}
	return strings.Join(names, ", ")
}
