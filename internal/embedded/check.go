package embedded

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/model"
)

// Guard states a TC-CFG-016 item reports.
const (
	// StateMissing: the wiring file, or the hook in it, is not there.
	StateMissing = "missing"
	// StateChanged: the event still has a hook that names tripcord, or the
	// manifest records the hook, but no entry matches what init wrote.
	StateChanged = "changed"
	// StateUnreadable: the wiring file could not be read or parsed.
	StateUnreadable = "unreadable"
)

// Present reports whether root holds a Tripcord embed: the bootstrap
// script or the embed manifest. A policy file alone is what
// `tripcord init` without --embed writes, and is not an embed.
func Present(root string) (bool, error) {
	r, err := adapters.NewSafeReader(root)
	if err != nil {
		return false, err
	}
	defer func() { _ = r.Close() }()
	return present(r), nil
}

func present(r *adapters.SafeReader) bool {
	for _, p := range []string{BootstrapPath, ManifestPath} {
		if _, err := r.Stat(p); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}

// Check returns one repository config item for every Tripcord hook that
// a Tripcord embed in root expects and that is missing, changed, or
// unreadable. The items are TC-CFG-016 permissions items (setting
// GuardSetting) at the hook's wiring file. only, when not empty, limits
// the check to those harnesses.
//
// The harnesses checked are the hook harnesses the manifest records.
// A manifest that is missing or unreadable checks every hook harness,
// and a recorded digest that differs from the one this build writes
// counts as changed.
func Check(root string, only []model.Harness) ([]model.ConfigItem, error) {
	r, err := adapters.NewSafeReader(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	if !present(r) {
		return nil, nil
	}
	harnesses := HookHarnesses
	recorded := map[string]string{}
	if m, ok := readManifest(r); ok {
		harnesses = nil
		for _, h := range HookHarnesses {
			if slices.Contains(m.Harnesses, string(h)) {
				harnesses = append(harnesses, h)
			}
		}
		for _, hook := range m.Hooks {
			recorded[hook.Harness+"\x00"+hook.Event] = hook.SHA256
		}
	}
	var items []model.ConfigItem
	for _, h := range harnesses {
		if len(only) > 0 && !slices.Contains(only, h) {
			continue
		}
		path := HookPath(h)
		raw, readErr := r.ReadFile(path, adapters.MaxConfigFileBytes)
		var hooks map[string]any
		state := ""
		switch {
		case errors.Is(readErr, fs.ErrNotExist):
			state = StateMissing
		case readErr != nil:
			state = StateUnreadable
		default:
			syntax := kit.StrictJSON
			if h == model.HarnessCursor {
				syntax = kit.JSONC
			}
			doc, _, err := kit.DecodeJSON(raw, syntax, string(h))
			top, ok := doc.(map[string]any)
			if err != nil || !ok {
				state = StateUnreadable
				break
			}
			hooks, _ = top["hooks"].(map[string]any)
		}
		for _, e := range HookEntries(h) {
			s := state
			if s == "" {
				s = entryState(e, hooks, recorded)
			}
			if s == "" {
				continue
			}
			item, err := guardItem(e, s, raw)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
	}
	return items, nil
}

func readManifest(r *adapters.SafeReader) (Manifest, bool) {
	raw, err := r.ReadFile(ManifestPath, adapters.MaxConfigFileBytes)
	if err != nil {
		return Manifest{}, false
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Schema != ManifestSchema {
		return Manifest{}, false
	}
	return m, true
}

// entryState is "" when hooks.<e.Event> holds an entry identical to e
// and the manifest, if it records e, records e's digest.
func entryState(e HookEntry, hooks map[string]any, recorded map[string]string) string {
	want := e.SHA256()
	if got, ok := recorded[string(e.Harness)+"\x00"+e.Event]; ok && got != want {
		return StateChanged
	}
	list, _ := hooks[e.Event].([]any)
	changed := false
	for _, v := range list {
		n := anyNode(v)
		if n.equal(e.entry) {
			return ""
		}
		if namesTripcord(n) {
			changed = true
		}
	}
	if changed {
		return StateChanged
	}
	return StateMissing
}

func guardItem(e HookEntry, state string, raw []byte) (model.ConfigItem, error) {
	key, err := json.Marshal([]string{GuardSetting, e.Event})
	if err != nil {
		return model.ConfigItem{}, err
	}
	payload, err := json.Marshal(map[string]string{
		"setting": GuardSetting,
		"event":   e.Event,
		"state":   state,
		"sha256":  e.SHA256(),
		"key":     string(key),
	})
	if err != nil {
		return model.ConfigItem{}, err
	}
	sum := sha256.Sum256(raw)
	return model.ConfigItem{
		Harness: e.Harness,
		Scope:   model.ScopeRepo,
		Path:    e.Path,
		SHA256:  hex.EncodeToString(sum[:]),
		Kind:    model.ConfigKindPermissions,
		Payload: payload,
		// Whether this item exists depends on the embed files too: a
		// staged change to either one must report it.
		SourcePaths: []string{BootstrapPath, ManifestPath},
	}, nil
}

// anyNode converts a kit.DecodeJSON value into a node.
func anyNode(v any) *node {
	switch t := v.(type) {
	case map[string]any:
		n := &node{kind: kindObject}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
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
