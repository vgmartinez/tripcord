package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules/argv"
)

// Input is the set of CEL variables for one config item or one event.
// Build it once and evaluate every applicable rule against it.
type Input struct {
	vars map[string]any
}

// ConfigInput binds config, payload, and, for task items, task.
// payload is the decoded JSON payload, or an empty map when there is none.
// It is the item's Detect view when the adapter kept one, so rules match
// the text as the file wrote it; a finding is still built from the
// sanitized Payload alone (see Match.Finding), so no rule can put the
// raw text in a report.
func ConfigInput(item model.ConfigItem, limits Limits) (*Input, error) {
	id, err := item.ID()
	if err != nil {
		return nil, err
	}
	src := []byte(item.Payload)
	if item.Detect != nil {
		src = item.Detect
	}
	if n := max(len(item.Payload), len(src)); n > limits.MaxInputBytes {
		return nil, fmt.Errorf("config %s: payload is %d bytes: %w", item.Path, n, ErrInputLimit)
	}
	var payload any = map[string]any{}
	if len(bytes.TrimSpace(src)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
		dec.UseNumber()
		if err := dec.Decode(&payload); err != nil {
			return nil, fmt.Errorf("config %s: payload is not valid JSON", item.Path)
		}
		payload = normalizeNumbers(payload)
	}
	if m, ok := payload.(map[string]any); ok {
		normalizeArgValues(item, m)
	}
	task := any(map[string]any{})
	if item.Kind == model.ConfigKindTask {
		task = payload
	}
	return &Input{vars: map[string]any{
		VarConfig:  configVars(id, item),
		VarPayload: payload,
		VarTask:    task,
		VarEvent:   emptyEvent(),
	}}, nil
}

// normalizeArgValues gives CEL the argv text that supported agents pass to
// their child process. A list element follows JavaScript's recursive
// Array#toString coercion; a map is deliberately replaced with an
// unmatchable marker. The original payload remains on ConfigItem for output.
func normalizeArgValues(item model.ConfigItem, payload map[string]any) {
	if args, ok := payload["args"].([]any); ok {
		for i, value := range args {
			if text, kind := argv.Value(value, false); kind != argv.Invalid {
				args[i] = text
			}
		}
	}
	if item.Kind != model.ConfigKindMCPServer || item.Harness != model.HarnessOpenCode {
		return
	}
	command, ok := payload["command"].([]any)
	if !ok {
		return
	}
	for i, value := range command {
		if text, kind := argv.Value(value, false); kind != argv.Invalid {
			command[i] = text
		}
	}
}

// normalizeNumbers walks a decoded JSON tree and turns each json.Number
// leaf (produced by UseNumber, which never errors on an out-of-range
// literal) into the float64 a plain json.Unmarshal would have produced,
// matching the type payload rules have always compared against. A
// literal float64 cannot represent, such as 1e999, falls back to its
// original text instead of failing the whole decode: the same
// fall-back-to-string rule kit/yaml.go applies to an out-of-range YAML
// float. Without this, planting an extreme number anywhere in a scanned
// file would make ConfigInput error, which silences every finding for
// the whole scan, not just the one offending item.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeNumbers(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = normalizeNumbers(val)
		}
		return t
	case json.Number:
		if f, err := t.Float64(); err == nil && !math.IsInf(f, 0) && !math.IsNaN(f) {
			return f
		}
		return t.String()
	default:
		return v
	}
}

// emptyEvent and emptyConfig bind every always-present field, so the
// fields checkGuards lets rules read unguarded exist on both paths.
func emptyEvent() map[string]any {
	m := map[string]any{}
	fillEventFields(m)
	return m
}

func emptyConfig() map[string]any {
	m := make(map[string]any, len(configKeys))
	for _, k := range configKeys {
		m[k] = ""
	}
	m["missing_scripts"] = 0
	m["script_locations"] = []string{}
	m["checksum_files"] = map[string][]string{}
	m["checksum_symlinks"] = []string{}
	m["repo_script"] = false
	m["hidden_chars"] = 0
	return m
}

// inputHarness is the harness bound in config, or empty when the input
// has no config map. An empty harness does not accept a command array.
func inputHarness(in *Input) model.Harness {
	if in == nil {
		return ""
	}
	cfg, _ := in.vars[VarConfig].(map[string]any)
	h, _ := cfg["harness"].(string)
	return model.Harness(h)
}

func configVars(id string, item model.ConfigItem) map[string]any {
	locations := item.ScriptLocations
	if locations == nil {
		locations = []string{}
	}
	sums := item.ChecksumFiles
	if sums == nil {
		sums = map[string][]string{}
	}
	symlinks := item.ChecksumSymlinks
	if symlinks == nil {
		symlinks = []string{}
	}
	return map[string]any{
		"id":                id,
		"harness":           item.Harness.String(),
		"scope":             item.Scope.String(),
		"path":              item.Path,
		"sha256":            item.SHA256,
		"kind":              item.Kind.String(),
		"missing_scripts":   int(item.MissingScripts),
		"script_locations":  locations,
		"checksum_files":    sums,
		"checksum_symlinks": symlinks,
		"repo_script":       item.RepoScript,
		"hidden_chars":      item.Hidden.Total,
	}
}

// EventInput binds event to the tripcord.event/v1 JSON form of ev, so
// rules use the wire names (event.kind, event.tool, event.command).
// The size checked against MaxInputBytes is without HTML escaping,
// which would count each <, >, and & in a command six times.
func EventInput(ev model.Event, limits Limits) (*Input, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ev); err != nil {
		return nil, fmt.Errorf("event %s: %w", ev.ID, err)
	}
	raw := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(raw) > limits.MaxInputBytes {
		return nil, fmt.Errorf("event %s: %d bytes: %w", ev.ID, len(raw), ErrInputLimit)
	}
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("event %s: %w", ev.ID, err)
	}
	fillEventFields(event)
	return &Input{vars: map[string]any{
		VarConfig:  emptyConfig(),
		VarPayload: map[string]any{},
		VarTask:    map[string]any{},
		VarEvent:   event,
	}}, nil
}

// eventFields are the event paths EventInput always binds: every
// tripcord.event/v1 field outside the lists. Fields the wire form omits
// when empty are bound as "", so rules read them without a has() guard.
var eventFields = []string{
	"schema", "id", "ts", "kind", "tool", "command", "paths", "net", "credentials", "redactions", "raw_ref",
	"source", "source.harness", "source.surface", "source.version", "source.origin",
	"session", "session.id", "session.repo", "session.branch", "session.actor", "session.parent",
}

func fillEventFields(event map[string]any) {
	for _, f := range eventFields {
		m := event
		parts := strings.Split(f, ".")
		for _, p := range parts[:len(parts)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		if _, ok := m[parts[len(parts)-1]]; !ok {
			m[parts[len(parts)-1]] = ""
		}
	}
}

func sortedStrings(s []string) []string {
	slices.Sort(s)
	return s
}
