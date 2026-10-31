package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Input is the set of CEL variables for one config item or one event.
// Build it once and evaluate every applicable rule against it.
type Input struct {
	vars map[string]any
}

// ConfigInput binds config, payload, and, for task items, task.
// payload is the decoded JSON payload, or an empty map when there is none.
func ConfigInput(item model.ConfigItem, limits Limits) (*Input, error) {
	id, err := item.ID()
	if err != nil {
		return nil, err
	}
	if len(item.Payload) > limits.MaxInputBytes {
		return nil, fmt.Errorf("config %s: payload is %d bytes: %w", item.Path, len(item.Payload), ErrInputLimit)
	}
	var payload any = map[string]any{}
	if len(bytes.TrimSpace(item.Payload)) > 0 {
		if err := json.Unmarshal(item.Payload, &payload); err != nil {
			return nil, fmt.Errorf("config %s: payload: %w", item.Path, err)
		}
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
	return m
}

func configVars(id string, item model.ConfigItem) map[string]any {
	return map[string]any{
		"id":      id,
		"harness": item.Harness.String(),
		"scope":   item.Scope.String(),
		"path":    item.Path,
		"sha256":  item.SHA256,
		"kind":    item.Kind.String(),
	}
}

// EventInput binds event to the tripcord.event/v1 JSON form of ev, so
// rules use the wire names (event.kind, event.tool, event.command).
func EventInput(ev model.Event, limits Limits) (*Input, error) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("event %s: %w", ev.ID, err)
	}
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
