package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

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
		VarConfig:  configVars(item),
		VarPayload: payload,
		VarTask:    task,
		VarEvent:   map[string]any{},
	}}, nil
}

func configVars(item model.ConfigItem) map[string]any {
	return map[string]any{
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
	return &Input{vars: map[string]any{
		VarConfig:  map[string]any{},
		VarPayload: map[string]any{},
		VarTask:    map[string]any{},
		VarEvent:   event,
	}}, nil
}

func sortedStrings(s []string) []string {
	slices.Sort(s)
	return s
}
