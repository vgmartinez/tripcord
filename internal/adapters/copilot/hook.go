package copilot

import (
	"encoding/json"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/model"
)

// HookEvents are the `tripcord hook --event` values for Copilot
// (.github/hooks/*.json, the CLI and the coding agent).
var HookEvents = []string{hook.EventPreTool}

// preToolUseInput is the Copilot preToolUse hook JSON. toolArgs is the
// tool's arguments as a JSON-encoded string; an object is accepted too.
// Copilot sends no event name, so nothing in the input is checked
// against --event.
type preToolUseInput struct {
	SessionID string          `json:"sessionId"`
	ToolName  string          `json:"toolName"`
	ToolArgs  json.RawMessage `json:"toolArgs"`
}

// ParseHookInput normalizes a Copilot hook's stdin for event.
func ParseHookInput(event string, data []byte, now time.Time) (model.Event, error) {
	if event != hook.EventPreTool {
		return model.Event{}, hook.Inputf("copilot: event %q: want %s", event, hook.EventPreTool)
	}
	var in preToolUseInput
	if err := hook.DecodeObject(data, &in); err != nil {
		return model.Event{}, err
	}
	if in.ToolName == "" {
		return model.Event{}, hook.Inputf("copilot: toolName is missing")
	}
	args, err := toolArgs(in.ToolArgs)
	if err != nil {
		return model.Event{}, err
	}
	call := hook.Call{
		Harness:   model.HarnessCopilot,
		Origin:    "hook:preToolUse",
		SessionID: in.SessionID,
		Tool:      in.ToolName,
		Input:     args,
	}
	return call.Event(data, now), nil
}

func toolArgs(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		if encoded == "" {
			return nil, nil
		}
		raw = json.RawMessage(encoded)
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, hook.Inputf("copilot: toolArgs is not a JSON object: %v", err)
	}
	return args, nil
}

// RenderDecision renders v for Copilot: a deny exits 2 with the reason
// on stderr, which blocks the tool call. An ask is a deny too: the
// Copilot CLI has a native ask, but the coding agent treats one as a
// deny, and both send the same preToolUse input, so the CLI cannot be
// told apart. Everything else exits 0 with nothing on stdout;
// a warning goes to stderr.
func RenderDecision(_ string, v hook.Verdict) hook.Output {
	switch v.Decision {
	case model.DecisionDeny:
		return hook.Output{Stderr: v.Reason + "\n", Exit: exitcode.Block}
	case model.DecisionAsk:
		return hook.Output{Stderr: v.Reason + " (tripcord cannot ask on Copilot, so the call is denied)\n", Exit: exitcode.Block}
	case model.DecisionWarn:
		return hook.Output{Stderr: v.Reason + "\n", Exit: exitcode.OK}
	case model.DecisionAllow, model.DecisionAudit:
		return hook.Output{Exit: exitcode.OK}
	default:
		return hook.Output{Stderr: "tripcord hook: unknown decision " + string(v.Decision) + "\n", Exit: exitcode.Internal}
	}
}
