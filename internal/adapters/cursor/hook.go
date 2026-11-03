package cursor

import (
	"encoding/json"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/model"
)

// HookEvents are the `tripcord hook --event` values for Cursor hooks.json
// (version 1) events.
var HookEvents = []string{hook.EventPreTool, hook.EventBeforeShell, hook.EventBeforeRead}

// cursorEvent is the hooks.json event name for each hook event.
var cursorEvent = map[string]string{
	hook.EventPreTool:     "preToolUse",
	hook.EventBeforeShell: "beforeShellExecution",
	hook.EventBeforeRead:  "beforeReadFile",
}

// hookInput is the Cursor hook JSON for the events above. Every event
// carries the common fields (conversation_id, hook_event_name,
// cursor_version, ...); preToolUse adds tool_name and tool_input,
// beforeShellExecution command, and beforeReadFile file_path. The
// content of a file being read is never kept.
type hookInput struct {
	ConversationID string         `json:"conversation_id"`
	HookEventName  string         `json:"hook_event_name"`
	CursorVersion  string         `json:"cursor_version"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	Command        *string        `json:"command"`
	FilePath       *string        `json:"file_path"`
}

// ParseHookInput normalizes a Cursor hook's stdin for event.
func ParseHookInput(event string, data []byte, now time.Time) (model.Event, error) {
	name, ok := cursorEvent[event]
	if !ok {
		return model.Event{}, hook.Inputf("cursor: event %q: want %s, %s, or %s", event, hook.EventPreTool, hook.EventBeforeShell, hook.EventBeforeRead)
	}
	var in hookInput
	if err := hook.DecodeObject(data, &in); err != nil {
		return model.Event{}, err
	}
	if in.HookEventName != name {
		return model.Event{}, hook.Inputf("cursor: hook_event_name %q: want %s", in.HookEventName, name)
	}
	call := hook.Call{
		Harness:   model.HarnessCursor,
		Origin:    "hook:" + name,
		SessionID: in.ConversationID,
		Version:   in.CursorVersion,
	}
	switch event {
	case hook.EventPreTool:
		if in.ToolName == "" {
			return model.Event{}, hook.Inputf("cursor: tool_name is missing")
		}
		call.Tool, call.Input = in.ToolName, in.ToolInput
	case hook.EventBeforeShell:
		if in.Command == nil {
			return model.Event{}, hook.Inputf("cursor: command is missing")
		}
		call.Tool, call.Command, call.Kind = "Shell", *in.Command, model.EventKindToolCall
	case hook.EventBeforeRead:
		if in.FilePath == nil || *in.FilePath == "" {
			return model.Event{}, hook.Inputf("cursor: file_path is missing")
		}
		call.Tool, call.Paths, call.Kind = "Read", []string{*in.FilePath}, model.EventKindRead
	}
	return call.Event(data, now), nil
}

type hookOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// RenderDecision renders v as Cursor hook output: {"permission": ...}
// with the reason as user_message and agent_message. deny also exits 2
// with the reason on stderr. ask is Cursor's own prompt on
// beforeShellExecution and a deny on the events without one. warn and
// audit allow; warn keeps its message.
func RenderDecision(event string, v hook.Verdict) hook.Output {
	out := hookOutput{Permission: "allow"}
	switch v.Decision {
	case model.DecisionDeny:
		out = hookOutput{Permission: "deny", UserMessage: v.Reason, AgentMessage: v.Reason}
	case model.DecisionAsk:
		if event == hook.EventBeforeShell {
			out = hookOutput{Permission: "ask", UserMessage: v.Reason, AgentMessage: v.Reason}
		} else {
			v = hook.Verdict{Decision: model.DecisionDeny, Reason: v.Reason + " (Cursor has no confirmation prompt for this event, so the call is denied)"}
			out = hookOutput{Permission: "deny", UserMessage: v.Reason, AgentMessage: v.Reason}
		}
	case model.DecisionWarn:
		out.UserMessage = v.Reason
	case model.DecisionAllow, model.DecisionAudit:
	default:
		return hook.Output{Stderr: "tripcord hook: unknown decision " + string(v.Decision) + "\n", Exit: exitcode.Internal}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return hook.Output{Stderr: "tripcord hook: " + err.Error() + "\n", Exit: exitcode.Internal}
	}
	o := hook.Output{Stdout: append(raw, '\n'), Exit: v.Exit()}
	if v.Decision == model.DecisionDeny {
		o.Stderr = v.Reason + "\n"
	}
	return o
}
