package claude

import (
	"encoding/json"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/model"
)

// HookEvents are the `tripcord hook --event` values Claude Code wiring
// passes.
var HookEvents = []string{hook.EventPreTool}

const claudePreToolUse = "PreToolUse"

// preToolUseInput is the Claude Code PreToolUse hook JSON. Fields rules
// do not read (transcript_path, permission_mode) are ignored. cwd is the
// directory a relative tool path is resolved against.
type preToolUseInput struct {
	SessionID     string         `json:"session_id"`
	Cwd           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
}

// ParseHookInput normalizes a Claude Code hook's stdin for event.
func ParseHookInput(event string, data []byte, now time.Time) (model.Event, error) {
	if event != hook.EventPreTool {
		return model.Event{}, hook.Inputf("claude: event %q: want %s", event, hook.EventPreTool)
	}
	var in preToolUseInput
	if err := hook.DecodeObject(data, &in); err != nil {
		return model.Event{}, err
	}
	if in.HookEventName != claudePreToolUse {
		return model.Event{}, hook.Inputf("claude: hook_event_name is not %s", claudePreToolUse)
	}
	if in.ToolName == "" {
		return model.Event{}, hook.Inputf("claude: tool_name is missing")
	}
	call := hook.Call{
		Harness:   model.HarnessClaude,
		Origin:    "hook:" + claudePreToolUse,
		SessionID: in.SessionID,
		Tool:      in.ToolName,
		Input:     in.ToolInput,
		Dir:       in.Cwd,
	}
	return call.Event(data, now), nil
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

type hookOutput struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
}

// RenderDecision renders v as Claude Code PreToolUse output. deny and
// ask set hookSpecificOutput.permissionDecision with the reason; deny
// also exits 2 with the reason on stderr, which Claude Code blocks on
// whether or not it reads stdout. warn is a systemMessage. allow and
// audit print {} and never set permissionDecision "allow", which would
// skip Claude Code's own permission prompts.
func RenderDecision(_ string, v hook.Verdict) hook.Output {
	var out hookOutput
	switch v.Decision {
	case model.DecisionDeny, model.DecisionAsk:
		out.HookSpecificOutput = &hookSpecificOutput{
			HookEventName:            claudePreToolUse,
			PermissionDecision:       string(v.Decision),
			PermissionDecisionReason: v.Reason,
		}
	case model.DecisionWarn:
		out.SystemMessage = v.Reason
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
