package windsurf

import (
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
)

// file is one Windsurf hooks, MCP, or rules file being normalized.
type file struct {
	*kit.Source
}

// hookActions are the handler fields that say what a Cascade hook runs:
// a shell command, or its PowerShell form on Windows.
var hookActions = []string{"command", "powershell"}

// hookEvents are the documented Cascade hook events. A handler under any
// other name is still emitted, and reported.
//
// Reviewed against https://docs.windsurf.com/windsurf/cascade/hooks on
// 2026-10-31.
var hookEvents = map[string]bool{
	"pre_read_code":                         true,
	"post_read_code":                        true,
	"pre_write_code":                        true,
	"post_write_code":                       true,
	"pre_run_command":                       true,
	"post_run_command":                      true,
	"pre_mcp_tool_use":                      true,
	"post_mcp_tool_use":                     true,
	"pre_user_prompt":                       true,
	"post_cascade_response":                 true,
	"post_cascade_response_with_transcript": true,
	"post_setup_worktree":                   true,
}

func (f *file) object(raw []byte, what string) (map[string]any, bool) {
	tree, warnings, err := kit.DecodeJSON(raw, kit.JSONC, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid JSON: %v", err)
		return nil, false
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		f.Warn("%s must be a JSON object", what)
	}
	return obj, ok
}

// hooks normalizes a hooks.json: {"hooks": {"pre_run_command":
// [{"command", "powershell", "show_output", "working_directory"}]}}.
// Each handler becomes one hook item. A pre_* hook that exits 2 blocks
// the action, so every handler is reported, whatever its event.
func (f *file) hooks(raw []byte) {
	obj, ok := f.object(raw, "hooks file")
	if !ok {
		return
	}
	hooks, ok := obj["hooks"]
	if !ok {
		f.Warn("hooks file has no hooks object")
		return
	}
	if events, ok := hooks.(map[string]any); ok {
		for _, event := range kit.SortedKeys(events) {
			if !hookEvents[event] {
				f.Warn("hooks.%s is not a documented Cascade hook event; its handlers are reported as written", event)
			}
		}
	}
	f.Hooks(hooks, kit.Flat, hookActions)
}

// mcpConfig normalizes mcp_config.json: {"mcpServers": {name: {"command",
// "args", "env"} or {"serverUrl", "headers"}}}. ${env:NAME} and
// ${file:path} placeholders are reported as written, never expanded.
func (f *file) mcpConfig(raw []byte) {
	obj, ok := f.object(raw, "mcp_config.json")
	if !ok {
		return
	}
	servers, ok := obj["mcpServers"]
	if !ok {
		f.Warn("mcp_config.json has no mcpServers object")
		return
	}
	f.MCPServers(servers, "mcpServers")
}
