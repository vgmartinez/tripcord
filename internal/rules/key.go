package rules

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// configEvidenceKey derives the optional evidence key from the config
// payload. It is empty when the payload does not carry one. The key is
// content, never a position in the file:
//
//   - a task uses payload.label
//   - an MCP server uses payload.name
//   - a hook uses payload.matcher and payload.command joined by "|"
//
// Other kinds have no key. A value that is not a JSON string is ignored.
func configEvidenceKey(item model.ConfigItem) string {
	if len(bytes.TrimSpace(item.Payload)) == 0 {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(item.Payload, &payload); err != nil {
		return ""
	}
	switch item.Kind {
	case model.ConfigKindTask:
		return jsonString(payload["label"])
	case model.ConfigKindMCPServer:
		return jsonString(payload["name"])
	case model.ConfigKindHook:
		matcher := jsonString(payload["matcher"])
		command := jsonString(payload["command"])
		if matcher == "" && command == "" {
			return ""
		}
		return matcher + "|" + command
	default:
		return ""
	}
}

func jsonString(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}
