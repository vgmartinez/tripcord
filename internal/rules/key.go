package rules

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// ConfigEvidenceKey derives the optional evidence key from the config
// payload. It is empty when the payload does not carry one. The key is
// content, never a position in the file:
//
//   - payload.key, when an adapter sets it, wins for every kind (adapters
//     use it to add the hook event and other discriminators that
//     matcher+command alone would collide on)
//   - a task uses payload.label
//   - an MCP server uses payload.name
//   - a hook uses payload.matcher and payload.command joined by "|"
//
// Other kinds have no key. A value that is not a JSON string is ignored.
func ConfigEvidenceKey(item model.ConfigItem) string {
	if len(bytes.TrimSpace(item.Payload)) == 0 {
		return ""
	}
	// UseNumber: a number outside float64's range (1e999) must not make
	// the whole payload undecodable, or every item in the file would
	// fall back to the same empty key and share one fingerprint.
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(item.Payload))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return ""
	}
	if key := jsonString(payload["key"]); key != "" {
		return key
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
