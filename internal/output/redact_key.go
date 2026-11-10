package output

import (
	"bytes"
	"encoding/json"
	"strings"
)

// redactEvidenceKey applies redact to the strings an evidence key
// encodes. An adapter encodes the key as a compact JSON array whose parts
// include the command of the entry (kit.EvidenceKey), and JSON hides what
// a redactor keys on: a quote is \", a newline is \n, a character can be
// \u-escaped. So a key that is JSON is decoded, every string in it is
// redacted as the plain text it is, and it is encoded again only when
// redaction changed one, which keeps every other key byte for byte and
// keeps a redacted key valid JSON. A key that is not JSON, such as the
// "matcher|command" string the rules engine derives, is redacted as text.
func redactEvidenceKey(key string, redact Redactor) string {
	if key == "" {
		return key
	}
	decoded, ok := decodeJSONKey(key)
	if !ok {
		return redact(key)
	}
	redacted, changed := redactJSONStrings(decoded, redact)
	if !changed {
		return key
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		return redact(key)
	}
	return string(encoded)
}

// decodeJSONKey decodes key when it is one JSON array or object.
func decodeJSONKey(key string) (any, bool) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" || (trimmed[0] != '[' && trimmed[0] != '{') {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil || decoder.More() {
		return nil, false
	}
	return decoded, true
}

// redactJSONStrings returns value with redact applied to every string and
// object name in it, and whether any of them changed.
func redactJSONStrings(value any, redact Redactor) (any, bool) {
	switch v := value.(type) {
	case string:
		out := redact(v)
		return out, out != v
	case []any:
		changed := false
		out := make([]any, len(v))
		for i, item := range v {
			var itemChanged bool
			out[i], itemChanged = redactJSONStrings(item, redact)
			changed = changed || itemChanged
		}
		return out, changed
	case map[string]any:
		changed := false
		out := make(map[string]any, len(v))
		for name, item := range v {
			redactedName := redact(name)
			redactedItem, itemChanged := redactJSONStrings(item, redact)
			out[redactedName] = redactedItem
			changed = changed || itemChanged || redactedName != name
		}
		return out, changed
	default:
		return value, false
	}
}
