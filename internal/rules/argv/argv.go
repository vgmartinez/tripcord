// Package argv normalizes untrusted argv values using the string coercion
// used by JavaScript process spawning.
package argv

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Opaque is a string no rule can accidentally match. A map is opaque rather
// than coerced because agent schemas do not define an executable map value.
const Opaque = "\x00tripcord-opaque-arg\x00"

// Kind says how Value represented one argv element.
type Kind uint8

const (
	Scalar Kind = iota
	CoercedList
	OpaqueMap
	Invalid
)

// Value returns the argv text for one value. Lists recursively use
// JavaScript Array#toString semantics: nested lists flatten with commas and
// null values inside a list become empty strings. Maps remain opaque.
func Value(v any, insideList bool) (string, Kind) {
	switch x := v.(type) {
	case nil:
		if insideList {
			return "", CoercedList
		}
		return "", Invalid
	case []any:
		parts := make([]string, 0, len(x))
		kind := CoercedList
		for _, item := range x {
			s, itemKind := Value(item, true)
			if itemKind == OpaqueMap {
				return Opaque, OpaqueMap
			}
			if itemKind == Invalid {
				// null is only invalid outside a list.
				return "", Invalid
			}
			parts = append(parts, s)
			if itemKind == CoercedList {
				kind = CoercedList
			}
		}
		return strings.Join(parts, ","), kind
	case map[string]any:
		return Opaque, OpaqueMap
	default:
		s, ok := scalar(x)
		if !ok {
			return "", Invalid
		}
		return s, Scalar
	}
}

func scalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case json.Number:
		return x.String(), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	default:
		return "", false
	}
}
