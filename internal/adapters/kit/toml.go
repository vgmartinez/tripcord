package kit

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// DecodeTOML parses one TOML document into the same tree shape as
// DecodeJSON: map[string]any, []any, string, int64, float64, and bool.
// Dates and times become their TOML text. Duplicate keys are a syntax
// error, as TOML requires; case-variant keys in one table are reported,
// because a harness that reads exact key names ignores one of them.
// Nesting beyond MaxNesting fails closed. A byte order mark is rejected.
func DecodeTOML(raw []byte, product string) (any, []string, error) {
	if bytes.HasPrefix(raw, utf8BOM) {
		return nil, nil, errors.New("TOML starts with a byte order mark")
	}
	var doc map[string]any
	if err := toml.Unmarshal(raw, &doc); err != nil {
		var derr *toml.DecodeError
		if errors.As(err, &derr) {
			row, col := derr.Position()
			return nil, nil, fmt.Errorf("line %d column %d: %s", row, col, derr.Error())
		}
		return nil, nil, err
	}
	var warnings []string
	value, err := tomlValue(doc, 0, "", product, &warnings)
	if err != nil {
		return nil, warnings, err
	}
	if value == nil {
		value = map[string]any{}
	}
	return value, warnings, nil
}

func tomlValue(v any, depth int, where, product string, warnings *[]string) (any, error) {
	if depth >= MaxNesting {
		return nil, fmt.Errorf("TOML nesting exceeds %d levels", MaxNesting)
	}
	switch x := v.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		keys := NewKeySet(where, product)
		for _, k := range SortedKeys(x) {
			*warnings = append(*warnings, keys.Add(k)...)
			child, err := tomlValue(x[k], depth+1, JoinWhere(where, k), product, warnings)
			if err != nil {
				return nil, err
			}
			out[k] = child
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			child, err := tomlValue(item, depth+1, where+"[]", product, warnings)
			if err != nil {
				return nil, err
			}
			out[i] = child
		}
		return out, nil
	case []map[string]any:
		out := make([]any, len(x))
		for i, item := range x {
			child, err := tomlValue(item, depth+1, where+"[]", product, warnings)
			if err != nil {
				return nil, err
			}
			out[i] = child
		}
		return out, nil
	case string, bool, int64:
		return x, nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return fmt.Sprint(x), nil
		}
		return x, nil
	case time.Time:
		return x.Format(time.RFC3339Nano), nil
	case fmt.Stringer:
		return x.String(), nil
	default:
		return fmt.Sprint(x), nil
	}
}
