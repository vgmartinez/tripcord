package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxNesting bounds JSON and YAML nesting so a deeply nested document fails
// closed instead of exhausting the stack.
const maxNesting = 64

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// decodeJSON parses one strict JSON document into a tree of map[string]any,
// []any, string, json.Number, bool, and nil.
//
// Claude Code parses settings with JSON.parse and reads keys by exact name.
// encoding/json's struct and map decoding matches keys case-insensitively
// with the last match winning, so a document carrying both "hooks" and
// "Hooks" would hide the hooks Claude runs. This decoder keeps keys exactly
// as written, lets an exact duplicate win last (JSON.parse semantics), and
// reports both exact and case-variant duplicates as warnings.
//
// A UTF-8 byte order mark, comments, and trailing commas are syntax errors,
// as they are for Claude Code.
func decodeJSON(raw []byte) (any, []string, error) {
	if bytes.HasPrefix(raw, utf8BOM) {
		return nil, nil, errors.New("JSON starts with a byte order mark")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	t := &treeDecoder{dec: dec}
	value, err := t.value(0, "")
	if err != nil {
		return nil, t.warnings, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, t.warnings, errors.New("more than one JSON value")
		}
		return nil, t.warnings, err
	}
	return value, t.warnings, nil
}

type treeDecoder struct {
	dec      *json.Decoder
	warnings []string
}

func (t *treeDecoder) value(depth int, where string) (any, error) {
	tok, err := t.dec.Token()
	if err != nil {
		return nil, err
	}
	return t.fromToken(tok, depth, where)
}

func (t *treeDecoder) fromToken(tok json.Token, depth int, where string) (any, error) {
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	if depth >= maxNesting {
		return nil, fmt.Errorf("JSON nesting exceeds %d levels", maxNesting)
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		keys := newKeySet(where)
		for t.dec.More() {
			keyTok, err := t.dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			value, err := t.value(depth+1, joinWhere(where, key))
			if err != nil {
				return nil, err
			}
			t.warnings = append(t.warnings, keys.add(key)...)
			obj[key] = value
		}
		if _, err := t.dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for t.dec.More() {
			value, err := t.value(depth+1, where+"[]")
			if err != nil {
				return nil, err
			}
			arr = append(arr, value)
		}
		if _, err := t.dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unexpected %q", delim)
	}
}

// skip consumes one value without building it.
func (t *treeDecoder) skip() error {
	depth := 0
	for {
		tok, err := t.dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > maxNesting {
					return fmt.Errorf("JSON nesting exceeds %d levels", maxNesting)
				}
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// keySet reports duplicate and case-variant keys within one object.
type keySet struct {
	where string
	exact map[string]bool
	folds map[string]string
}

func newKeySet(where string) *keySet {
	return &keySet{where: where, exact: map[string]bool{}, folds: map[string]string{}}
}

func (k *keySet) add(key string) []string {
	var warnings []string
	if k.exact[key] {
		warnings = append(warnings, fmt.Sprintf("duplicate key %q%s; the last value is used", key, k.suffix()))
	}
	fold := strings.ToLower(key)
	if prev, ok := k.folds[fold]; ok && prev != key {
		warnings = append(warnings, fmt.Sprintf("case-variant keys %q and %q%s; Claude Code reads only the exact key name", prev, key, k.suffix()))
	}
	k.exact[key] = true
	if _, ok := k.folds[fold]; !ok {
		k.folds[fold] = key
	}
	return warnings
}

func (k *keySet) suffix() string {
	if k.where == "" {
		return ""
	}
	return " in " + k.where
}

func joinWhere(where, key string) string {
	if where == "" {
		return key
	}
	return where + "." + key
}
