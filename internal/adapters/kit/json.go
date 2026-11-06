package kit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/jsonc"
)

// MaxNesting bounds JSON, YAML, and TOML nesting so a deeply nested
// document fails closed instead of exhausting the stack.
const MaxNesting = 64

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Syntax selects how strictly a JSON file is parsed.
type Syntax int

const (
	// StrictJSON is JSON.parse: no byte order mark, comments, or trailing
	// commas.
	StrictJSON Syntax = iota
	// JSONC is the VS Code dialect: a leading byte order mark, // and /* */
	// comments, and trailing commas are accepted.
	JSONC
)

// DecodeJSON parses one JSON document into map[string]any, []any, string,
// json.Number, bool, and nil, keeping keys exactly as written. An exact
// duplicate key wins last (JSON.parse and jsonc-parser semantics) and is
// reported; case-variant keys in one object are reported too, because a
// harness that reads exact key names would ignore one of them. folded
// names objects (dotted, as in warnings) whose keys the harness matches
// case-insensitively, such as Copilot's hook event names; case variants
// there are not reported.
func DecodeJSON(raw []byte, syntax Syntax, product string, folded ...string) (any, []string, error) {
	if syntax == JSONC {
		cleaned, err := jsonc.Strip(bytes.TrimPrefix(raw, utf8BOM))
		if err != nil {
			return nil, nil, err
		}
		raw = cleaned
	} else if bytes.HasPrefix(raw, utf8BOM) {
		return nil, nil, errors.New("JSON starts with a byte order mark")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	t := &treeDecoder{dec: dec, product: product, folded: folded}
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
	product  string
	folded   []string
	warnings []string
}

func (t *treeDecoder) value(depth int, where string) (any, error) {
	tok, err := t.dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	if depth >= MaxNesting {
		return nil, fmt.Errorf("JSON nesting exceeds %d levels", MaxNesting)
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		keys := NewKeySet(where, t.product)
		keys.foldOK = slices.Contains(t.folded, where)
		for t.dec.More() {
			keyTok, err := t.dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			value, err := t.value(depth+1, JoinWhere(where, key))
			if err != nil {
				return nil, err
			}
			t.warnings = append(t.warnings, keys.Add(key)...)
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

// KeySet reports duplicate and case-variant keys within one object.
type KeySet struct {
	where   string
	product string
	exact   map[string]bool
	folds   map[string]string
	foldOK  bool
}

// NewKeySet starts a key set for the object at where ("" for the root).
func NewKeySet(where, product string) *KeySet {
	return &KeySet{where: where, product: product, exact: map[string]bool{}, folds: map[string]string{}}
}

// Add records key and returns any warnings it causes.
func (k *KeySet) Add(key string) []string {
	var warnings []string
	if k.exact[key] {
		warnings = append(warnings, fmt.Sprintf("duplicate key %q%s; the last value is used", key, k.suffix()))
	}
	fold := strings.ToLower(key)
	if prev, ok := k.folds[fold]; ok && prev != key && !k.foldOK {
		warnings = append(warnings, fmt.Sprintf("case-variant keys %q and %q%s; %s reads only the exact key name", prev, key, k.suffix(), k.product))
	}
	k.exact[key] = true
	if _, ok := k.folds[fold]; !ok {
		k.folds[fold] = key
	}
	return warnings
}

func (k *KeySet) suffix() string {
	if k.where == "" {
		return ""
	}
	return " in " + k.where
}

// JoinWhere extends a dotted location used in warnings.
func JoinWhere(where, key string) string {
	if where == "" {
		return key
	}
	return where + "." + key
}
