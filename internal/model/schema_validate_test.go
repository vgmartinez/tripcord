package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// schemaIndex validates documents against the published JSON Schemas.
// It covers the keyword subset those files use: type, const, enum,
// properties, required, additionalProperties (boolean only), items,
// minLength, minimum, maximum, minItems, pattern, format (date-time
// only), $ref, oneOf, if/then, and not. oneOf runs the full check
// against each branch and requires exactly one to succeed; a branch is
// any schema this validator otherwise supports (for example
// {"required":[...]}), not a distinct oneOf-only syntax. if/then applies
// then only when the instance validates against if; else is not
// supported. not succeeds when the instance fails the subschema. It
// does NOT implement the rest of 2020-12: no anyOf/allOf, no
// $dynamicRef or $defs, no patternProperties, dependentRequired,
// unevaluatedProperties, multipleOf, uniqueItems, contains, or other
// formats. A schema file
// that uses an unsupported keyword fails to load (see
// auditSchemaNode), so a schema change cannot silently go unchecked by
// this validator; it either stays inside this subset or the loader
// rejects it and a contributor notices in review. Extend both
// schemaKeywords and the matching check function together if a v1.x
// schema needs a keyword this validator does not yet cover.
//
// byID keys on each schema's JSON-Schema $id (an absolute URI, for
// example "https://schemas.tripcord.invalid/tripcord.event/v1"), which
// is separate from the document-level "schema" field a Tripcord record
// carries (for example SchemaEvent, "tripcord.event/v1"). The schemaID*
// constants below name the $id values; Schema*  name the document field
// values.
type schemaIndex struct {
	byID map[string]map[string]any
}

// schemaID* are the JSON-Schema $id values, used to key schemaIndex.byID
// and as the id argument to validate. They intentionally use the
// reserved ".invalid" TLD (RFC 2606): $id only needs to be a syntactically
// absolute URI so $ref resolves; it is not meant to be dereferenced over
// the network, and the project does not control a real tripcord.* domain.
const (
	schemaIDEvent   = "https://schemas.tripcord.invalid/tripcord.event/v1"
	schemaIDFinding = "https://schemas.tripcord.invalid/tripcord.finding/v1"
	schemaIDSession = "https://schemas.tripcord.invalid/tripcord.session/v1"
)

func loadSchemaIndex(t requireFatal) *schemaIndex {
	t.Helper()
	idx, err := readSchemaIndex(filepath.Join(repoRoot(t), "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

type requireFatal interface {
	Helper()
	Fatal(args ...any)
}

func repoRoot(t requireFatal) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readSchemaIndex(dir string) (*schemaIndex, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	idx := &schemaIndex{byID: map[string]map[string]any{}}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".schema.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := walkSchema(schema, name, auditSchemaNode); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		id, _ := schema["$id"].(string)
		if id == "" {
			return nil, fmt.Errorf("%s: missing $id", name)
		}
		if _, exists := idx.byID[id]; exists {
			return nil, fmt.Errorf("duplicate schema id %s", id)
		}
		idx.byID[id] = schema
	}
	if err := idx.resolveRefs(); err != nil {
		return nil, err
	}
	return idx, nil
}

func (idx *schemaIndex) resolveRefs() error {
	for id, schema := range idx.byID {
		err := walkSchema(schema, id, func(node map[string]any, path string) error {
			ref, ok := node["$ref"].(string)
			if !ok {
				return nil
			}
			if _, exists := idx.byID[ref]; !exists {
				return fmt.Errorf("%s: unresolved $ref %q", path, ref)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (idx *schemaIndex) validate(id string, raw []byte) error {
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		return err
	}
	return idx.validateValue(id, instance)
}

func (idx *schemaIndex) validateValue(id string, instance any) error {
	schema, ok := idx.byID[id]
	if !ok {
		return fmt.Errorf("unknown schema %s", id)
	}
	return idx.check(schema, instance, "$", 0)
}

func (idx *schemaIndex) check(schema map[string]any, instance any, path string, depth int) error {
	if depth > 32 {
		return fmt.Errorf("%s: schema $ref too deep", path)
	}
	if ref, ok := schema["$ref"].(string); ok {
		target, ok := idx.byID[ref]
		if !ok {
			return fmt.Errorf("%s: unknown $ref %q", path, ref)
		}
		if err := idx.check(target, instance, path, depth+1); err != nil {
			return err
		}
		if !siblingConstraints(schema) {
			return nil
		}
		local := make(map[string]any, len(schema)-1)
		for key, value := range schema {
			if key != "$ref" {
				local[key] = value
			}
		}
		return idx.check(local, instance, path, depth+1)
	}
	if raw, ok := schema["type"]; ok {
		matches, err := typeMatches(raw, instance)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if !matches {
			return fmt.Errorf("%s: value does not match type", path)
		}
	}
	if value, ok := schema["const"]; ok && !reflect.DeepEqual(value, instance) {
		return fmt.Errorf("%s: value does not match const", path)
	}
	if err := checkEnum(schema, instance, path); err != nil {
		return err
	}
	if text, ok := instance.(string); ok {
		if err := checkString(schema, text, path); err != nil {
			return err
		}
	}
	if number, ok := instance.(float64); ok {
		if err := checkNumber(schema, number, path); err != nil {
			return err
		}
	}
	if err := idx.checkOneOf(schema, instance, path, depth); err != nil {
		return err
	}
	if err := idx.checkIfThen(schema, instance, path, depth); err != nil {
		return err
	}
	if err := idx.checkNot(schema, instance, path, depth); err != nil {
		return err
	}
	switch value := instance.(type) {
	case map[string]any:
		return idx.checkObject(schema, value, path, depth)
	case []any:
		return idx.checkArray(schema, value, path, depth)
	default:
		return nil
	}
}

// checkOneOf requires exactly one of schema's oneOf branches to match
// instance. A branch is itself a schema, checked with the same check
// function, so a branch may use any keyword this validator supports.
func (idx *schemaIndex) checkOneOf(schema map[string]any, instance any, path string, depth int) error {
	raw, ok := schema["oneOf"]
	if !ok {
		return nil
	}
	branches, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s: schema oneOf is not an array", path)
	}
	matched := 0
	var lastErr error
	for i, b := range branches {
		branch, ok := b.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: oneOf[%d] is not an object", path, i)
		}
		if err := idx.check(branch, instance, path, depth+1); err != nil {
			lastErr = err
			continue
		}
		matched++
	}
	switch matched {
	case 1:
		return nil
	case 0:
		return fmt.Errorf("%s: value matches no oneOf branch (last: %v)", path, lastErr)
	default:
		return fmt.Errorf("%s: value matches more than one oneOf branch", path)
	}
}

// checkIfThen applies schema.then when the instance validates against
// schema.if. A failing if means the condition does not hold, which is
// not an error. else is not supported.
func (idx *schemaIndex) checkIfThen(schema map[string]any, instance any, path string, depth int) error {
	rawIf, hasIf := schema["if"]
	rawThen, hasThen := schema["then"]
	if !hasIf && !hasThen {
		return nil
	}
	if !hasIf {
		return fmt.Errorf("%s: then without if", path)
	}
	ifSchema, ok := rawIf.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: if is not an object", path)
	}
	if err := idx.check(ifSchema, instance, path, depth+1); err != nil {
		return nil
	}
	if !hasThen {
		return nil
	}
	thenSchema, ok := rawThen.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: then is not an object", path)
	}
	return idx.check(thenSchema, instance, path+".then", depth+1)
}

// checkNot requires the instance to fail schema.not.
func (idx *schemaIndex) checkNot(schema map[string]any, instance any, path string, depth int) error {
	raw, ok := schema["not"]
	if !ok {
		return nil
	}
	sub, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: not is not an object", path)
	}
	if err := idx.check(sub, instance, path, depth+1); err != nil {
		return nil
	}
	return fmt.Errorf("%s: value matched not", path)
}

func siblingConstraints(schema map[string]any) bool {
	for key := range schema {
		switch key {
		case "$ref", "$schema", "$id", "$comment", "title", "description":
			continue
		default:
			return true
		}
	}
	return false
}

func typeMatches(raw, instance any) (bool, error) {
	switch typed := raw.(type) {
	case string:
		return matchType(typed, instance)
	case []any:
		if len(typed) == 0 {
			return false, errors.New("type array is empty")
		}
		for _, item := range typed {
			name, ok := item.(string)
			if !ok {
				return false, errors.New("type entry is not a string")
			}
			ok, err := matchType(name, instance)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, errors.New("type is not a string or array")
	}
}

func matchType(name string, instance any) (bool, error) {
	switch name {
	case "object":
		_, ok := instance.(map[string]any)
		return ok, nil
	case "array":
		_, ok := instance.([]any)
		return ok, nil
	case "string":
		_, ok := instance.(string)
		return ok, nil
	case "number":
		_, ok := instance.(float64)
		return ok, nil
	case "integer":
		number, ok := instance.(float64)
		if !ok || math.IsInf(number, 0) || number != math.Trunc(number) {
			return false, nil
		}
		return true, nil
	case "boolean":
		_, ok := instance.(bool)
		return ok, nil
	case "null":
		return instance == nil, nil
	default:
		return false, fmt.Errorf("unknown type %q", name)
	}
}

func checkEnum(schema map[string]any, instance any, path string) error {
	raw, ok := schema["enum"]
	if !ok {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("%s: schema enum is not an array", path)
	}
	for _, item := range items {
		if reflect.DeepEqual(item, instance) {
			return nil
		}
	}
	encoded, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("%s: value is not in the enum", path)
	}
	return fmt.Errorf("%s: value %s is not in the enum", path, encoded)
}

func checkString(schema map[string]any, text, path string) error {
	if raw, ok := schema["minLength"]; ok {
		min, ok := wholeNumber(raw)
		if !ok {
			return fmt.Errorf("%s: schema minLength is invalid", path)
		}
		if utf8.RuneCountInString(text) < min {
			return fmt.Errorf("%s: value is shorter than minLength", path)
		}
	}
	if raw, ok := schema["pattern"].(string); ok {
		re, err := regexp.Compile(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if !re.MatchString(text) {
			return fmt.Errorf("%s: value does not match pattern", path)
		}
	}
	if schema["format"] == "date-time" {
		if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
			return fmt.Errorf("%s: value does not match format date-time", path)
		}
	}
	return nil
}

func checkNumber(schema map[string]any, number float64, path string) error {
	if raw, ok := schema["minimum"]; ok {
		bound, ok := raw.(float64)
		if !ok {
			return fmt.Errorf("%s: schema minimum is invalid", path)
		}
		if number < bound {
			return fmt.Errorf("%s: value is below minimum", path)
		}
	}
	if raw, ok := schema["maximum"]; ok {
		bound, ok := raw.(float64)
		if !ok {
			return fmt.Errorf("%s: schema maximum is invalid", path)
		}
		if number > bound {
			return fmt.Errorf("%s: value is above maximum", path)
		}
	}
	return nil
}

func (idx *schemaIndex) checkObject(schema map[string]any, obj map[string]any, path string, depth int) error {
	if raw, ok := schema["required"]; ok {
		names, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("%s: schema required is not an array", path)
		}
		for _, item := range names {
			name, ok := item.(string)
			if !ok {
				return fmt.Errorf("%s: schema required entry is not a string", path)
			}
			if _, exists := obj[name]; !exists {
				return fmt.Errorf("%s.%s: required property is missing", path, name)
			}
		}
	}
	props, _ := schema["properties"].(map[string]any)
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if props != nil {
			if raw, ok := props[name]; ok {
				child, ok := raw.(map[string]any)
				if !ok {
					return fmt.Errorf("%s.%s: property schema is not an object", path, name)
				}
				if err := idx.check(child, obj[name], path+"."+name, depth+1); err != nil {
					return err
				}
				continue
			}
		}
		if raw, ok := schema["additionalProperties"]; ok {
			allowed, ok := raw.(bool)
			if !ok {
				return fmt.Errorf("%s: additionalProperties is not a boolean", path)
			}
			if !allowed {
				return fmt.Errorf("%s.%s: unexpected property", path, name)
			}
		}
	}
	return nil
}

func (idx *schemaIndex) checkArray(schema map[string]any, items []any, path string, depth int) error {
	if raw, ok := schema["minItems"]; ok {
		min, ok := wholeNumber(raw)
		if !ok {
			return fmt.Errorf("%s: schema minItems is invalid", path)
		}
		if len(items) < min {
			return fmt.Errorf("%s: array is shorter than minItems", path)
		}
	}
	raw, ok := schema["items"]
	if !ok {
		return nil
	}
	itemSchema, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: items schema is not an object", path)
	}
	for i, item := range items {
		if err := idx.check(itemSchema, item, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
			return err
		}
	}
	return nil
}

func wholeNumber(v any) (int, bool) {
	number, ok := v.(float64)
	if !ok || number < 0 || number != math.Trunc(number) || number > float64(math.MaxInt) {
		return 0, false
	}
	return int(number), true
}

var schemaAnnotations = map[string]struct{}{
	"$comment":    {},
	"title":       {},
	"description": {},
}

var schemaKeywords = map[string]struct{}{
	"$schema":              {},
	"$id":                  {},
	"$ref":                 {},
	"type":                 {},
	"const":                {},
	"enum":                 {},
	"properties":           {},
	"required":             {},
	"additionalProperties": {},
	"items":                {},
	"minLength":            {},
	"minimum":              {},
	"maximum":              {},
	"minItems":             {},
	"pattern":              {},
	"format":               {},
	"oneOf":                {},
	"if":                   {},
	"then":                 {},
	"not":                  {},
}

func auditSchemaNode(schema map[string]any, path string) error {
	for key := range schema {
		if _, ok := schemaAnnotations[key]; ok {
			continue
		}
		if _, ok := schemaKeywords[key]; !ok {
			return fmt.Errorf("%s: unsupported keyword %q", path, key)
		}
	}
	if raw, ok := schema["format"]; ok && raw != "date-time" {
		return fmt.Errorf("%s: unsupported format %v", path, raw)
	}
	if raw, ok := schema["pattern"].(string); ok {
		if _, err := regexp.Compile(raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	if raw, ok := schema["additionalProperties"]; ok {
		if _, isBool := raw.(bool); !isBool {
			return fmt.Errorf("%s: additionalProperties must be a boolean", path)
		}
	}
	if raw, ok := schema["$ref"]; ok {
		if _, isString := raw.(string); !isString {
			return fmt.Errorf("%s: $ref must be a string", path)
		}
	}
	return nil
}

func walkSchema(schema map[string]any, path string, fn func(map[string]any, string) error) error {
	if err := fn(schema, path); err != nil {
		return err
	}
	if raw, ok := schema["properties"]; ok {
		props, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: properties is not an object", path)
		}
		names := make([]string, 0, len(props))
		for name := range props {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child, ok := props[name].(map[string]any)
			if !ok {
				return fmt.Errorf("%s.%s: property schema is not an object", path, name)
			}
			if err := walkSchema(child, path+"."+name, fn); err != nil {
				return err
			}
		}
	}
	if raw, ok := schema["items"]; ok {
		child, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: items schema is not an object", path)
		}
		if err := walkSchema(child, path+".items", fn); err != nil {
			return err
		}
	}
	for _, key := range []string{"if", "then", "not"} {
		raw, ok := schema[key]
		if !ok {
			continue
		}
		child, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s.%s: not an object", path, key)
		}
		if err := walkSchema(child, path+"."+key, fn); err != nil {
			return err
		}
	}
	if raw, ok := schema["oneOf"]; ok {
		branches, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("%s: oneOf is not an array", path)
		}
		for i, b := range branches {
			child, ok := b.(map[string]any)
			if !ok {
				return fmt.Errorf("%s.oneOf[%d]: not an object", path, i)
			}
			if err := walkSchema(child, fmt.Sprintf("%s.oneOf[%d]", path, i), fn); err != nil {
				return err
			}
		}
	}
	return nil
}
