package schemas_test

import (
	"encoding/json"
	"fmt"
	"sort"
)

// breakingChanges reports non-additive edits from base to next.
// An empty result means next can replace base on the v1 schema.
func breakingChanges(base, next any) []string {
	var errs []string
	diffSchema(base, next, "$", &errs)
	sort.Strings(errs)
	return errs
}

func diffSchema(base, next any, path string, errs *[]string) {
	baseObj, baseOK := base.(map[string]any)
	nextObj, nextOK := next.(map[string]any)
	if !baseOK || !nextOK {
		if canon(base) != canon(next) {
			*errs = append(*errs, path+": schema form changed")
		}
		return
	}
	diffEqual(baseObj, nextObj, "$id", path, errs)
	diffEqual(baseObj, nextObj, "$schema", path, errs)
	diffType(baseObj, nextObj, path, errs)
	diffConst(baseObj, nextObj, path, errs)
	diffEnum(baseObj, nextObj, path, errs)
	diffRef(baseObj, nextObj, path, errs)
	diffRelax(baseObj, nextObj, "pattern", path, errs)
	diffRelax(baseObj, nextObj, "format", path, errs)
	for _, key := range []string{"minimum", "minLength", "minItems", "minProperties", "exclusiveMinimum"} {
		diffBound(baseObj, nextObj, key, path, true, errs)
	}
	for _, key := range []string{"maximum", "maxLength", "maxItems", "maxProperties", "exclusiveMaximum"} {
		diffBound(baseObj, nextObj, key, path, false, errs)
	}
	diffAdditional(baseObj, nextObj, path, errs)
	diffItems(baseObj, nextObj, path, errs)
	diffProperties(baseObj, nextObj, path, errs)
	diffUnknown(baseObj, nextObj, path, errs)
}

func diffEqual(base, next map[string]any, key, path string, errs *[]string) {
	if canon(base[key]) != canon(next[key]) {
		*errs = append(*errs, fmt.Sprintf("%s: %s changed", path, key))
	}
}

func diffType(base, next map[string]any, path string, errs *[]string) {
	baseSet, baseOK, err := typeSet(base["type"], hasKey(base, "type"))
	if err != nil {
		*errs = append(*errs, path+": "+err.Error())
		return
	}
	nextSet, nextOK, err := typeSet(next["type"], hasKey(next, "type"))
	if err != nil {
		*errs = append(*errs, path+": "+err.Error())
		return
	}
	if !baseOK && !nextOK {
		return
	}
	if !baseOK && nextOK {
		*errs = append(*errs, path+": type added")
		return
	}
	if baseOK && !nextOK {
		return
	}
	var missing []string
	for name := range baseSet {
		if _, ok := nextSet[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		*errs = append(*errs, fmt.Sprintf("%s: type narrowed, missing %s", path, name))
	}
}

func typeSet(v any, present bool) (map[string]struct{}, bool, error) {
	if !present {
		return nil, false, nil
	}
	switch typed := v.(type) {
	case string:
		return map[string]struct{}{typed: {}}, true, nil
	case []any:
		set := make(map[string]struct{}, len(typed))
		for _, item := range typed {
			name, ok := item.(string)
			if !ok {
				return nil, true, fmt.Errorf("type entry is not a string")
			}
			set[name] = struct{}{}
		}
		return set, true, nil
	default:
		return nil, true, fmt.Errorf("type is not a string or array")
	}
}

func diffConst(base, next map[string]any, path string, errs *[]string) {
	baseValue, baseOK := base["const"]
	nextValue, nextOK := next["const"]
	if !baseOK && !nextOK {
		return
	}
	if baseOK && !nextOK {
		return
	}
	if !baseOK || canon(baseValue) != canon(nextValue) {
		*errs = append(*errs, path+": const changed")
	}
}

func diffEnum(base, next map[string]any, path string, errs *[]string) {
	baseValue, baseOK := base["enum"]
	nextValue, nextOK := next["enum"]
	if !baseOK && !nextOK {
		return
	}
	if baseOK && !nextOK {
		return
	}
	if !baseOK {
		*errs = append(*errs, path+": enum added")
		return
	}
	baseSet, err := enumSet(baseValue)
	if err != nil {
		*errs = append(*errs, path+": "+err.Error())
		return
	}
	nextSet, err := enumSet(nextValue)
	if err != nil {
		*errs = append(*errs, path+": "+err.Error())
		return
	}
	var missing []string
	for value := range baseSet {
		if _, ok := nextSet[value]; !ok {
			missing = append(missing, value)
		}
	}
	sort.Strings(missing)
	for _, value := range missing {
		*errs = append(*errs, fmt.Sprintf("%s: enum removed %s", path, value))
	}
}

func enumSet(v any) (map[string]struct{}, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("enum is not an array")
	}
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[canon(item)] = struct{}{}
	}
	return set, nil
}

func diffRef(base, next map[string]any, path string, errs *[]string) {
	baseValue, baseOK := base["$ref"]
	nextValue, nextOK := next["$ref"]
	if !baseOK && !nextOK {
		return
	}
	if !baseOK || !nextOK || canon(baseValue) != canon(nextValue) {
		*errs = append(*errs, path+": $ref changed")
	}
}

func diffRelax(base, next map[string]any, key, path string, errs *[]string) {
	baseValue, baseOK := base[key]
	nextValue, nextOK := next[key]
	if !baseOK && !nextOK {
		return
	}
	if baseOK && !nextOK {
		return
	}
	if !baseOK {
		*errs = append(*errs, fmt.Sprintf("%s: %s added", path, key))
		return
	}
	if canon(baseValue) != canon(nextValue) {
		*errs = append(*errs, fmt.Sprintf("%s: %s changed", path, key))
	}
}

func diffBound(base, next map[string]any, key, path string, lowerTight bool, errs *[]string) {
	baseValue, baseOK := base[key]
	nextValue, nextOK := next[key]
	if !baseOK && !nextOK {
		return
	}
	if baseOK && !nextOK {
		return
	}
	if !baseOK {
		*errs = append(*errs, fmt.Sprintf("%s: %s added", path, key))
		return
	}
	baseNumber, baseIs := baseValue.(float64)
	nextNumber, nextIs := nextValue.(float64)
	if !baseIs || !nextIs {
		*errs = append(*errs, fmt.Sprintf("%s: %s is not a number", path, key))
		return
	}
	tightened := (lowerTight && nextNumber > baseNumber) || (!lowerTight && nextNumber < baseNumber)
	if tightened {
		*errs = append(*errs, fmt.Sprintf("%s: %s tightened", path, key))
	}
}

func diffAdditional(base, next map[string]any, path string, errs *[]string) {
	baseMode, baseSchema, err := additionalMode(base["additionalProperties"], hasKey(base, "additionalProperties"))
	if err != nil {
		*errs = append(*errs, path+": "+err.Error())
		return
	}
	nextMode, nextSchema, err := additionalMode(next["additionalProperties"], hasKey(next, "additionalProperties"))
	if err != nil {
		*errs = append(*errs, path+": "+err.Error())
		return
	}
	switch baseMode + "->" + nextMode {
	case "open->open", "closed->closed", "closed->open", "schema->open":
		return
	case "schema->schema":
		diffSchema(baseSchema, nextSchema, path+".additionalProperties", errs)
	default:
		*errs = append(*errs, path+": additionalProperties narrowed")
	}
}

func additionalMode(v any, present bool) (string, map[string]any, error) {
	if !present {
		return "open", nil, nil
	}
	switch typed := v.(type) {
	case bool:
		if typed {
			return "open", nil, nil
		}
		return "closed", nil, nil
	case map[string]any:
		return "schema", typed, nil
	default:
		return "", nil, fmt.Errorf("additionalProperties has an unsupported form")
	}
}

func diffItems(base, next map[string]any, path string, errs *[]string) {
	baseValue, baseOK := base["items"]
	nextValue, nextOK := next["items"]
	switch {
	case !baseOK && !nextOK:
		return
	case baseOK && !nextOK:
		return
	case !baseOK:
		*errs = append(*errs, path+": items added")
	default:
		diffSchema(baseValue, nextValue, path+".items", errs)
	}
}

func diffProperties(base, next map[string]any, path string, errs *[]string) {
	baseProps, err := objectMap(base["properties"])
	if err != nil {
		*errs = append(*errs, path+": properties "+err.Error())
		return
	}
	nextProps, err := objectMap(next["properties"])
	if err != nil {
		*errs = append(*errs, path+": properties "+err.Error())
		return
	}
	for _, name := range unionKeys(baseProps, nextProps) {
		baseProp, baseOK := baseProps[name]
		nextProp, nextOK := nextProps[name]
		switch {
		case baseOK && !nextOK:
			*errs = append(*errs, path+"."+name+": removed property")
		case !baseOK:
			continue
		default:
			diffSchema(baseProp, nextProp, path+"."+name, errs)
		}
	}
	baseReq, err := stringSet(base["required"])
	if err != nil {
		*errs = append(*errs, path+": required "+err.Error())
		return
	}
	nextReq, err := stringSet(next["required"])
	if err != nil {
		*errs = append(*errs, path+": required "+err.Error())
		return
	}
	for _, name := range sortedKeys(nextReq) {
		if _, ok := baseReq[name]; !ok {
			*errs = append(*errs, path+"."+name+": added required field")
		}
	}
}

func diffUnknown(base, next map[string]any, path string, errs *[]string) {
	seen := map[string]struct{}{}
	for key := range base {
		seen[key] = struct{}{}
	}
	for key := range next {
		seen[key] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for key := range seen {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		if knownSchemaKey(key) {
			continue
		}
		if canon(base[key]) != canon(next[key]) {
			*errs = append(*errs, fmt.Sprintf("%s: %s changed", path, key))
		}
	}
}

func knownSchemaKey(key string) bool {
	switch key {
	case "$id", "$schema", "$comment", "title", "description", "examples", "default",
		"type", "const", "enum", "$ref", "pattern", "format",
		"minimum", "minLength", "minItems", "minProperties", "exclusiveMinimum",
		"maximum", "maxLength", "maxItems", "maxProperties", "exclusiveMaximum",
		"additionalProperties", "items", "properties", "required":
		return true
	default:
		return false
	}
}

func hasKey(obj map[string]any, key string) bool {
	_, ok := obj[key]
	return ok
}

func objectMap(v any) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("is not an object")
	}
	return obj, nil
}

func stringSet(v any) (map[string]struct{}, error) {
	if v == nil {
		return map[string]struct{}{}, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("is not an array")
	}
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		name, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("entry is not a string")
		}
		set[name] = struct{}{}
	}
	return set, nil
}

func unionKeys(left, right map[string]any) []string {
	seen := map[string]struct{}{}
	for key := range left {
		seen[key] = struct{}{}
	}
	for key := range right {
		seen[key] = struct{}{}
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]struct{}) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func canon(v any) string {
	encoded, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("invalid:%T", v)
	}
	return string(encoded)
}
