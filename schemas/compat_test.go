package schemas_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestV1SchemasStayCompatibleWithBaseline(t *testing.T) {
	t.Parallel()
	dir := schemasDir(t)
	live := schemaNames(t, dir)
	base := schemaNames(t, filepath.Join(dir, "testdata", "baseline"))
	required := []string{
		"tripcord.event.v1.schema.json",
		"tripcord.finding.v1.schema.json",
		"tripcord.session.v1.schema.json",
	}
	for _, name := range required {
		if !containsName(live, name) || !containsName(base, name) {
			t.Fatalf("missing %s live=%v baseline=%v", name, live, base)
		}
	}
	if !reflect.DeepEqual(live, base) {
		t.Fatalf("live %v baseline %v", live, base)
	}
	for _, name := range live {
		current := loadSchema(t, filepath.Join(dir, name))
		accepted := loadSchema(t, filepath.Join(dir, "testdata", "baseline", name))
		if errs := breakingChanges(accepted, current); len(errs) != 0 {
			t.Fatalf("%s: %s", name, strings.Join(errs, "\n"))
		}
	}
}

func TestSchemaObjectsStayOpen(t *testing.T) {
	t.Parallel()
	dir := schemasDir(t)
	for _, name := range schemaNames(t, dir) {
		schema := loadSchema(t, filepath.Join(dir, name))
		assertObjectsOpen(t, schema, name+":$")
	}
}

// assertObjectsOpen walks every object-typed schema node (the root, each
// property, and each array's items) and fails if any of them sets
// additionalProperties: false. A v1 schema must stay open so that a
// reader built against an earlier v1.x minor version does not reject a
// document carrying a later, additive property.
func assertObjectsOpen(t *testing.T, node map[string]any, path string) {
	t.Helper()
	if typ, _ := node["type"].(string); typ == "object" {
		if raw, ok := node["additionalProperties"]; ok {
			if closed, isBool := raw.(bool); isBool && !closed {
				t.Fatalf("%s: additionalProperties is false; v1 object schemas must stay open", path)
			}
		}
	}
	if props, ok := node["properties"].(map[string]any); ok {
		names := make([]string, 0, len(props))
		for name := range props {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child, ok := props[name].(map[string]any)
			if !ok {
				t.Fatalf("%s.%s: property schema is not an object", path, name)
			}
			assertObjectsOpen(t, child, path+"."+name)
		}
	}
	if items, ok := node["items"].(map[string]any); ok {
		assertObjectsOpen(t, items, path+".items")
	}
}

func TestSchemaIDsAreAbsoluteURIs(t *testing.T) {
	t.Parallel()
	for _, name := range schemaNames(t, schemasDir(t)) {
		schema := loadLive(t, name)
		id, _ := schema["$id"].(string)
		if !strings.HasPrefix(id, "https://") {
			t.Fatalf("%s: $id = %q, want an absolute https:// URI so $ref resolves in ajv or check-jsonschema", name, id)
		}
	}
	session := loadLive(t, "tripcord.session.v1.schema.json")
	ref := object(t, object(t, props(t, session)["events"])["items"])["$ref"]
	event := loadLive(t, "tripcord.event.v1.schema.json")
	if ref != event["$id"] {
		t.Fatalf("session events.items.$ref = %v, want event's $id %v", ref, event["$id"])
	}
}

func TestSchemaReadmeRequiresV2ForBreakingChanges(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(schemasDir(t), "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"v2", "testdata/baseline", "optional property"} {
		if !bytesContains(raw, fragment) {
			t.Fatalf("schemas/README.md missing %q", fragment)
		}
	}
}

func TestRemovingPropertyIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	delete(props(t, next), "command")
	expectBreak(t, base, next, "command: removed property")
}

func TestRenameIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	fields := props(t, next)
	fields["cmd"] = fields["command"]
	delete(fields, "command")
	expectBreak(t, base, next, "command: removed property")
}

func TestNestedRemovalIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	source := object(t, props(t, next)["source"])
	delete(props(t, source), "version")
	expectBreak(t, base, next, "version: removed property")
}

func TestTypeChangeIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	object(t, props(t, next)["command"])["type"] = "integer"
	expectBreak(t, base, next, "type narrowed")
}

func TestNarrowingEnumIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.finding.v1.schema.json")
	next := cloneSchema(t, base)
	severity := object(t, props(t, next)["severity"])
	severity["enum"] = []any{"medium", "high", "critical"}
	expectBreak(t, base, next, `enum removed "low"`)
}

func TestWideningEnumIsAllowed(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.finding.v1.schema.json")
	next := cloneSchema(t, base)
	severity := object(t, props(t, next)["severity"])
	severity["enum"] = []any{"low", "medium", "high", "critical", "info"}
	expectAllowed(t, base, next)
}

func TestAddingOptionalPropertyIsAllowed(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	props(t, next)["note"] = map[string]any{"type": "string"}
	expectAllowed(t, base, next)

	source := object(t, props(t, next)["source"])
	props(t, source)["build"] = map[string]any{"type": "string"}
	expectAllowed(t, base, next)
}

func TestAddingRequiredFieldIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	props(t, next)["note"] = map[string]any{"type": "string"}
	next["required"] = append(next["required"].([]any), "note")
	expectBreak(t, base, next, "note: added required field")
}

func TestRequiringOptionalFieldIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.finding.v1.schema.json")
	next := cloneSchema(t, base)
	location := object(t, props(t, next)["location"])
	location["required"] = append(location["required"].([]any), "session")
	expectBreak(t, base, next, "session: added required field")
}

func TestDroppingRequiredIsAllowed(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	var kept []any
	for _, item := range next["required"].([]any) {
		if item != "raw_ref" {
			kept = append(kept, item)
		}
	}
	next["required"] = kept
	expectAllowed(t, base, next)
}

func TestDescriptionChangeIsAllowed(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.session.v1.schema.json")
	next := cloneSchema(t, base)
	next["description"] = "edited description"
	expectAllowed(t, base, next)
}

func TestConstChangeIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	object(t, props(t, next)["schema"])["const"] = "tripcord.event/v2"
	expectBreak(t, base, next, "const changed")
}

func TestTypeUnionNarrowAndWiden(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.event.v1.schema.json")
	next := cloneSchema(t, base)
	parent := object(t, props(t, object(t, props(t, next)["session"]))["parent"])
	parent["type"] = "string"
	expectBreak(t, base, next, "type narrowed, missing null")

	widened := cloneSchema(t, base)
	parent = object(t, props(t, object(t, props(t, widened)["session"]))["parent"])
	parent["type"] = []any{"string", "null", "boolean"}
	expectAllowed(t, base, widened)
}

func TestRefChangeIsBreaking(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.session.v1.schema.json")
	next := cloneSchema(t, base)
	items := object(t, object(t, props(t, next)["events"])["items"])
	items["$ref"] = "tripcord.event/v2"
	expectBreak(t, base, next, "$ref changed")
}

func TestDroppingItemsIsAllowed(t *testing.T) {
	t.Parallel()
	base := loadLive(t, "tripcord.session.v1.schema.json")
	next := cloneSchema(t, base)
	delete(object(t, props(t, next)["events"]), "items")
	expectAllowed(t, base, next)
}

func TestBoundsPatternAndAdditionalProperties(t *testing.T) {
	t.Parallel()
	base := schemaFrom(t, `{"type":"object","properties":{"a":{"type":"string","minLength":1,"pattern":"^a"}},"additionalProperties":true}`)
	tight := schemaFrom(t, `{"type":"object","properties":{"a":{"type":"string","minLength":2,"pattern":"^a"}},"additionalProperties":true}`)
	expectBreak(t, base, tight, "minLength tightened")

	relaxed := schemaFrom(t, `{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":true}`)
	expectAllowed(t, base, relaxed)

	patterned := schemaFrom(t, `{"type":"object","properties":{"a":{"type":"string","minLength":1,"pattern":"^b"}},"additionalProperties":true}`)
	expectBreak(t, base, patterned, "pattern changed")

	closed := schemaFrom(t, `{"type":"object","properties":{"a":{"type":"string","minLength":1,"pattern":"^a"}},"additionalProperties":false}`)
	expectBreak(t, base, closed, "additionalProperties narrowed")

	opened := schemaFrom(t, `{"type":"object","additionalProperties":false}`)
	loosened := schemaFrom(t, `{"type":"object","additionalProperties":true}`)
	expectAllowed(t, opened, loosened)
}

func expectBreak(t *testing.T, base, next map[string]any, fragment string) {
	t.Helper()
	errs := breakingChanges(base, next)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, "\n"), fragment) {
		t.Fatalf("changes = %v, want %q", errs, fragment)
	}
}

func expectAllowed(t *testing.T, base, next map[string]any) {
	t.Helper()
	if errs := breakingChanges(base, next); len(errs) != 0 {
		t.Fatalf("changes = %v", errs)
	}
}

func schemasDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}

func schemaNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".schema.json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

func loadLive(t *testing.T, name string) map[string]any {
	t.Helper()
	return loadSchema(t, filepath.Join(schemasDir(t), name))
}

func loadSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return schemaFrom(t, string(raw))
}

func schemaFrom(t *testing.T, raw string) map[string]any {
	t.Helper()
	var schema map[string]any
	if err := json.Unmarshal([]byte(raw), &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func cloneSchema(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	return schemaFrom(t, string(raw))
}

func props(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	return object(t, schema["properties"])
}

func object(t *testing.T, v any) map[string]any {
	t.Helper()
	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%T is not an object", v)
	}
	return obj
}

func containsName(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func bytesContains(raw []byte, fragment string) bool {
	return strings.Contains(string(raw), fragment)
}
