package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublishedSchemaIDs(t *testing.T) {
	t.Parallel()
	idx := loadSchemaIndex(t)
	for _, id := range []string{SchemaEvent, SchemaFinding, SchemaSession} {
		schema, ok := idx.byID[id]
		if !ok {
			t.Fatalf("missing %s", id)
		}
		if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("%s dialect = %v", id, schema["$schema"])
		}
		comment, _ := schema["$comment"].(string)
		if !strings.Contains(comment, "Apache-2.0") {
			t.Fatalf("%s comment = %q", id, comment)
		}
	}
}

func TestSchemaEnumsMatchGo(t *testing.T) {
	t.Parallel()
	idx := loadSchemaIndex(t)
	event := idx.byID[SchemaEvent]
	finding := idx.byID[SchemaFinding]
	session := idx.byID[SchemaSession]

	assertEnum(t, subSchema(t, event, "source", "harness"), harnessStrings(productHarnesses))
	ids := make([]Harness, 0, len(productHarnesses)+len(surfaces))
	ids = append(ids, productHarnesses...)
	ids = append(ids, surfaces...)
	assertEnum(t, subSchema(t, finding, "location", "harness"), harnessStrings(ids))
	assertEnum(t, subSchema(t, finding, "severity"), severityStrings())
	assertEnum(t, subSchema(t, finding, "decision"), decisionStrings())
	assertEnum(t, subSchema(t, session, "origin"), originStrings())
}

func TestSchemaRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()
	idx := loadSchemaIndex(t)
	event := mustObject(t, readTestdata(t, "event.json"))
	finding := mustObject(t, readTestdata(t, "finding.json"))

	delete(event, "id")
	expectSchemaError(t, idx, SchemaEvent, event, "required property is missing")

	event = mustObject(t, readTestdata(t, "event.json"))
	event["extra"] = true
	expectSchemaError(t, idx, SchemaEvent, event, "unexpected property")

	event = mustObject(t, readTestdata(t, "event.json"))
	source := event["source"].(map[string]any)
	source["harness"] = "vscode"
	expectSchemaError(t, idx, SchemaEvent, event, "not in the enum")

	event = mustObject(t, readTestdata(t, "event.json"))
	event["ts"] = "yesterday"
	expectSchemaError(t, idx, SchemaEvent, event, "date-time")

	event = mustObject(t, readTestdata(t, "event.json"))
	event["redactions"] = 1.5
	expectSchemaError(t, idx, SchemaEvent, event, "does not match type")

	finding["severity"] = "info"
	expectSchemaError(t, idx, SchemaFinding, finding, "not in the enum")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["decision"] = "enforce"
	expectSchemaError(t, idx, SchemaFinding, finding, "not in the enum")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["confidence"] = 1.2
	expectSchemaError(t, idx, SchemaFinding, finding, "above maximum")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["fingerprint"] = "abc"
	expectSchemaError(t, idx, SchemaFinding, finding, "does not match pattern")

	session := map[string]any{
		"schema": SchemaSession,
		"id":     "s",
		"origin": "remote",
		"events": []any{},
	}
	expectSchemaError(t, idx, SchemaSession, session, "not in the enum")

	var ev any
	if err := json.Unmarshal(readTestdata(t, "event.json"), &ev); err != nil {
		t.Fatal(err)
	}
	badEvent := ev.(map[string]any)
	delete(badEvent, "id")
	session["origin"] = "local"
	session["events"] = []any{badEvent}
	expectSchemaError(t, idx, SchemaSession, session, "required property is missing")
}

func TestAuditRejectsUnsupportedKeyword(t *testing.T) {
	t.Parallel()
	err := auditSchemaNode(map[string]any{"oneOf": []any{}}, "$")
	if err == nil || !strings.Contains(err.Error(), "oneOf") {
		t.Fatalf("audit = %v", err)
	}
}

func expectSchemaError(t *testing.T, idx *schemaIndex, id string, doc map[string]any, fragment string) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	err = idx.validate(id, raw)
	if err == nil || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("validate %s error = %v, want %q", id, err, fragment)
	}
}

func mustObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func subSchema(t *testing.T, schema map[string]any, names ...string) map[string]any {
	t.Helper()
	cur := schema
	for _, name := range names {
		props, ok := cur["properties"].(map[string]any)
		if !ok {
			t.Fatalf("no properties before %s", name)
		}
		next, ok := props[name].(map[string]any)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		cur = next
	}
	return cur
}

func assertEnum(t *testing.T, schema map[string]any, want []string) {
	t.Helper()
	raw, ok := schema["enum"].([]any)
	if !ok {
		t.Fatalf("enum missing in %v", schema)
	}
	got := map[string]struct{}{}
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("enum value %v", item)
		}
		got[text] = struct{}{}
	}
	if len(got) != len(want) {
		t.Fatalf("enum = %v, want %v", got, want)
	}
	for _, item := range want {
		if _, ok := got[item]; !ok {
			t.Fatalf("enum missing %s in %v", item, got)
		}
	}
}

func harnessStrings(list []Harness) []string {
	out := make([]string, len(list))
	for i, item := range list {
		out[i] = string(item)
	}
	return out
}

func severityStrings() []string {
	out := make([]string, len(severityOrder))
	for i, item := range severityOrder {
		out[i] = string(item)
	}
	return out
}

func decisionStrings() []string {
	out := make([]string, len(decisions))
	for i, item := range decisions {
		out[i] = string(item)
	}
	return out
}

func originStrings() []string {
	out := make([]string, len(origins))
	for i, item := range origins {
		out[i] = string(item)
	}
	return out
}
