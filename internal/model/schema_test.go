package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublishedSchemaIDs(t *testing.T) {
	t.Parallel()
	idx := loadSchemaIndex(t)
	for _, id := range []string{schemaIDEvent, schemaIDFinding, schemaIDSession} {
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
	event := idx.byID[schemaIDEvent]
	finding := idx.byID[schemaIDFinding]
	session := idx.byID[schemaIDSession]

	assertEnum(t, subSchema(t, event, "source", "harness"), harnessStrings(productHarnesses))
	ids := make([]Harness, 0, len(productHarnesses)+len(surfaces))
	ids = append(ids, productHarnesses...)
	ids = append(ids, surfaces...)
	assertEnum(t, subSchema(t, finding, "location", "harness"), harnessStrings(ids))
	assertEnum(t, subSchema(t, finding, "location", "scope"), scopeStrings())
	assertEnum(t, subSchema(t, finding, "severity"), severityStrings())
	assertEnum(t, subSchema(t, finding, "decision"), decisionStrings())
	assertEnum(t, subSchema(t, session, "origin"), originStrings())
}

func TestFingerprintPatternMatchesSchema(t *testing.T) {
	t.Parallel()
	finding := loadSchemaIndex(t).byID[schemaIDFinding]
	pattern, _ := subSchema(t, finding, "fingerprint")["pattern"].(string)
	if pattern != fingerprintPattern.String() {
		t.Fatalf("schema pattern %q, Go pattern %q", pattern, fingerprintPattern.String())
	}
}

func TestSchemaRequiredFields(t *testing.T) {
	t.Parallel()
	event := loadSchemaIndex(t).byID[schemaIDEvent]
	if got := stringSlice(t, event["required"]); !equalSet(got, []string{"schema", "id", "ts", "source", "session", "kind"}) {
		t.Fatalf("event required = %v", got)
	}
	source := subSchema(t, event, "source")
	if got := stringSlice(t, source["required"]); !equalSet(got, []string{"harness"}) {
		t.Fatalf("source required = %v", got)
	}
	session := subSchema(t, event, "session")
	if got := stringSlice(t, session["required"]); !equalSet(got, []string{"id"}) {
		t.Fatalf("event.session required = %v", got)
	}
}

func TestSchemaObjectsAreOpenAtModelLevel(t *testing.T) {
	t.Parallel()
	idx := loadSchemaIndex(t)
	event := mustObject(t, readTestdata(t, "event.json"))
	event["extra_future_field"] = "ignored by an old reader"
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := idx.validate(schemaIDEvent, raw); err != nil {
		t.Fatalf("open event schema rejected an unknown property: %v", err)
	}
}

func TestDecisionAsk(t *testing.T) {
	t.Parallel()
	got, err := ParseDecision("ask")
	if err != nil || got != DecisionAsk || !got.Valid() {
		t.Fatalf("ParseDecision(ask) = %q, %v", got, err)
	}

	var finding Finding
	if err := json.Unmarshal(readTestdata(t, "finding.json"), &finding); err != nil {
		t.Fatal(err)
	}
	finding.Decision = DecisionAsk
	if err := finding.Validate(); err != nil {
		t.Fatalf("Validate rejected ask: %v", err)
	}

	doc := mustObject(t, readTestdata(t, "finding.json"))
	doc["decision"] = "ask"
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadSchemaIndex(t).validate(schemaIDFinding, raw); err != nil {
		t.Fatalf("schema rejected decision ask: %v", err)
	}
}

func TestSchemaRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()
	idx := loadSchemaIndex(t)
	event := mustObject(t, readTestdata(t, "event.json"))
	finding := mustObject(t, readTestdata(t, "finding.json"))

	delete(event, "id")
	expectSchemaError(t, idx, schemaIDEvent, event, "required property is missing")

	event = mustObject(t, readTestdata(t, "event.json"))
	source := event["source"].(map[string]any)
	source["harness"] = "vscode"
	expectSchemaError(t, idx, schemaIDEvent, event, "not in the enum")

	event = mustObject(t, readTestdata(t, "event.json"))
	event["ts"] = "yesterday"
	expectSchemaError(t, idx, schemaIDEvent, event, "date-time")

	event = mustObject(t, readTestdata(t, "event.json"))
	event["redactions"] = 1.5
	expectSchemaError(t, idx, schemaIDEvent, event, "does not match type")

	finding["severity"] = "info"
	expectSchemaError(t, idx, schemaIDFinding, finding, "not in the enum")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["decision"] = "enforce"
	expectSchemaError(t, idx, schemaIDFinding, finding, "not in the enum")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["confidence"] = 1.2
	expectSchemaError(t, idx, schemaIDFinding, finding, "above maximum")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["fingerprint"] = "abc"
	expectSchemaError(t, idx, schemaIDFinding, finding, "does not match pattern")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["fingerprint"] = "tcf_8c1e77"
	expectSchemaError(t, idx, schemaIDFinding, finding, "does not match pattern")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	finding["fingerprint"] = "tcf_bf8994fdb9dc73ed0"
	expectSchemaError(t, idx, schemaIDFinding, finding, "does not match pattern")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	location := finding["location"].(map[string]any)
	location["scope"] = "global"
	expectSchemaError(t, idx, schemaIDFinding, finding, "not in the enum")

	for _, path := range []string{
		"/work/repo/.vscode/tasks.json",
		"C:/Users/runner/x.json",
		`C:\Users\x`,
		"../../etc/passwd",
		`\Windows\x`,
		`\\srv\share\x`,
	} {
		finding = mustObject(t, readTestdata(t, "finding.json"))
		location = finding["location"].(map[string]any)
		delete(location, "scope")
		location["path"] = path
		expectSchemaError(t, idx, schemaIDFinding, finding, "value matched not")

		finding = mustObject(t, readTestdata(t, "finding.json"))
		location = finding["location"].(map[string]any)
		location["scope"] = "repo"
		location["path"] = path
		expectSchemaError(t, idx, schemaIDFinding, finding, "value matched not")
	}

	finding = mustObject(t, readTestdata(t, "finding.json"))
	location = finding["location"].(map[string]any)
	location["scope"] = "repo"
	location["path"] = ".vscode/tasks.json"
	if raw, err := json.Marshal(finding); err != nil {
		t.Fatal(err)
	} else if err := idx.validate(schemaIDFinding, raw); err != nil {
		t.Fatalf("repo-relative path: %v", err)
	}
	location["path"] = "a:b.json"
	if raw, err := json.Marshal(finding); err != nil {
		t.Fatal(err)
	} else if err := idx.validate(schemaIDFinding, raw); err != nil {
		t.Fatalf("colon filename: %v", err)
	}
	location["scope"] = "managed"
	location["path"] = "/etc/cursor/hooks.json"
	if raw, err := json.Marshal(finding); err != nil {
		t.Fatal(err)
	} else if err := idx.validate(schemaIDFinding, raw); err != nil {
		t.Fatalf("managed absolute path: %v", err)
	}

	finding = mustObject(t, readTestdata(t, "finding.json"))
	evidenceBoth := finding["evidence"].([]any)[0].(map[string]any)
	evidenceBoth["config"] = map[string]any{"id": "claude:repo:.claude/settings.json"}
	expectSchemaError(t, idx, schemaIDFinding, finding, "matches more than one oneOf branch")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	evidenceNoID := finding["evidence"].([]any)[0].(map[string]any)
	delete(evidenceNoID, "event")
	evidenceNoID["config"] = map[string]any{"key": "filesystem"}
	expectSchemaError(t, idx, schemaIDFinding, finding, "required property is missing")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	evidenceString := finding["evidence"].([]any)[0].(map[string]any)
	delete(evidenceString, "event")
	evidenceString["config"] = "claude:repo:.claude/settings.json"
	expectSchemaError(t, idx, schemaIDFinding, finding, "does not match type")

	finding = mustObject(t, readTestdata(t, "finding.json"))
	evidenceNeither := finding["evidence"].([]any)[0].(map[string]any)
	delete(evidenceNeither, "event")
	expectSchemaError(t, idx, schemaIDFinding, finding, "matches no oneOf branch")

	session := map[string]any{
		"schema": SchemaSession,
		"id":     "s",
		"origin": "remote",
		"events": []any{},
	}
	expectSchemaError(t, idx, schemaIDSession, session, "not in the enum")

	var ev any
	if err := json.Unmarshal(readTestdata(t, "event.json"), &ev); err != nil {
		t.Fatal(err)
	}
	badEvent := ev.(map[string]any)
	delete(badEvent, "id")
	session["origin"] = "local"
	session["events"] = []any{badEvent}
	expectSchemaError(t, idx, schemaIDSession, session, "required property is missing")
}

func TestAuditRejectsUnsupportedKeyword(t *testing.T) {
	t.Parallel()
	err := auditSchemaNode(map[string]any{"anyOf": []any{}}, "$")
	if err == nil || !strings.Contains(err.Error(), "anyOf") {
		t.Fatalf("audit = %v", err)
	}
}

func TestOneOfRequiresExactlyOneMatch(t *testing.T) {
	t.Parallel()
	idx := loadSchemaIndex(t)
	schema := map[string]any{
		"oneOf": []any{
			map[string]any{"required": []any{"event"}},
			map[string]any{"required": []any{"config"}},
		},
	}
	neither := map[string]any{"excerpt": "x"}
	if err := idx.check(schema, neither, "$", 0); err == nil {
		t.Fatal("neither branch matched, want an error")
	}
	eventOnly := map[string]any{"event": "evt_1"}
	if err := idx.check(schema, eventOnly, "$", 0); err != nil {
		t.Fatalf("event-only should match exactly one branch: %v", err)
	}
	configOnly := map[string]any{"config": "claude:repo:.claude/settings.json"}
	if err := idx.check(schema, configOnly, "$", 0); err != nil {
		t.Fatalf("config-only should match exactly one branch: %v", err)
	}
	both := map[string]any{"event": "evt_1", "config": "claude:repo:.claude/settings.json"}
	if err := idx.check(schema, both, "$", 0); err == nil {
		t.Fatal("both branches matched, want an error")
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

func stringSlice(t *testing.T, v any) []string {
	t.Helper()
	items, ok := v.([]any)
	if !ok {
		t.Fatalf("%v is not an array", v)
	}
	out := make([]string, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("entry %v is not a string", item)
		}
		out[i] = text
	}
	return out
}

func equalSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	set := make(map[string]struct{}, len(got))
	for _, item := range got {
		set[item] = struct{}{}
	}
	for _, item := range want {
		if _, ok := set[item]; !ok {
			return false
		}
	}
	return true
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

func scopeStrings() []string {
	out := make([]string, len(scopes))
	for i, item := range scopes {
		out[i] = string(item)
	}
	return out
}
