package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// event.json and finding.json are the tripcord.event/v1 and
// tripcord.finding/v1 samples from the technical spec.

func TestEventSampleRoundTrip(t *testing.T) {
	t.Parallel()
	raw := readTestdata(t, "event.json")
	var ev Event
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		t.Fatal(err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	if ev.Schema != SchemaEvent || ev.ID != "evt_01JD7Q2M9X" {
		t.Fatalf("id = %s schema = %s", ev.ID, ev.Schema)
	}
	wantTS := time.Date(2026, 10, 31, 7, 41, 12, 384000000, time.UTC)
	if !ev.TS.Equal(wantTS) {
		t.Fatalf("ts = %s", ev.TS.Format(time.RFC3339Nano))
	}
	if ev.Source.Harness != HarnessClaude || ev.Source.Surface != "cloud" || ev.Source.Version != "2.1.310" || ev.Source.Origin != "hook:PreToolUse" {
		t.Fatalf("source = %+v", ev.Source)
	}
	if ev.Session.ID != "00893aaf-19fa-41d2" || ev.Session.Repo != "acme/api" || ev.Session.Branch != "claude/fix-auth" || ev.Session.Actor != "agent" || ev.Session.Parent != nil {
		t.Fatalf("session = %+v", ev.Session)
	}
	if ev.Kind != EventKindToolCall || ev.Tool != "shell" || ev.Command != "cat /proc/$PPID/environ" {
		t.Fatalf("kind=%s tool=%s command=%s", ev.Kind, ev.Tool, ev.Command)
	}
	if len(ev.Paths) != 1 || ev.Paths[0] != "/proc/1234/environ" || len(ev.Net) != 0 || len(ev.Credentials) != 0 || ev.Redactions != 0 {
		t.Fatalf("paths=%v net=%v creds=%v redactions=%d", ev.Paths, ev.Net, ev.Credentials, ev.Redactions)
	}
	if ev.RawRef != "transcript:~/.claude/projects/-repo/00893aaf.jsonl#L418" {
		t.Fatalf("raw_ref = %s", ev.RawRef)
	}

	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, raw, out)
	var again Event
	if err := json.Unmarshal(out, &again); err != nil {
		t.Fatal(err)
	}
	out2, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("remarshal = %s", out2)
	}
	if !bytes.Contains(out, []byte(`"redactions":0`)) || !bytes.Contains(out, []byte(`"parent":null`)) || !bytes.Contains(out, []byte(`"ts":"2026-10-31T07:41:12.384Z"`)) {
		t.Fatalf("marshal = %s", out)
	}

	idx := loadSchemaIndex(t)
	if err := idx.validate(SchemaEvent, raw); err != nil {
		t.Fatal(err)
	}
	if err := idx.validate(SchemaEvent, out); err != nil {
		t.Fatal(err)
	}
}

func TestEventNilSlicesMarshalAsArrays(t *testing.T) {
	t.Parallel()
	var ev Event
	if err := json.Unmarshal(readTestdata(t, "event.json"), &ev); err != nil {
		t.Fatal(err)
	}
	ev.Paths = nil
	ev.Net = nil
	ev.Credentials = nil
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Paths != nil || ev.Net != nil || ev.Credentials != nil {
		t.Fatal("MarshalJSON mutated the value")
	}
	for _, fragment := range []string{`"paths":[]`, `"net":[]`, `"credentials":[]`} {
		if !bytes.Contains(out, []byte(fragment)) {
			t.Fatalf("missing %s in %s", fragment, out)
		}
	}
	if err := loadSchemaIndex(t).validate(SchemaEvent, out); err != nil {
		t.Fatal(err)
	}
}

func TestEventDropsSecretFields(t *testing.T) {
	t.Parallel()
	var ev Event
	if err := json.Unmarshal(readTestdata(t, "event.json"), &ev); err != nil {
		t.Fatal(err)
	}
	ev.Net = []NetEvent{{
		Host:   "evil.example",
		Method: "GET",
		URL:    "https://evil.example/a",
	}}
	ev.Credentials = []CredentialRef{{
		Fingerprint: "hmac-1",
		Last4:       "wxyz",
		Provider:    "github",
	}}
	wire := map[string]any{}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire["net"] = []any{map[string]any{"host": "evil.example", "token": "sekrit-token"}}
	wire["credentials"] = []any{map[string]any{"fingerprint": "hmac-1", "value": "sekrit-value", "secret": "sekrit-secret"}}
	open, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadSchemaIndex(t).validate(SchemaEvent, open); err != nil {
		t.Fatal(err)
	}
	var decoded Event
	if err := json.Unmarshal(open, &decoded); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("sekrit-token")) || bytes.Contains(out, []byte("sekrit-value")) || bytes.Contains(out, []byte("sekrit-secret")) {
		t.Fatalf("secret survived marshal: %s", out)
	}
	if decoded.Net[0].Host != "evil.example" || decoded.Credentials[0].Fingerprint != "hmac-1" {
		t.Fatalf("kept fields = net:%+v cred:%+v", decoded.Net, decoded.Credentials)
	}
}

func TestFindingSampleRoundTrip(t *testing.T) {
	t.Parallel()
	raw := readTestdata(t, "finding.json")
	var finding Finding
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&finding); err != nil {
		t.Fatal(err)
	}
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	if finding.Schema != SchemaFinding || finding.Rule != "TC-SEC-018" || finding.Severity != SeverityCritical || finding.Decision != DecisionDeny {
		t.Fatalf("%+v", finding)
	}
	if finding.Title != "El agente intentó leer el entorno de otro proceso" {
		t.Fatalf("title = %s", finding.Title)
	}
	if finding.Fix != "Ejecuta el agente con PID namespace propio o hidepid=2" {
		t.Fatalf("fix = %s", finding.Fix)
	}
	if finding.Fingerprint != "tcf_8c1e77" {
		t.Fatalf("stored fingerprint = %s", finding.Fingerprint)
	}
	if finding.Confidence != 0.95 {
		t.Fatalf("confidence = %v", finding.Confidence)
	}
	if finding.Location.Harness != HarnessClaude || finding.Location.Session != "00893aaf-19fa-41d2" || finding.Location.Path != "" || finding.Location.Line != nil {
		t.Fatalf("location = %+v", finding.Location)
	}
	if len(finding.Evidence) != 1 || finding.Evidence[0].Event != "evt_01JD7Q2M9X" || finding.Evidence[0].Excerpt != "cat /proc/$PPID/environ" {
		t.Fatalf("evidence = %+v", finding.Evidence)
	}
	if len(finding.Refs) != 1 || finding.Refs[0] != "https://novee.security/blog/breaking-ai-agent-sandboxes/" {
		t.Fatalf("refs = %+v", finding.Refs)
	}

	out, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONEqual(t, raw, out)
	if !bytes.Contains(out, []byte(`"confidence":0.95`)) || !bytes.Contains(out, []byte(`"fingerprint":"tcf_8c1e77"`)) {
		t.Fatalf("marshal = %s", out)
	}
	var again Finding
	if err := json.Unmarshal(out, &again); err != nil {
		t.Fatal(err)
	}
	out2, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("remarshal = %s", out2)
	}
	idx := loadSchemaIndex(t)
	if err := idx.validate(SchemaFinding, raw); err != nil {
		t.Fatal(err)
	}
	if err := idx.validate(SchemaFinding, out); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	t.Parallel()
	var ev Event
	if err := json.Unmarshal(readTestdata(t, "event.json"), &ev); err != nil {
		t.Fatal(err)
	}
	parent := "parent-session"
	session := Session{
		Schema: SchemaSession,
		ID:     ev.Session.ID,
		Origin: OriginCloud,
		Repo:   ev.Session.Repo,
		Branch: ev.Session.Branch,
		Actor:  ev.Session.Actor,
		Parent: &parent,
		Events: []Event{ev},
	}
	if err := session.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	idx := loadSchemaIndex(t)
	if err := idx.validate(SchemaSession, out); err != nil {
		t.Fatal(err)
	}
	var again Session
	if err := json.Unmarshal(out, &again); err != nil {
		t.Fatal(err)
	}
	if err := again.Validate(); err != nil {
		t.Fatal(err)
	}
	out2, err := json.Marshal(again)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("remarshal = %s", out2)
	}
	if again.Origin != OriginCloud || again.ID != ev.Session.ID || len(again.Events) != 1 || again.Events[0].ID != ev.ID {
		t.Fatalf("session = %+v", again)
	}
	if again.Parent == nil || *again.Parent != parent {
		t.Fatalf("parent = %v", again.Parent)
	}

	empty := Session{Schema: SchemaSession, ID: "s", Origin: OriginImported}
	if err := empty.Validate(); err != nil {
		t.Fatal(err)
	}
	emptyOut, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(emptyOut, []byte(`"events":[]`)) || !bytes.Contains(emptyOut, []byte(`"parent":null`)) {
		t.Fatalf("empty = %s", emptyOut)
	}
	if err := idx.validate(SchemaSession, emptyOut); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsClosedFields(t *testing.T) {
	t.Parallel()
	var ev Event
	if err := json.Unmarshal(readTestdata(t, "event.json"), &ev); err != nil {
		t.Fatal(err)
	}
	ev.Source.Harness = SurfaceVSCode
	if err := ev.Validate(); err == nil {
		t.Fatal("vscode accepted as event harness")
	}
	var finding Finding
	if err := json.Unmarshal(readTestdata(t, "finding.json"), &finding); err != nil {
		t.Fatal(err)
	}
	finding.Location.Harness = SurfaceVSCode
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	finding.Decision = "enforce"
	if err := finding.Validate(); err == nil {
		t.Fatal("enforce accepted as a decision")
	}
}

func assertJSONEqual(t *testing.T, want, got []byte) {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(want, &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &right); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("json mismatch\n got %s\nwant %s", got, want)
	}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
