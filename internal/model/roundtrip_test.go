package model

import (
	"bytes"
	"encoding/json"
	"errors"
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
	if ev.Session.ID != "00893aaf-19fa-41d2" || ev.Session.Repo != "vgmartinez/api" || ev.Session.Branch != "claude/fix-auth" || ev.Session.Actor != "agent" || ev.Session.Parent != nil {
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
	if err := idx.validate(schemaIDEvent, raw); err != nil {
		t.Fatal(err)
	}
	if err := idx.validate(schemaIDEvent, out); err != nil {
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
	if err := loadSchemaIndex(t).validate(schemaIDEvent, out); err != nil {
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
	if err := loadSchemaIndex(t).validate(schemaIDEvent, open); err != nil {
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
	// The stored id is the digest Fingerprint computes for this
	// document's rule, location, and evidence. It is 16 hex digits.
	computed, err := Fingerprint(finding.Rule, finding.Location, finding.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	const sampleFingerprint = "tcf_c761c03b24e7b179"
	if computed != sampleFingerprint || !fingerprintPattern.MatchString(computed) {
		t.Fatalf("computed fingerprint = %s", computed)
	}
	if finding.Fingerprint != sampleFingerprint {
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
	if !bytes.Contains(out, []byte(`"confidence":0.95`)) || !bytes.Contains(out, []byte(`"fingerprint":"`+sampleFingerprint+`"`)) {
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
	if err := idx.validate(schemaIDFinding, raw); err != nil {
		t.Fatal(err)
	}
	if err := idx.validate(schemaIDFinding, out); err != nil {
		t.Fatal(err)
	}
}

func TestFindingFingerprintMustBeSixteenHex(t *testing.T) {
	t.Parallel()
	var finding Finding
	if err := json.Unmarshal(readTestdata(t, "finding.json"), &finding); err != nil {
		t.Fatal(err)
	}
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"tcf_8c1e77",
		"tcf_bf8994fdb9dc73e",
		"tcf_bf8994fdb9dc73ed0",
		"tcf_BF8994FDB9DC73ED",
	} {
		finding.Fingerprint = bad
		if err := finding.Validate(); err == nil {
			t.Fatalf("%s validated", bad)
		}
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
	if err := idx.validate(schemaIDSession, out); err != nil {
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
	if err := idx.validate(schemaIDSession, emptyOut); err != nil {
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
	fp, err := Fingerprint(finding.Rule, finding.Location, finding.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	finding.Fingerprint = fp
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	finding.Decision = "enforce"
	if err := finding.Validate(); err == nil {
		t.Fatal("enforce accepted as a decision")
	}
}

func TestEventMinimalRoundTrip(t *testing.T) {
	t.Parallel()
	// Only the required fields: schema, id, ts, source.harness,
	// session.id, kind. A local, non-git, non-cloud session has no
	// repo, branch, actor, surface, version, origin, tool, command, or
	// raw_ref to report.
	ev := Event{
		Schema: SchemaEvent,
		ID:     "evt_minimal",
		TS:     time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC),
		Source: Source{Harness: HarnessCodex},
		Session: EventSession{
			ID: "local-session",
		},
		Kind: EventKindRead,
	}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"surface", "version", "origin", "repo", "branch", "actor", "tool", "command", "raw_ref"} {
		if bytes.Contains(out, []byte(`"`+absent+`"`)) {
			t.Fatalf("marshal kept optional empty field %q: %s", absent, out)
		}
	}
	for _, present := range []string{`"paths":[]`, `"net":[]`, `"credentials":[]`, `"redactions":0`, `"parent":null`} {
		if !bytes.Contains(out, []byte(present)) {
			t.Fatalf("marshal missing %s: %s", present, out)
		}
	}
	if err := loadSchemaIndex(t).validate(schemaIDEvent, out); err != nil {
		t.Fatal(err)
	}
	var again Event
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
}

func TestEventValidateRequiresOnlySixFields(t *testing.T) {
	t.Parallel()
	base := Event{
		Schema:  SchemaEvent,
		ID:      "evt_1",
		TS:      time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC),
		Source:  Source{Harness: HarnessCodex},
		Session: EventSession{ID: "s"},
		Kind:    EventKindRead,
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []func(*Event){
		func(e *Event) { e.Schema = "" },
		func(e *Event) { e.ID = "" },
		func(e *Event) { e.TS = time.Time{} },
		func(e *Event) { e.Source.Harness = "" },
		func(e *Event) { e.Source.Harness = SurfaceGeneric },
		func(e *Event) { e.Session.ID = "" },
		func(e *Event) { e.Kind = "" },
		func(e *Event) { e.Redactions = -1 },
	}
	for i, mutate := range cases {
		e := base
		mutate(&e)
		if err := e.Validate(); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestEvidenceExactlyOneOfEventOrConfig(t *testing.T) {
	t.Parallel()
	base := func() Finding {
		var f Finding
		if err := json.Unmarshal(readTestdata(t, "finding.json"), &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	eventOnly := base()
	if err := eventOnly.Validate(); err != nil {
		t.Fatal(err)
	}

	configOnly := base()
	configOnly.Evidence = []Evidence{{Config: &ConfigRef{ID: "claude:repo:.claude/settings.json", Key: "filesystem"}, Excerpt: "hooks.PreToolUse"}}
	fp, err := Fingerprint(configOnly.Rule, configOnly.Location, configOnly.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	configOnly.Fingerprint = fp
	if err := configOnly.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(configOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"config":{"id":"claude:repo:.claude/settings.json","key":"filesystem"}`)) || bytes.Contains(out, []byte(`"event"`)) {
		t.Fatalf("marshal = %s", out)
	}
	if err := loadSchemaIndex(t).validate(schemaIDFinding, out); err != nil {
		t.Fatal(err)
	}

	neither := base()
	neither.Evidence = []Evidence{{Excerpt: "no id at all"}}
	if err := neither.Validate(); err == nil {
		t.Fatal("evidence with neither event nor config validated")
	}

	both := base()
	both.Evidence = []Evidence{{Event: "evt_1", Config: &ConfigRef{ID: "claude:repo:.claude/settings.json"}}}
	if err := both.Validate(); err == nil {
		t.Fatal("evidence with both event and config validated")
	}

	noExcerpt := base()
	noExcerpt.Evidence = []Evidence{{Config: &ConfigRef{ID: "claude:repo:.claude/settings.json"}}}
	fp, err = Fingerprint(noExcerpt.Rule, noExcerpt.Location, noExcerpt.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	noExcerpt.Fingerprint = fp
	if err := noExcerpt.Validate(); err != nil {
		t.Fatalf("excerpt should be optional: %v", err)
	}

	missingID := base()
	missingID.Evidence = []Evidence{{Config: &ConfigRef{Key: "filesystem"}}}
	if err := missingID.Validate(); err == nil {
		t.Fatal("config without an id validated")
	}
}

func TestLocationScopeValidate(t *testing.T) {
	t.Parallel()
	var finding Finding
	if err := json.Unmarshal(readTestdata(t, "finding.json"), &finding); err != nil {
		t.Fatal(err)
	}
	finding.Location.Scope = ScopeRepo
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	finding.Location.Scope = "global"
	if err := finding.Validate(); err == nil {
		t.Fatal("global scope validated")
	}
}

func TestFindingValidateRuleID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rule string
		want bool
	}{
		{"TC-CFG-001", true},
		{"ACME-001", true},
		{"TC-CFG-01", false},
		{"tc-cfg-001", false},
		{"TC-CFG-001\n::error", false},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			var finding Finding
			if err := json.Unmarshal(readTestdata(t, "finding.json"), &finding); err != nil {
				t.Fatal(err)
			}
			finding.Rule = tc.rule
			fingerprint, err := Fingerprint(finding.Rule, finding.Location, finding.Evidence)
			if err != nil {
				t.Fatal(err)
			}
			finding.Fingerprint = fingerprint
			if got := finding.Validate() == nil; got != tc.want {
				t.Fatalf("Validate(%q) = %t, want %t", tc.rule, got, tc.want)
			}
		})
	}
}

func TestFindingValidateLocationPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		scope Scope
		path  string
		want  error
	}{
		{"repo absolute", ScopeRepo, "/work/repo/.vscode/tasks.json", errPathNotRelative},
		{"empty scope absolute", "", "/work/repo/.vscode/tasks.json", errPathNotRelative},
		{"repo drive forward slash", ScopeRepo, "C:/Users/runner/x.json", errPathNotRelative},
		{"empty scope drive forward slash", "", "C:/Users/runner/x.json", errPathNotRelative},
		{"repo drive backslash", ScopeRepo, `C:\Users\x`, errPathNotRelative},
		{"empty scope drive backslash", "", `C:\Users\x`, errPathNotRelative},
		{"repo raw dotdot", ScopeRepo, "a/../b", errPathDotDot},
		{"empty scope raw dotdot", "", "a/../b", errPathDotDot},
		{"repo dotdot", ScopeRepo, "../../etc/passwd", errPathDotDot},
		{"empty scope dotdot", "", "../../etc/passwd", errPathDotDot},
		{"repo relative", ScopeRepo, ".vscode/tasks.json", nil},
		{"repo colon filename", ScopeRepo, "a:b.json", nil},
		{"repo dot segment", ScopeRepo, "a/./b", errPathNotNormalized},
		{"empty scope dot segment", "", "a/./b", errPathNotNormalized},
		{"repo leading dot slash", ScopeRepo, "./x", errPathNotNormalized},
		{"empty scope leading dot slash", "", "./x", errPathNotNormalized},
		{"repo double slash", ScopeRepo, "a//b", errPathNotNormalized},
		{"empty scope double slash", "", "a//b", errPathNotNormalized},
		{"user home", ScopeUser, "~/.claude/settings.json", nil},
		{"user absolute", ScopeUser, "/home/dev/.claude/settings.json", errPathNotUserHome},
		{"managed absolute", ScopeManaged, "/etc/cursor/hooks.json", nil},
		{"managed drive canonical", ScopeManaged, "C:/programdata/cursor/hooks.json", nil},
		{"managed drive not canonical", ScopeManaged, `C:\ProgramData\cursor\hooks.json`, errPathNotNormalized},
		{"managed relative", ScopeManaged, "cursor/hooks.json", errPathNotAbsolute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var finding Finding
			if err := json.Unmarshal(readTestdata(t, "finding.json"), &finding); err != nil {
				t.Fatal(err)
			}
			finding.Location.Scope = tc.scope
			finding.Location.Path = tc.path
			if tc.want == nil {
				fp, err := Fingerprint(finding.Rule, finding.Location, finding.Evidence)
				if err != nil {
					t.Fatal(err)
				}
				finding.Fingerprint = fp
			}
			err := finding.Validate()
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate(%q) err = %v, want %v", tc.path, err, tc.want)
			}
		})
	}
}

func TestFindingValidateConfigID(t *testing.T) {
	t.Parallel()
	var finding Finding
	if err := json.Unmarshal(readTestdata(t, "finding.json"), &finding); err != nil {
		t.Fatal(err)
	}
	finding.Evidence = []Evidence{{Config: &ConfigRef{ID: "/abs/../junk"}}}
	if err := finding.Validate(); err == nil {
		t.Fatal("junk config id validated")
	}
	finding.Evidence = []Evidence{{Config: &ConfigRef{ID: "claude:repo:.claude/settings.json"}}}
	fp, err := Fingerprint(finding.Rule, finding.Location, finding.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	finding.Fingerprint = fp
	if err := finding.Validate(); err != nil {
		t.Fatal(err)
	}
	finding.Fingerprint = "tcf_0000000000000000"
	if err := finding.Validate(); err == nil {
		t.Fatal("stored fingerprint did not have to match the computed one")
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
