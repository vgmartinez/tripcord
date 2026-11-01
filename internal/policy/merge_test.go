package policy

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules"
)

type fakeCatalog map[string]*rules.Rule

func (c fakeCatalog) Rule(id string) (*rules.Rule, bool) {
	r, ok := c[id]
	return r, ok
}

func (c fakeCatalog) Rules() []*rules.Rule {
	var out []*rules.Rule
	for _, id := range slices.Sorted(maps.Keys(c)) {
		out = append(out, c[id])
	}
	return out
}

var corePack = rules.PackRef{Name: "tripcord/core", Version: "2026.11"}

func fakeRule(id string, sev model.Severity, harness ...model.Harness) *rules.Rule {
	return &rules.Rule{ID: id, Severity: sev, Pack: corePack, Harness: harness}
}

var catalog = fakeCatalog{
	"TC-CFG-001": fakeRule("TC-CFG-001", model.SeverityCritical, model.HarnessClaude, model.HarnessCursor, model.SurfaceVSCode),
	"TC-CFG-004": fakeRule("TC-CFG-004", model.SeverityHigh, model.HarnessClaude),
	"TC-CFG-011": fakeRule("TC-CFG-011", model.SeverityMedium, model.HarnessCodex),
	"TC-SEC-018": fakeRule("TC-SEC-018", model.SeverityCritical, model.HarnessClaude, model.HarnessCodex),
}

func testEnv(t *testing.T) *rules.Env {
	t.Helper()
	env, err := rules.NewEnv(rules.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func layer(t *testing.T, kind LayerKind, doc string) Layer {
	t.Helper()
	f, err := Parse([]byte("version: 1\n" + doc))
	if err != nil {
		t.Fatalf("%s: %v", kind, err)
	}
	return Layer{Kind: kind, Source: string(kind) + ".yaml", File: f}
}

func merge(t *testing.T, cat RuleCatalog, docs ...string) (*Effective, error) {
	t.Helper()
	return mergeOn(t, SurfaceScan, cat, docs...)
}

func mergeOn(t *testing.T, surface Surface, cat RuleCatalog, docs ...string) (*Effective, error) {
	t.Helper()
	kinds := []LayerKind{LayerOrg, LayerRepo, LayerLocal}
	var layers []Layer
	for i, d := range docs {
		layers = append(layers, layer(t, kinds[i], d))
	}
	return Merge(testEnv(t), cat, surface, layers)
}

func mustMerge(t *testing.T, cat RuleCatalog, docs ...string) *Effective {
	t.Helper()
	return mustMergeOn(t, SurfaceScan, cat, docs...)
}

func mustMergeOn(t *testing.T, surface Surface, cat RuleCatalog, docs ...string) *Effective {
	t.Helper()
	e, err := mergeOn(t, surface, cat, docs...)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), substr) {
		t.Fatalf("err = %v, want %q", err, substr)
	}
}

func TestDefaults(t *testing.T) {
	e := mustMerge(t, nil)
	if e.Mode != ModeEnforce || e.FailOn != model.SeverityHigh || len(e.Harnesses) != 8 || !e.Enabled("TC-CFG-001", model.HarnessClaude) || !e.HarnessEnabled(model.HarnessDevin) || e.Egress != EgressNone || !e.Redact {
		t.Fatalf("defaults = %+v", e)
	}
	if e.Provenance["mode"].Layer != LayerDefault {
		t.Fatalf("provenance = %v", e.Provenance)
	}
}

func TestPrecedenceAndProvenance(t *testing.T) {
	e := mustMerge(t, catalog,
		"mode: warn\nharnesses: [claude]\nrules:\n  include: [\"TC-*\"]\n  severity_overrides: {TC-CFG-011: high, TC-CFG-004: low}\npack: [tripcord/core@2026.11, acme/extra@2026.10]\n",
		"mode: enforce\nrules:\n  severity_overrides: {TC-CFG-011: critical}\npack: tripcord/core@2026.12\nsecrets: {rulesets: [gitleaks-default]}\n",
		"mode: audit\nharnesses: [claude, cursor]\nprivacy: {redact: false}\n",
	)
	if e.Mode != ModeAudit || e.Provenance["mode"] != (Origin{LayerLocal, "local.yaml"}) {
		t.Fatalf("mode %s from %v", e.Mode, e.Provenance["mode"])
	}
	if len(e.Harnesses) != 2 || e.Provenance["harnesses"].Layer != LayerLocal {
		t.Fatalf("harnesses %v", e.Harnesses)
	}
	if e.Severity("TC-CFG-011", model.SeverityMedium) != model.SeverityCritical || e.Provenance["rules.severity_overrides.TC-CFG-011"].Layer != LayerRepo {
		t.Fatal("repo override did not win")
	}
	if e.Severity("TC-CFG-004", model.SeverityHigh) != model.SeverityLow || e.Provenance["rules.severity_overrides.TC-CFG-004"].Layer != LayerOrg {
		t.Fatal("org override lost")
	}
	if e.Severity("TC-SEC-018", model.SeverityCritical) != model.SeverityCritical {
		t.Fatal("base severity lost")
	}
	if len(e.Packs) != 2 || e.Packs[0].String() != "tripcord/core@2026.12" || e.Provenance["pack.tripcord/core"].Layer != LayerRepo || e.Provenance["pack.acme/extra"].Layer != LayerOrg {
		t.Fatalf("packs %v", e.Packs)
	}
	if e.Redact || e.Provenance["privacy.redact"].Layer != LayerLocal || e.Provenance["rules.include"].Layer != LayerOrg {
		t.Fatal("privacy or include provenance wrong")
	}
	if len(e.Layers) != 4 || e.Layers[0].Layer != LayerDefault || e.Layers[3].Layer != LayerLocal {
		t.Fatalf("layers %v", e.Layers)
	}
}

func TestLockedMode(t *testing.T) {
	lockEnforce := "mode: enforce\nlocked: {mode: true}\n"
	if _, err := merge(t, nil, lockEnforce, "mode: warn\n"); err == nil {
		t.Fatal("repo relaxed a locked enforce mode")
	}
	_, err := merge(t, nil, lockEnforce, "", "mode: audit\n")
	wantErr(t, err, "locked at enforce")
	e := mustMerge(t, nil, lockEnforce, "mode: enforce\n")
	if e.Mode != ModeEnforce || e.ModeLock.Origin.Layer != LayerOrg || e.Provenance["locked.mode"].Layer != LayerOrg {
		t.Fatalf("effective %+v", e)
	}
	// A lock on warn allows tightening to enforce but not loosening to audit.
	e = mustMerge(t, nil, "mode: warn\nlocked: {mode: true}\n", "mode: enforce\n")
	if e.Mode != ModeEnforce {
		t.Fatal("tightening rejected")
	}
	_, err = merge(t, nil, "mode: warn\nlocked: {mode: true}\n", "mode: audit\n")
	wantErr(t, err, "locked at warn")
	// Locking without a mode locks the inherited default.
	_, err = merge(t, nil, "locked: {mode: true}\n", "mode: warn\n")
	wantErr(t, err, "locked at enforce")
	// A lower layer cannot unlock.
	_, err = merge(t, nil, lockEnforce, "locked: {mode: false}\n")
	wantErr(t, err, "cannot unlock")
	// Without a lock, lower layers relax freely.
	if e := mustMerge(t, nil, "mode: enforce\n", "mode: audit\n"); e.Mode != ModeAudit {
		t.Fatal("unlocked mode not overridden")
	}
	// The locking layer itself applies its mode first, then locks it.
	if e := mustMerge(t, nil, "mode: audit\n", "mode: warn\nlocked: {mode: true}\n"); e.Mode != ModeWarn {
		t.Fatal("same-layer lock")
	}
}

func TestLockedSeverity(t *testing.T) {
	org := "rules:\n  severity_overrides: {TC-CFG-011: high}\nlocked:\n  rules: [TC-CFG-011]\n"
	_, err := merge(t, catalog, org, "rules:\n  severity_overrides: {TC-CFG-011: medium}\n")
	wantErr(t, err, "below high")
	e := mustMerge(t, catalog, org, "rules:\n  severity_overrides: {TC-CFG-011: critical}\n", "rules:\n  severity_overrides: {TC-CFG-011: high}\n")
	if e.Severity("TC-CFG-011", model.SeverityMedium) != model.SeverityHigh {
		t.Fatal("local could not return to the locked floor")
	}
	_, err = merge(t, catalog, org, "rules:\n  severity_overrides: {TC-CFG-011: critical}\n", "rules:\n  severity_overrides: {TC-CFG-011: medium}\n")
	wantErr(t, err, "below high")

	// Without an override at lock time the floor is the rule's base severity.
	glob := "locked:\n  rules: [\"TC-CFG-*\"]\n"
	_, err = merge(t, catalog, glob, "rules:\n  severity_overrides: {TC-CFG-001: high}\n")
	wantErr(t, err, "below critical")
	mustMerge(t, catalog, glob, "rules:\n  severity_overrides: {TC-CFG-011: high}\n")
	// Unlocked rules can be lowered.
	mustMerge(t, catalog, glob, "rules:\n  severity_overrides: {TC-SEC-018: low}\n")
	// Without a catalog the floor is unknown, so the override is refused.
	_, err = merge(t, nil, glob, "rules:\n  severity_overrides: {TC-CFG-001: critical}\n")
	wantErr(t, err, "unknown")
}

func TestLockedExceptions(t *testing.T) {
	exc := func(rule string) string {
		return "rules:\n  exceptions:\n    - {rule: " + rule + ", path: .claude/settings.json, sha256: " + strings.Repeat("a", 64) + ", reason: ok, expires: 2027-01-31}\n"
	}
	lock := "locked:\n  rules: [TC-CFG-001]\n"
	_, err := merge(t, catalog, lock, exc("TC-CFG-001"))
	wantErr(t, err, "TC-CFG-001 is locked by org.yaml")
	_, err = merge(t, catalog, lock, "", exc("TC-CFG-001"))
	wantErr(t, err, "is locked")
	e := mustMerge(t, catalog, lock, exc("TC-CFG-004"))
	if len(e.Exceptions) != 1 || e.Provenance["rules.exceptions[0]"].Layer != LayerRepo {
		t.Fatalf("exceptions %+v", e.Exceptions)
	}
	// The locking layer may carry its own exceptions; they accumulate.
	e = mustMerge(t, catalog, strings.TrimSuffix(exc("TC-CFG-001"), "\n")+"\n"+lock, exc("TC-CFG-004"))
	if len(e.Exceptions) != 2 || e.Exceptions[0].Origin.Layer != LayerOrg {
		t.Fatalf("exceptions %+v", e.Exceptions)
	}
}

func exceptionDoc(rule string) string {
	return "rules:\n  exceptions:\n    - {rule: " + rule + ", path: .claude/settings.json, sha256: " + strings.Repeat("a", 64) + ", reason: ok, expires: 2027-01-31}\n"
}

// TestExemptionLocks covers locked.exceptions and the allowlist.
// A later layer cannot add an exception for a rule locked under rules
// or under exceptions, and rules.include cannot drop it. An exceptions
// lock does not freeze severity.
func TestExemptionLocks(t *testing.T) {
	org := "locked:\n  rules: [TC-SEC-018]\n  exceptions: [TC-CFG-004]\n"
	e := mustMerge(t, catalog, org, "rules:\n  include: [\"TC-FOR-*\"]\n")
	if !e.Selected("TC-SEC-018") || !e.Selected("TC-CFG-004") {
		t.Fatalf("allowlist dropped a locked rule")
	}
	if e.Selected("TC-CFG-001") || !e.Selected("TC-FOR-020") {
		t.Fatalf("include applied wrong: cfg001=%v for020=%v", e.Selected("TC-CFG-001"), e.Selected("TC-FOR-020"))
	}
	if !e.RuleLocked("TC-SEC-018") || e.RuleLocked("TC-CFG-004") {
		t.Fatal("exceptions lock froze severity")
	}
	if !e.ExemptionLocked("TC-SEC-018") || !e.ExemptionLocked("TC-CFG-004") || e.ExemptionLocked("TC-CFG-001") {
		t.Fatal("exemption lock set wrong")
	}
	if e.Provenance["locked.exceptions[TC-CFG-004]"].Layer != LayerOrg {
		t.Fatalf("provenance %v", e.Provenance["locked.exceptions[TC-CFG-004]"])
	}

	e = mustMerge(t, catalog, org, "rules:\n  severity_overrides: {TC-CFG-004: low}\n")
	if e.Severity("TC-CFG-004", model.SeverityHigh) != model.SeverityLow {
		t.Fatal("exceptions lock froze severity")
	}
	_, err := merge(t, catalog, org, "rules:\n  severity_overrides: {TC-SEC-018: low}\n")
	wantErr(t, err, "below critical")

	_, err = merge(t, catalog, org, exceptionDoc("TC-CFG-004"))
	wantErr(t, err, "cannot exempt")
	_, err = merge(t, catalog, org, exceptionDoc("TC-SEC-018"))
	wantErr(t, err, "cannot exempt")
	e = mustMerge(t, catalog, org, exceptionDoc("TC-CFG-001"))
	if len(e.Exceptions) != 1 || e.Exceptions[0].Rule != "TC-CFG-001" {
		t.Fatalf("unlocked exception %+v", e.Exceptions)
	}

	e = mustMerge(t, catalog, exceptionDoc("TC-CFG-004")+org)
	if len(e.Exceptions) != 1 || e.Exceptions[0].Origin.Layer != LayerOrg {
		t.Fatalf("locking layer lost its exception: %+v", e.Exceptions)
	}
	_, err = merge(t, catalog, exceptionDoc("TC-CFG-004")+org, exceptionDoc("TC-CFG-004"))
	wantErr(t, err, "cannot exempt")
}

func TestLockedRuleStaysEnabled(t *testing.T) {
	e := mustMerge(t, catalog, "locked:\n  rules: [TC-SEC-018]\n", "rules:\n  include: [\"TC-CFG-*\"]\n")
	if !e.Selected("TC-SEC-018") || !e.Selected("TC-CFG-001") || e.Selected("TC-FOR-020") {
		t.Fatal("include and lock combination wrong")
	}
	if !e.RuleLocked("TC-SEC-018") || e.RuleLocked("TC-CFG-001") {
		t.Fatal("RuleLocked wrong")
	}
}

func TestLocksAccumulate(t *testing.T) {
	e := mustMerge(t, catalog, "locked:\n  rules: [TC-CFG-001]\n", "locked:\n  rules: [TC-CFG-004]\n")
	if len(e.RuleLocks) != 2 || e.Provenance["locked.rules[TC-CFG-004]"].Layer != LayerRepo {
		t.Fatalf("locks %+v", e.RuleLocks)
	}
	_, err := merge(t, catalog, "locked:\n  rules: [TC-CFG-001]\n", "locked:\n  rules: [TC-CFG-004]\n",
		"rules:\n  severity_overrides: {TC-CFG-004: low}\n")
	wantErr(t, err, "below high")
}

func TestCustomRules(t *testing.T) {
	e := mustMerge(t, catalog, strings.Replace(specSample, "version: 1\n", "", 1))
	if len(e.Custom) != 1 || e.Custom[0].ID != "ACME-001" || e.Custom[0].Severity != model.SeverityHigh {
		t.Fatalf("custom %+v", e.Custom)
	}
	ev := model.Event{
		Schema: model.SchemaEvent, ID: "evt_1", TS: time.Unix(0, 0),
		Source:  model.Source{Harness: model.HarnessClaude, Surface: "cloud", Version: "1", Origin: "hook:PreToolUse"},
		Session: model.EventSession{ID: "s"}, Kind: model.EventKindToolCall, Tool: "shell",
	}
	for cmd, want := range map[string]bool{
		"railway volume delete prod":    true,
		"RAILWAY   environment  delete": true,
		"railway volume list":           false,
	} {
		ev.Command = cmd
		in, err := rules.EventInput(ev, rules.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Custom[0].Deny(context.Background(), in)
		if err != nil || got != want {
			t.Errorf("%q: %v, %v", cmd, got, err)
		}
	}
	ev.Tool, ev.Command = "read", "railway volume delete prod"
	in, _ := rules.EventInput(ev, rules.DefaultLimits())
	if got, _ := e.Custom[0].Deny(context.Background(), in); got {
		t.Error("when precondition ignored")
	}

	custom := func(id, deny string) string {
		return "custom:\n  - {id: " + id + ", deny_if: '" + deny + "', message: m}\n"
	}
	_, err := merge(t, catalog, custom("ACME-001", "true"), custom("ACME-001", "true"))
	wantErr(t, err, "already defined")
	_, err = merge(t, catalog, custom("TC-CFG-001", "true"))
	wantErr(t, err, "pack rule id")
	_, err = merge(t, catalog, custom("ACME-002", "event.command"))
	wantErr(t, err, "want bool")
	_, err = merge(t, catalog, custom("ACME-003", `event.command.matches("(a)\\1")`))
	wantErr(t, err, "deny_if")
}

func TestExceptionStatus(t *testing.T) {
	sha := strings.Repeat("b", 64)
	e := mustMerge(t, catalog, "rules:\n  exceptions:\n    - {rule: TC-CFG-004, path: .claude/settings.json, sha256: "+sha+", reason: ok, expires: 2027-01-31}\n")
	day := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	cases := []struct {
		rule, path, sha string
		now             time.Time
		want            ExceptionStatus
	}{
		{"TC-CFG-004", ".claude/settings.json", sha, day("2026-11-01T00:00:00Z"), ExceptionActive},
		{"TC-CFG-004", ".claude/settings.json", sha, day("2027-01-31T23:59:59Z"), ExceptionActive},
		{"TC-CFG-004", ".claude/settings.json", sha, day("2027-02-01T00:00:00Z"), ExceptionExpired},
		{"TC-CFG-004", ".claude/settings.json", sha, day("2027-02-01T00:30:00+01:00"), ExceptionActive},
		{"TC-CFG-004", ".claude/settings.json", strings.Repeat("c", 64), day("2026-11-01T00:00:00Z"), ExceptionHashMismatch},
		{"TC-CFG-004", ".cursor/hooks.json", sha, day("2026-11-01T00:00:00Z"), ExceptionNone},
		{"TC-CFG-001", ".claude/settings.json", sha, day("2026-11-01T00:00:00Z"), ExceptionNone},
	}
	for _, c := range cases {
		ex, got := e.Exception(c.rule, c.path, c.sha, c.now)
		if got != c.want || (got == ExceptionNone) != (ex == nil) {
			t.Errorf("%s %s %s: %v, want %v", c.rule, c.path, c.now, got, c.want)
		}
	}
}

func TestExceptionActiveWinsOverStale(t *testing.T) {
	old, cur := strings.Repeat("1", 64), strings.Repeat("2", 64)
	e := mustMerge(t, catalog,
		"rules:\n  exceptions:\n    - {rule: TC-CFG-004, path: a.json, sha256: "+old+", reason: old, expires: 2027-01-31}\n",
		"rules:\n  exceptions:\n    - {rule: TC-CFG-004, path: a.json, sha256: "+cur+", reason: new, expires: 2027-01-31}\n",
	)
	ex, st := e.Exception("TC-CFG-004", "a.json", cur, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if st != ExceptionActive || ex.Reason != "new" {
		t.Fatalf("%v %+v", st, ex)
	}
}

func TestPackFloor(t *testing.T) {
	lock := "pack: tripcord/core@2026.11\nlocked:\n  rules: [\"TC-CFG-*\"]\n"
	_, err := merge(t, catalog, lock, "", "pack: [tripcord/core@2020.01]\n")
	wantErr(t, err, "below tripcord/core@2026.11, locked by org.yaml")
	assertExit(t, err, exitcode.Config)
	_, err = merge(t, catalog, lock, "pack: tripcord/core@2026.12\n", "pack: tripcord/core@2026.10\n")
	wantErr(t, err, "below tripcord/core@2026.11")
	e := mustMerge(t, catalog, lock, "pack: tripcord/core@2026.12\n", "pack: tripcord/core@2026.11\n")
	if e.Packs[0].String() != "tripcord/core@2026.11" || e.PackFloors["tripcord/core"].Origin.Layer != LayerOrg {
		t.Fatalf("packs %v floors %v", e.Packs, e.PackFloors)
	}

	// With no pin, the floor is the version of the catalog rules the lock covers.
	_, err = merge(t, catalog, "locked:\n  rules: [TC-CFG-001]\n", "pack: tripcord/core@2026.10\n")
	wantErr(t, err, "below tripcord/core@2026.11")
	// A pin wins over the catalog version.
	mustMerge(t, catalog, "pack: tripcord/core@2026.10\nlocked:\n  exceptions: [TC-CFG-001]\n", "pack: tripcord/core@2026.10\n")
	// Without a rule lock, pins move freely.
	mustMerge(t, catalog, "pack: tripcord/core@2026.11\nlocked: {mode: true}\n", "pack: tripcord/core@2020.01\n")
	mustMerge(t, catalog, "pack: tripcord/core@2026.11\n", "pack: tripcord/core@2020.01\n")
}

func TestHarnessLock(t *testing.T) {
	lock := "locked:\n  rules: [TC-CFG-001]\n"
	_, err := merge(t, catalog, lock, "", "harnesses: [cursor]\n")
	wantErr(t, err, "claude cannot be removed; rules locked by org.yaml cover it")
	// Harnesses no locked rule covers can go.
	e := mustMerge(t, catalog, lock, "harnesses: [claude, cursor]\n")
	if !e.Enabled("TC-CFG-001", model.HarnessClaude) || e.Enabled("TC-CFG-001", model.HarnessCodex) || !e.Enabled("TC-CFG-001", model.SurfaceVSCode) {
		t.Fatal("Enabled ignores the harnesses list")
	}
	// locked.exceptions protects coverage too.
	_, err = merge(t, catalog, "locked:\n  exceptions: [TC-CFG-004]\n", "harnesses: [cursor]\n")
	wantErr(t, err, "claude cannot be removed")
	// Without a catalog every listed harness stays.
	_, err = merge(t, nil, lock, "harnesses: [claude, cursor]\n")
	wantErr(t, err, "codex cannot be removed")
	// The snapshot is the list at lock time; adding is always allowed.
	mustMerge(t, catalog, "harnesses: [cursor]\n"+lock, "harnesses: [cursor, claude]\n", "harnesses: [cursor]\n")
	_, err = merge(t, catalog, "harnesses: [claude, cursor]\n"+lock, "harnesses: [claude]\n")
	wantErr(t, err, "cursor cannot be removed")
}

// TestEnabledMatchesEngine checks that the engine, given the policy's
// filter, evaluates exactly the rule and item pairs Enabled reports.
func TestEnabledMatchesEngine(t *testing.T) {
	env := testEnv(t)
	pack, err := rules.LoadDir("../rules/testdata/packs/fixture", env)
	if err != nil {
		t.Fatal(err)
	}
	e := mustMerge(t, nil, "harnesses: [claude]\nrules:\n  include: [TEST-CFG-002, TEST-CFG-004]\n")
	cfg := func(h model.Harness, path string, kind model.ConfigKind, payload string) model.ConfigItem {
		return model.ConfigItem{Harness: h, Scope: model.ScopeRepo, Path: path, Kind: kind, SHA256: strings.Repeat("a", 64), Payload: []byte(payload)}
	}
	items := []model.ConfigItem{
		cfg(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"sh"}`),
		cfg(model.HarnessCursor, ".cursor/mcp.json", model.ConfigKindMCPServer, `{"command":"sh"}`),
		cfg(model.SurfaceVSCode, ".vscode/tasks.json", model.ConfigKindTask, `{"runOptions":{"runOn":"folderOpen"}}`),
	}
	all := rules.NewEngine(env, pack.Rules).ScanConfig(context.Background(), items)
	got := rules.NewEngine(env, pack.Rules, rules.WithFilter(e.RuleFilter())).ScanConfig(context.Background(), items)
	if len(all.Errors)+len(got.Errors) != 0 {
		t.Fatal(all.Errors, got.Errors)
	}
	key := func(m rules.Match) string { return m.Rule.ID + "@" + m.Item.Harness.String() }
	var want, have []string
	for _, m := range all.Matches {
		if e.Enabled(m.Rule.ID, m.Item.Harness) {
			want = append(want, key(m))
		}
	}
	for _, m := range got.Matches {
		have = append(have, key(m))
	}
	if strings.Join(have, ",") != strings.Join(want, ",") || strings.Join(have, ",") != "TEST-CFG-002@claude,TEST-CFG-004@claude" {
		t.Fatalf("engine %v, Enabled %v", have, want)
	}
}

// TestCustomDenyGuards covers deny-style rules, where failing open on a
// missing field would let the event through.
func TestCustomDenyGuards(t *testing.T) {
	custom := func(when, deny string) string {
		doc := "custom:\n  - id: ACME-010\n    deny_if: '" + deny + "'\n    message: m\n"
		if when != "" {
			doc += "    when: '" + when + "'\n"
		}
		return doc
	}
	_, err := merge(t, nil, custom("", `!(event.extra == "x")`))
	wantErr(t, err, "has(event.extra)")
	_, err = merge(t, nil, custom(`event.tool == "mcp"`, `!event.net.all(n, n.host.endsWith(".corp"))`))
	wantErr(t, err, "has(n.host)")

	e := mustMerge(t, nil,
		custom(`event.kind == "tool_call"`, `!event.command.startsWith("git ")`)+
			"  - id: ACME-011\n    deny_if: '!event.net.all(n, has(n.host) && n.host.endsWith(\".corp\"))'\n    message: m\n")
	ev := model.Event{
		Schema: model.SchemaEvent, ID: "evt_1", TS: time.Unix(0, 0),
		Source:  model.Source{Harness: model.HarnessClaude},
		Session: model.EventSession{ID: "s"}, Kind: model.EventKindToolCall,
	}
	cases := []struct {
		name    string
		mutate  func(*model.Event)
		deny010 bool
		deny011 bool
	}{
		// No command: the negated condition denies instead of failing open.
		{"no command", func(*model.Event) {}, true, false},
		{"git", func(ev *model.Event) { ev.Command = "git status" }, false, false},
		{"other", func(ev *model.Event) { ev.Command = "rm -rf /" }, true, false},
		// A net entry without a host is not proven internal, so it denies.
		{"hostless net", func(ev *model.Event) { ev.Net = []model.NetEvent{{Method: "GET"}} }, true, true},
		{"corp net", func(ev *model.Event) { ev.Net = []model.NetEvent{{Host: "a.corp"}} }, true, false},
	}
	for _, c := range cases {
		ev := ev
		c.mutate(&ev)
		in, err := rules.EventInput(ev, rules.HookLimits())
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range []bool{c.deny010, c.deny011} {
			got, err := e.Custom[i].Deny(context.Background(), in)
			if err != nil || got != want {
				t.Errorf("%s: %s = %v, %v; want %v", c.name, e.Custom[i].ID, got, err, want)
			}
		}
	}
}
