package policy

import (
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestDefaultsFor(t *testing.T) {
	for _, surface := range []Surface{SurfaceScan, SurfacePreopen, SurfacePRContext, SurfaceAction} {
		d, err := DefaultsFor(surface)
		if err != nil {
			t.Fatal(err)
		}
		if d.Mode != nonHookMode || d.FailOn != nonHookFailOn {
			t.Fatalf("%s: %+v", surface, d)
		}
		for _, sev := range []model.Severity{model.SeverityHigh, model.SeverityCritical} {
			ok, err := d.Fails(sev)
			if err != nil || !ok {
				t.Errorf("%s %s fails = %v, %v", surface, sev, ok, err)
			}
		}
		for _, sev := range []model.Severity{model.SeverityLow, model.SeverityMedium} {
			ok, err := d.Fails(sev)
			if err != nil || ok {
				t.Errorf("%s %s fails = %v, %v", surface, sev, ok, err)
			}
		}
	}

	d, err := DefaultsFor(SurfaceHook)
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode != hookMode || d.FailOn != "" {
		t.Fatalf("hook: %+v", d)
	}
	for _, sev := range []model.Severity{model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical} {
		ok, err := d.Fails(sev)
		if err != nil || ok {
			t.Errorf("hook %s fails = %v, %v; the hook shows findings and does not block", sev, ok, err)
		}
	}

	if _, err := DefaultsFor("watch"); err == nil {
		t.Fatal("unknown surface accepted")
	}
	if _, err := DefaultsFor(""); err == nil {
		t.Fatal("empty surface accepted")
	}
	if ok, err := (Defaults{}).Fails("severe"); err == nil || ok {
		t.Fatalf("bad severity: %v, %v", ok, err)
	}
}

func TestNoPolicySurfaceDefaults(t *testing.T) {
	for _, surface := range Surfaces() {
		e := mustMergeOn(t, surface, nil)
		d, err := DefaultsFor(surface)
		if err != nil {
			t.Fatal(err)
		}
		if e.Mode != d.Mode || e.FailOn != d.FailOn {
			t.Fatalf("%s: mode %s fail-on %q, want %s %q", surface, e.Mode, e.FailOn, d.Mode, d.FailOn)
		}
		if e.Provenance["mode"].Layer != LayerDefault || e.Provenance["fail-on"].Layer != LayerDefault {
			t.Fatalf("%s provenance %v", surface, e.Provenance)
		}
	}
}

func TestExplicitPolicyOverridesSurfaceDefaults(t *testing.T) {
	// A policy that sets both replaces the surface default, including on
	// the hook, where the default would not block.
	for _, surface := range []Surface{SurfaceScan, SurfaceHook} {
		e := mustMergeOn(t, surface, nil, "mode: audit\nfail-on: critical\n")
		if e.Mode != ModeAudit || e.FailOn != model.SeverityCritical {
			t.Fatalf("%s: mode %s fail-on %s", surface, e.Mode, e.FailOn)
		}
		if e.Provenance["mode"].Layer != LayerOrg || e.Provenance["fail-on"].Layer != LayerOrg {
			t.Fatalf("%s provenance %v", surface, e.Provenance)
		}
		ok, err := e.Fails(model.SeverityHigh)
		if err != nil || ok {
			t.Fatalf("%s high fails = %v, %v", surface, ok, err)
		}
		ok, err = e.Fails(model.SeverityCritical)
		if err != nil || !ok {
			t.Fatalf("%s critical fails = %v, %v", surface, ok, err)
		}
	}

	// Setting one leaves the other at the surface default.
	e := mustMergeOn(t, SurfaceScan, nil, "mode: warn\n")
	if e.Mode != ModeWarn || e.FailOn != model.SeverityHigh || e.Provenance["fail-on"].Layer != LayerDefault {
		t.Fatalf("scan mode only: mode %s fail-on %s from %s", e.Mode, e.FailOn, e.Provenance["fail-on"].Layer)
	}
	e = mustMergeOn(t, SurfaceHook, nil, "fail-on: high\n")
	if e.Mode != ModeWarn || e.FailOn != model.SeverityHigh || e.Provenance["mode"].Layer != LayerDefault {
		t.Fatalf("hook fail-on only: mode %s fail-on %s from %s", e.Mode, e.FailOn, e.Provenance["mode"].Layer)
	}
	ok, err := e.Fails(model.SeverityHigh)
	if err != nil || !ok {
		t.Fatalf("explicit hook fail-on: %v, %v", ok, err)
	}

	// A later layer replaces an earlier explicit value.
	e = mustMergeOn(t, SurfaceAction, nil, "fail-on: low\n", "fail-on: medium\n")
	if e.FailOn != model.SeverityMedium || e.Provenance["fail-on"].Layer != LayerRepo {
		t.Fatalf("later fail-on: %s from %s", e.FailOn, e.Provenance["fail-on"].Layer)
	}
}

func TestHookLockUsesWarnDefault(t *testing.T) {
	// A mode lock with no explicit mode locks the surface default.
	// On the hook that is warn: audit is rejected, enforce is allowed.
	_, err := mergeOn(t, SurfaceHook, nil, "locked: {mode: true}\n", "mode: audit\n")
	wantErr(t, err, "locked at warn")
	e := mustMergeOn(t, SurfaceHook, nil, "locked: {mode: true}\n", "mode: enforce\n")
	if e.Mode != ModeEnforce {
		t.Fatalf("hook could not tighten to enforce: %s", e.Mode)
	}
}

func TestLoadRequiresSurface(t *testing.T) {
	_, err := Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: noManaged(t)})
	wantErr(t, err, "surface")
	assertExit(t, err, exitcode.Config)
}

func TestLoadHookDefault(t *testing.T) {
	e, err := Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: noManaged(t), Surface: SurfaceHook, Env: testEnv(t)})
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode != ModeWarn || e.FailOn != "" {
		t.Fatalf("hook default %+v", e)
	}
	ok, err := e.Fails(model.SeverityCritical)
	if err != nil || ok {
		t.Fatalf("hook blocked a critical finding: %v, %v", ok, err)
	}
}
