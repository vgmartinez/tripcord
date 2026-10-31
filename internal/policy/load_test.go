package policy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// noManaged points the managed policy at a file that does not exist,
// so tests do not read the machine's real managed policy.
func noManaged(t *testing.T) string {
	return filepath.Join(t.TempDir(), "managed", "policy.yaml")
}

func layerNames(layers []Layer) string {
	var kinds []string
	for _, l := range layers {
		kinds = append(kinds, string(l.Kind)+":"+filepath.Base(filepath.Dir(l.Source))+"/"+filepath.Base(l.Source))
	}
	return strings.Join(kinds, ",")
}

func TestLoadNoFiles(t *testing.T) {
	e, err := Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: noManaged(t), Surface: SurfaceScan, Env: testEnv(t)})
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode != ModeEnforce || e.FailOn != model.SeverityHigh || len(e.Layers) != 1 {
		t.Fatalf("effective %+v", e)
	}
}

func TestLoadRepoPolicyMustExist(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := Load(Options{RepoRoot: t.TempDir(), RepoPolicy: missing, ManagedPolicy: noManaged(t), Surface: SurfaceScan, Env: testEnv(t)})
	if err == nil {
		t.Fatal("missing --policy file was accepted")
	}
	var polErr *Error
	if !errors.As(err, &polErr) || polErr.ExitCode() != exitcode.Config {
		t.Fatalf("err = %v, want a config Error", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadDefaultRepoPolicyIsOptional(t *testing.T) {
	e, err := Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: noManaged(t), Surface: SurfaceScan, Env: testEnv(t)})
	if err != nil {
		t.Fatalf("missing default repo policy: %v", err)
	}
	if e.Mode != ModeEnforce {
		t.Fatalf("effective %+v", e)
	}
}

func TestManagedPolicyPath(t *testing.T) {
	t.Setenv("ProgramData", `D:\Data`)
	for goos, want := range map[string]string{
		"linux":   "/etc/tripcord/policy.yaml",
		"freebsd": "/etc/tripcord/policy.yaml",
		"darwin":  "/Library/Application Support/Tripcord/policy.yaml",
		"windows": `D:\Data\Tripcord\policy.yaml`,
	} {
		if got := ManagedPolicyPath(goos); got != want {
			t.Errorf("%s: %s, want %s", goos, got, want)
		}
	}
}

func TestLoadLayers(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	packs := filepath.Join(root, "packs")
	managed := filepath.Join(root, "managed", "policy.yaml")
	write(t, filepath.Join(packs, "acme", "base@2026.11", PackPolicyFile), "version: 1\nmode: enforce\nlocked: {mode: true}\n")
	write(t, managed, "version: 1\nextends: acme/base@2026.11\nrules:\n  severity_overrides: {TC-CFG-011: high}\n")
	write(t, filepath.Join(root, "flag", "org.yaml"), "version: 1\nsecrets: {rulesets: [default]}\n")
	write(t, filepath.Join(root, "team", "extra.yaml"), "version: 1\nprivacy: {redact: true}\n")
	write(t, filepath.Join(repo, RepoFile), "version: 1\nextends: [../../team/extra.yaml, ../../managed/policy.yaml]\nharnesses: [claude]\n")
	write(t, filepath.Join(repo, LocalFile), "version: 1\nharnesses: [claude, cursor]\n")

	opts := Options{
		RepoRoot: repo, ManagedPolicy: managed, OrgPolicy: []string{filepath.Join(root, "flag", "org.yaml")},
		Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog, Resolver: DirResolver{Root: packs},
	}
	layers, err := LoadLayers(opts)
	if err != nil {
		t.Fatal(err)
	}
	// The repo's extends of the managed file is a no-op: it already
	// merged, first, as org.
	want := "org:base@2026.11/policy.yaml,org:managed/policy.yaml,org:flag/org.yaml," +
		"extends:team/extra.yaml,repo:.tripcord/policy.yaml,local:.tripcord/policy.local.yaml"
	if got := layerNames(layers); got != want {
		t.Fatalf("layers = %s", got)
	}
	e, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	if e.ModeLock == nil || !strings.HasSuffix(e.ModeLock.Origin.Source, filepath.Join("base@2026.11", PackPolicyFile)) {
		t.Fatalf("mode lock %+v", e.ModeLock)
	}
	if e.Provenance["rules.severity_overrides.TC-CFG-011"].Layer != LayerOrg ||
		e.Provenance["secrets.rulesets"].Layer != LayerOrg ||
		e.Provenance["privacy.redact"].Layer != LayerExtends ||
		e.Provenance["harnesses"].Layer != LayerLocal {
		t.Fatalf("provenance %v", e.Provenance)
	}

	// The local layer is bound by the org lock.
	write(t, filepath.Join(repo, LocalFile), "version: 1\nmode: audit\n")
	_, err = Load(opts)
	wantErr(t, err, "locked at enforce")
	assertExit(t, err, exitcode.Config)
}

// The org layer does not depend on the repo: a repo policy with no
// extends, or one that extends something else, still sits under the
// org locks.
func TestOrgLocksWithoutExtends(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed", "policy.yaml")
	write(t, managed, "version: 1\nmode: enforce\nrules:\n  include: [\"*\"]\nlocked:\n  mode: true\n  rules: [TC-CFG-*]\n")
	write(t, filepath.Join(root, "lax.yaml"), "version: 1\nmode: audit\n")
	opts := Options{RepoRoot: root, ManagedPolicy: managed, Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog}

	write(t, filepath.Join(root, RepoFile), "version: 1\nrules:\n  include: [TC-MCP-*]\n")
	e, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	if e.ModeLock == nil || e.ModeLock.Origin.Layer != LayerOrg || !e.RuleLocked("TC-CFG-001") || !e.Selected("TC-CFG-001") {
		t.Fatalf("org locks not inherited: %+v", e)
	}

	for name, body := range map[string]string{
		"no extends":    "version: 1\nmode: audit\n",
		"other extends": "version: 1\nextends: ../lax.yaml\n",
	} {
		t.Run(name, func(t *testing.T) {
			write(t, filepath.Join(root, RepoFile), body)
			_, err := Load(opts)
			wantErr(t, err, "locked at enforce")
			assertExit(t, err, exitcode.Config)
		})
	}
	t.Run("exception", func(t *testing.T) {
		write(t, filepath.Join(root, RepoFile), "version: 1\n"+exceptionDoc("TC-CFG-001"))
		_, err := Load(opts)
		wantErr(t, err, "cannot exempt")
	})
}

func TestLoadDiamond(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "base.yaml"), "version: 1\nmode: warn\n")
	write(t, filepath.Join(root, "a.yaml"), "version: 1\nextends: ./base.yaml\n")
	write(t, filepath.Join(root, "b.yaml"), "version: 1\nextends: ./base.yaml\n")
	write(t, filepath.Join(root, RepoFile), "version: 1\nextends: [../a.yaml, ../b.yaml]\n")
	layers, err := LoadLayers(Options{RepoRoot: root, ManagedPolicy: noManaged(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 4 || filepath.Base(layers[0].Source) != "base.yaml" || layers[0].Kind != LayerExtends {
		t.Fatalf("layers %+v", layers)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		opts  func(*Options)
		want  string
		code  exitcode.Code
	}{
		"invalid repo policy": {
			files: map[string]string{RepoFile: "version: 1\nmode: off\n"},
			want:  "mode", code: exitcode.Config,
		},
		"invalid local policy": {
			files: map[string]string{LocalFile: "version: 1\nprivacy: {egress: upload}\n"},
			want:  "egress", code: exitcode.Config,
		},
		"missing extends": {
			files: map[string]string{RepoFile: "version: 1\nextends: ./nope.yaml\n"},
			want:  "does not exist", code: exitcode.Config,
		},
		"cycle": {
			files: map[string]string{
				RepoFile:           "version: 1\nextends: ./a.yaml\n",
				".tripcord/a.yaml": "version: 1\nextends: ./policy.yaml\n",
			},
			want: "cycle", code: exitcode.Config,
		},
		"pack without resolver": {
			files: map[string]string{RepoFile: "version: 1\nextends: acme/base@2026.11\n"},
			want:  "no pack resolver", code: exitcode.Config,
		},
		"local extends": {
			files: map[string]string{LocalFile: "version: 1\nextends: ./policy.yaml\n"},
			want:  "not allowed in the local policy", code: exitcode.Config,
		},
		"missing org policy": {
			opts: func(o *Options) { o.OrgPolicy = []string{filepath.Join(o.RepoRoot, "nope.yaml")} },
			want: "org policy does not exist", code: exitcode.Config,
		},
		"invalid managed policy": {
			files: map[string]string{"managed.yaml": "version: 1\nmode: off\n"},
			opts:  func(o *Options) { o.ManagedPolicy = filepath.Join(o.RepoRoot, "managed.yaml") },
			want:  "mode", code: exitcode.Config,
		},
		"unreadable managed policy": {
			opts: func(o *Options) {
				o.ManagedPolicy = filepath.Join(o.RepoRoot, "managed")
				if err := os.MkdirAll(o.ManagedPolicy, 0o755); err != nil {
					panic(err)
				}
			},
			want: "managed", code: exitcode.Internal,
		},
		"invalid parent": {
			files: map[string]string{
				RepoFile:           "version: 1\nextends: ./a.yaml\n",
				".tripcord/a.yaml": "version: 2\n",
			},
			want: "version", code: exitcode.Config,
		},
		"depth": {
			files: func() map[string]string {
				m := map[string]string{RepoFile: "version: 1\nextends: ./p0.yaml\n"}
				for i := 0; i <= MaxExtendsDepth; i++ {
					m[".tripcord/p"+string(rune('0'+i))+".yaml"] = "version: 1\nextends: ./p" + string(rune('0'+i+1)) + ".yaml\n"
				}
				m[".tripcord/p"+string(rune('0'+MaxExtendsDepth+1))+".yaml"] = "version: 1\n"
				return m
			}(),
			want: "nested deeper", code: exitcode.Config,
		},
		"unreadable": {
			files: map[string]string{},
			opts: func(o *Options) {
				if err := os.MkdirAll(filepath.Join(o.RepoRoot, RepoFile), 0o755); err != nil {
					panic(err)
				}
			},
			want: "policy.yaml", code: exitcode.Internal,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			for rel, body := range c.files {
				write(t, filepath.Join(root, rel), body)
			}
			opts := Options{RepoRoot: root, ManagedPolicy: noManaged(t), Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog}
			if c.opts != nil {
				c.opts(&opts)
			}
			_, err := Load(opts)
			wantErr(t, err, c.want)
			assertExit(t, err, c.code)
		})
	}
}

// TestManagedPolicyPermissions covers checkManagedPolicyFile: a
// world-writable managed policy is rejected regardless of OS, and a
// file owned by the user running the test (as every file write in this
// suite is) is accepted. The negative owner case needs a file owned by
// someone else, which needs root to set up, so it is not covered here.
func TestManagedPolicyPermissions(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "managed", "policy.yaml")
	write(t, managed, "version: 1\nmode: warn\n")

	e, err := Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: managed, Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog})
	if err != nil {
		t.Fatalf("policy owned by the current user rejected: %v", err)
	}
	if e.Mode != ModeWarn || e.Provenance["mode"].Layer != LayerOrg {
		t.Fatalf("managed policy was not applied: %+v", e)
	}

	if runtime.GOOS == "windows" {
		t.Skip("world-writable is not meaningful on Windows; see checkManagedPolicyOwner")
	}
	if err := os.Chmod(managed, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: managed, Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog})
	wantErr(t, err, "world-writable")
	assertExit(t, err, exitcode.Config)

	if err := os.Chmod(managed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(managed), 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: managed, Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog})
	wantErr(t, err, "parent for")
	wantErr(t, err, "world-writable")
	assertExit(t, err, exitcode.Config)

	if err := os.Chmod(filepath.Dir(managed), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: managed, Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog}); err != nil {
		t.Fatalf("group-writable parent owned by the current user was rejected: %v", err)
	}
}

func TestManagedPolicyParentStatIsNotIgnored(t *testing.T) {
	err := checkManagedPolicyParentPath(filepath.Join(t.TempDir(), "missing", "policy.yaml"))
	if err == nil {
		t.Fatal("missing parent directory was ignored")
	}
}

func TestApplyFailOnRespectsLockedCeiling(t *testing.T) {
	root := t.TempDir()
	org := filepath.Join(root, "org.yaml")
	write(t, org, "version: 1\nmode: enforce\nfail-on: medium\nlocked:\n  mode: true\n")
	e, err := Load(Options{RepoRoot: t.TempDir(), ManagedPolicy: noManaged(t), OrgPolicy: []string{org}, Surface: SurfaceScan, Env: testEnv(t), Catalog: catalog})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyFailOn(model.SeverityCritical); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("loosening error = %v", err)
	}
	if e.FailOn != model.SeverityMedium {
		t.Fatalf("fail-on changed to %s", e.FailOn)
	}
	if err := e.ApplyFailOn(model.SeverityLow); err != nil {
		t.Fatal(err)
	}
	if e.FailOn != model.SeverityLow {
		t.Fatalf("fail-on = %s", e.FailOn)
	}
}

func assertExit(t *testing.T, err error, want exitcode.Code) {
	t.Helper()
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("%v is not a *policy.Error", err)
	}
	if pe.ExitCode() != want {
		t.Fatalf("exit code %d, want %d (%v)", pe.ExitCode(), want, err)
	}
}
