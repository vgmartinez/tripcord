package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
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

func TestLoadNoFiles(t *testing.T) {
	e, err := Load(Options{RepoRoot: t.TempDir(), Env: testEnv(t)})
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode != ModeEnforce || len(e.Layers) != 1 {
		t.Fatalf("effective %+v", e)
	}
}

func TestLoadLayers(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	packs := filepath.Join(root, "packs")
	write(t, filepath.Join(packs, "acme", "base@2026.11", PackPolicyFile), "version: 1\nmode: enforce\nlocked: {mode: true}\n")
	write(t, filepath.Join(root, "org", "policy.yaml"), "version: 1\nextends: acme/base@2026.11\nrules:\n  severity_overrides: {TC-CFG-011: high}\n")
	write(t, filepath.Join(repo, RepoFile), "version: 1\nextends: ../../org/policy.yaml\nharnesses: [claude]\n")
	write(t, filepath.Join(repo, LocalFile), "version: 1\nharnesses: [claude, cursor]\n")

	opts := Options{RepoRoot: repo, Env: testEnv(t), Catalog: catalog, Resolver: DirResolver{Root: packs}}
	layers, err := LoadLayers(opts)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, l := range layers {
		kinds = append(kinds, string(l.Kind)+":"+filepath.Base(filepath.Dir(l.Source))+"/"+filepath.Base(l.Source))
	}
	want := "org:base@2026.11/policy.yaml,org:org/policy.yaml,repo:.tripcord/policy.yaml,local:.tripcord/policy.local.yaml"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("layers = %v", kinds)
	}
	e, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	if e.ModeLock == nil || !strings.HasSuffix(e.ModeLock.Origin.Source, filepath.Join("base@2026.11", PackPolicyFile)) {
		t.Fatalf("mode lock %+v", e.ModeLock)
	}
	if e.Provenance["rules.severity_overrides.TC-CFG-011"].Layer != LayerOrg || e.Provenance["harnesses"].Layer != LayerLocal {
		t.Fatalf("provenance %v", e.Provenance)
	}

	// The local layer is bound by the org lock.
	write(t, filepath.Join(repo, LocalFile), "version: 1\nmode: audit\n")
	_, err = Load(opts)
	wantErr(t, err, "locked at enforce")
	assertExit(t, err, exitcode.Config)
}

func TestLoadDiamond(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "base.yaml"), "version: 1\nmode: warn\n")
	write(t, filepath.Join(root, "a.yaml"), "version: 1\nextends: ./base.yaml\n")
	write(t, filepath.Join(root, "b.yaml"), "version: 1\nextends: ./base.yaml\n")
	write(t, filepath.Join(root, RepoFile), "version: 1\nextends: [../a.yaml, ../b.yaml]\n")
	layers, err := LoadLayers(Options{RepoRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 4 || filepath.Base(layers[0].Source) != "base.yaml" {
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
			want:  "only allowed in the repo policy", code: exitcode.Config,
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
			opts := Options{RepoRoot: root, Env: testEnv(t), Catalog: catalog}
			if c.opts != nil {
				c.opts(&opts)
			}
			_, err := Load(opts)
			wantErr(t, err, c.want)
			assertExit(t, err, c.code)
		})
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
