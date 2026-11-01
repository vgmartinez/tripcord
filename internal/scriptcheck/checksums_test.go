package scriptcheck

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func envSetup(harness model.Harness, path, payload string) model.ConfigItem {
	return model.ConfigItem{Harness: harness, Scope: model.ScopeRepo, Path: path, Kind: model.ConfigKindEnvSetup, Payload: []byte(payload)}
}

func TestAnnotateChecksums(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	root := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("good.sha256", sum+"  t.sh\n"+sum+" *u.sh\n")
	write("other.sha256", sum+"  other.sh\n")
	write("bad.sha256", sum+"  t.sh\nnot a sum\n")
	write("empty.sha256", "")
	if err := os.Mkdir(filepath.Join(root, "dir.sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "x.sha256")
	if err := os.WriteFile(outside, []byte(sum+"  t.sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.sha256")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("good.sha256", filepath.Join(root, "inside.sha256")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("t.sh", filepath.Join(root, "sums-to-target.sha256")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("good.sha256", filepath.Join(root, "target-to-sums.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/x", filepath.Join(root, "broken.sha256")); err != nil {
		t.Fatal(err)
	}
	check := func(sums string) string {
		return `"curl -fsSLo t.sh https://x.invalid/t.sh && sha256sum -c ` + sums + ` && sh t.sh"`
	}
	const copilot = ".github/workflows/copilot-setup-steps.yml"
	items := []model.ConfigItem{
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("good.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("other.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("bad.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("empty.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("dir.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("escape.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("inside.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("sums-to-target.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("broken.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("gone.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":"curl -fsSLo target-to-sums.sh https://x.invalid/t.sh && sha256sum -c good.sha256 && sh target-to-sums.sh"}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("good.sha256")+`,"working-directory":"sub"}`),
		envSetup(model.HarnessCursor, ".cursor/environment.json", `{"setting":"install","value":`+check("good.sha256")+`}`),
		envSetup(model.SurfaceDevcontainer, ".devcontainer/devcontainer.json", `{"setting":"postCreateCommand","command":["bash","-c",`+check("good.sha256")+`]}`),
		envSetup(model.SurfaceDevcontainer, ".devcontainer/other/devcontainer.json", `{"setting":"postCreateCommand","command":`+check("good.sha256")+`}`),
		envSetup(model.SurfaceDevcontainer, ".devcontainer/other/devcontainer.json", `{"setting":"workspaceFolder","value":"/src"}`),
	}
	user := envSetup(model.HarnessCursor, "~/.cursor/environment.json", `{"setting":"install","value":`+check("good.sha256")+`}`)
	user.Scope = model.ScopeUser
	items = append(items, user)
	if err := Annotate(root, items); err != nil {
		t.Fatal(err)
	}
	good := map[string][]string{"good.sha256": {"t.sh", "u.sh"}}
	want := []map[string][]string{
		good,
		{"other.sha256": {"other.sh"}},
		nil, nil, nil, nil, nil, nil, nil, nil,
		good,
		nil,
		good, good,
		nil, nil, nil,
	}
	if got, want := items[10].ChecksumSymlinks, []string{"target-to-sums.sh"}; !slices.Equal(got, want) {
		t.Errorf("target-to-sums ChecksumSymlinks = %q, want %q", got, want)
	}
	for i, item := range items {
		if !maps.EqualFunc(item.ChecksumFiles, want[i], slices.Equal[[]string]) {
			t.Errorf("item %d (%s %s) ChecksumFiles = %q, want %q", i, item.Path, item.Payload, item.ChecksumFiles, want[i])
		}
	}
}

func TestAnnotateChecksumsCaseFoldedAliases(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	const (
		path = ".github/workflows/copilot-setup-steps.yml"
		run  = `{"setting":"step","run":"curl -fsSLo t.sh https://x.invalid/t.sh && sha256sum -c t.sh.sha256 && sh t.sh"}`
	)
	for _, tc := range []struct {
		name  string
		run   string
		setup func(t *testing.T, root string)
		sums  map[string][]string
		links []string
	}{
		{
			name: "target symlink to sums",
			setup: func(t *testing.T, root string) {
				writeChecksumFile(t, root, "t.sh.sha256", sum+"  t.sh\n")
				if err := os.Symlink("t.sh.sha256", filepath.Join(root, "T.SH")); err != nil {
					t.Fatal(err)
				}
			},
			sums:  map[string][]string{"t.sh.sha256": {"t.sh"}},
			links: []string{"t.sh"},
		},
		{
			name: "target symlink outside root",
			setup: func(t *testing.T, root string) {
				writeChecksumFile(t, root, "t.sh.sha256", sum+"  t.sh\n")
				if err := os.Symlink("/tmp/tripcord-outside.sh", filepath.Join(root, "T.SH")); err != nil {
					t.Fatal(err)
				}
			},
			sums:  map[string][]string{"t.sh.sha256": {"t.sh"}},
			links: []string{"t.sh"},
		},
		{
			name: "sums case variant symlink",
			setup: func(t *testing.T, root string) {
				writeChecksumFile(t, root, "t.sh.sha256", sum+"  t.sh\n")
				writeChecksumFile(t, root, "T.sh", sum+"  t.sh\n")
				if err := os.Symlink("T.sh", filepath.Join(root, "T.SH.SHA256")); err != nil {
					t.Fatal(err)
				}
			},
			sums: nil,
		},
		{
			name: "regular sums spelling sorts before symlink",
			run:  `{"setting":"step","run":"curl -fsSLo t.sh https://x.invalid/t.sh && sha256sum -c T.SH.SHA256 && sh t.sh"}`,
			setup: func(t *testing.T, root string) {
				// ReadDir returns uppercase first, so the regular file is
				// seen before the symlink that a case-insensitive checkout
				// can open for the same name.
				writeChecksumFile(t, root, "T.SH.SHA256", sum+"  t.sh\n")
				if err := os.Symlink("T.SH", filepath.Join(root, "t.sh.sha256")); err != nil {
					t.Fatal(err)
				}
			},
			sums: nil,
		},
		{
			name: "regular target spelling sorts before symlink",
			run:  `{"setting":"step","run":"curl -fsSLo T.SH https://x.invalid/t.sh && sha256sum -c t.sh.sha256 && sh T.SH"}`,
			setup: func(t *testing.T, root string) {
				writeChecksumFile(t, root, "t.sh.sha256", sum+"  T.SH\n")
				writeChecksumFile(t, root, "T.SH", "regular\n")
				if err := os.Symlink("/tmp/tripcord-outside.sh", filepath.Join(root, "t.sh")); err != nil {
					t.Fatal(err)
				}
			},
			sums:  map[string][]string{"t.sh.sha256": {"T.SH"}},
			links: []string{"T.SH"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.setup(t, root)
			script := run
			if tc.run != "" {
				script = tc.run
			}
			items := []model.ConfigItem{envSetup(model.HarnessCopilot, path, script)}
			if err := Annotate(root, items); err != nil {
				t.Fatal(err)
			}
			got := items[0]
			if !maps.EqualFunc(got.ChecksumFiles, tc.sums, slices.Equal[[]string]) {
				t.Errorf("ChecksumFiles = %q, want %q", got.ChecksumFiles, tc.sums)
			}
			if !slices.Equal(got.ChecksumSymlinks, tc.links) {
				t.Errorf("ChecksumSymlinks = %q, want %q", got.ChecksumSymlinks, tc.links)
			}
		})
	}
}

func writeChecksumFile(t *testing.T, root, name, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
