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
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("broken.sha256")+`}`),
		envSetup(model.HarnessCopilot, copilot, `{"setting":"step","run":`+check("gone.sha256")+`}`),
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
		nil, nil, nil, nil,
		{"inside.sha256": {"t.sh", "u.sh"}},
		nil, nil, nil,
		good, good,
		nil, nil, nil,
	}
	for i, item := range items {
		if !maps.EqualFunc(item.ChecksumFiles, want[i], slices.Equal[[]string]) {
			t.Errorf("item %d (%s %s) ChecksumFiles = %q, want %q", i, item.Path, item.Payload, item.ChecksumFiles, want[i])
		}
	}
}
