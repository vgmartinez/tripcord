package generic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	got := kittest.Discover(t, New(Options{}), root)
	golden := kittest.GoldenJSON(t, got, nil)
	kittest.AssertGolden(t, "discover.golden", golden)
	for _, leak := range []string{"npm_live_123", "key=abc", "k-1", "access=tok", "sig=xyz"} {
		if strings.Contains(string(golden), leak) {
			t.Fatalf("discovery leaks %q", leak)
		}
	}
}

func TestSharedFileHarnesses(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	got := kittest.Discover(t, New(Options{}), root)
	want := map[string]model.Harness{
		"AGENTS.md":                    model.SurfaceGeneric,
		"services/api/AGENTS.md":       model.SurfaceGeneric,
		".agents/skills/lint/SKILL.md": model.SurfaceGeneric,
		".vscode/tasks.json":           model.SurfaceVSCode,
		".vscode/mcp.json":             model.SurfaceVSCode,
	}
	seen := map[string]bool{}
	for _, item := range got.Items {
		if h, ok := want[item.Path]; !ok || item.Harness != h {
			t.Errorf("%s: harness %s", item.Path, item.Harness)
		}
		seen[item.Path] = true
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("missing %s", path)
		}
	}
}

func TestTasksOnly(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	home := t.TempDir()
	kittest.WriteFile(t, filepath.Join(home, ".agents", "skills", "a", "SKILL.md"), "---\nname: a\n---\nx\n")
	a := New(Options{TasksOnly: true, IncludeUser: true, HomeDir: home})
	if !a.Detect(root) || a.Detect(t.TempDir()) {
		t.Fatal("Detect should follow .vscode/tasks.json only")
	}
	got := kittest.Discover(t, a, root)
	if len(got.Items) == 0 {
		t.Fatal("no items")
	}
	for _, item := range got.Items {
		if item.Path != ".vscode/tasks.json" || item.Harness != model.SurfaceVSCode {
			t.Fatalf("TasksOnly read %s (%s)", item.Path, item.Harness)
		}
	}
}

func TestFolderOpenTask(t *testing.T) {
	t.Parallel()
	root := kittest.CopyTree(t, filepath.Join("testdata", "repo"))
	got := kittest.Discover(t, New(Options{}), root)
	open := map[string]bool{}
	for _, item := range got.Find(".vscode/tasks.json", model.ConfigKindTask) {
		p := kittest.Payload(t, item)
		open[p["label"].(string)] = p["folder_open"].(bool)
	}
	if !open["bootstrap"] || open["test"] || open["lint"] || len(open) != 3 {
		t.Fatalf("folder_open = %v", open)
	}
}

// TestTasksSameLabelAndCommandGetDistinctKeys reproduces the collision a
// reviewer found: two tasks with the same label and command but
// different args shared a key, because the key only carried the label
// and command.
func TestTasksSameLabelAndCommandGetDistinctKeys(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".vscode", "tasks.json"), `{"tasks":[
		{"label":"build","type":"shell","command":"go","args":["build","./..."]},
		{"label":"build","type":"shell","command":"go","args":["build","./cmd/..."]}
	]}`)
	got := kittest.Discover(t, New(Options{}), root)
	items := got.Find(".vscode/tasks.json", model.ConfigKindTask)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2: %+v", len(items), items)
	}
	k1, _ := kittest.Payload(t, items[0])["key"].(string)
	k2, _ := kittest.Payload(t, items[1])["key"].(string)
	if k1 == k2 {
		t.Fatalf("two tasks with the same label/command but different args share a key: %s", k1)
	}
}

func TestVSCodeHostileInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		file    string
		content string
		diag    string
		items   int
	}{
		{"malformed tasks", ".vscode/tasks.json", `{"tasks":[`, "invalid JSON", 0},
		{"tasks not array", ".vscode/tasks.json", `{"tasks":{}}`, "tasks must be an array", 0},
		{"task not object", ".vscode/tasks.json", `{"tasks":["x"]}`, "must be an object", 0},
		{"bom crlf jsonc", ".vscode/tasks.json", "\ufeff{\r\n// c\r\n\"tasks\": [{\"label\": \"a\", \"command\": \"x\"},],\r\n}", "", 1},
		{"case-variant runOptions", ".vscode/tasks.json", `{"tasks":[{"label":"a","command":"x","runOptions":{"runOn":"default"},"RunOptions":{"runOn":"folderOpen"}}]}`, "case-variant", 1},
		{"duplicate tasks key", ".vscode/tasks.json", `{"tasks":[],"tasks":[{"label":"a","command":"x"}]}`, "duplicate key", 1},
		{"deep", ".vscode/mcp.json", `{"servers":` + strings.Repeat("[", 300) + strings.Repeat("]", 300) + `}`, "nesting", 0},
		{"servers not object", ".vscode/mcp.json", `{"servers":[]}`, "servers must be an object", 0},
		{"oversize", ".vscode/tasks.json", `{"x":"` + strings.Repeat("a", 2<<20) + `"}`, "cannot read", 0},
		{"agents frontmatter malformed is not reported", "AGENTS.md", "---\na: [\n---\nbody", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, filepath.FromSlash(tc.file)), tc.content)
			got := kittest.Discover(t, New(Options{}), root)
			if len(got.Items) != tc.items {
				t.Fatalf("items = %d, want %d: %+v", len(got.Items), tc.items, got.Items)
			}
			if tc.diag == "" {
				if len(got.Diagnostics) != 0 {
					t.Fatalf("diagnostics = %v", got.Diagnostics)
				}
				return
			}
			if !got.HasDiag(tc.file+": ") || !got.HasDiag(tc.diag) {
				t.Fatalf("diagnostics = %v, want %q", got.Diagnostics, tc.diag)
			}
		})
	}
}

func TestCaseInsensitiveSharedPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	kittest.WriteFile(t, filepath.Join(root, ".VSCode", "Tasks.json"), `{"tasks":[{"label":"a","command":"x","runOptions":{"runOn":"folderOpen"}}]}`)
	kittest.WriteFile(t, filepath.Join(root, "pkg", "Agents.md"), "x")
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Find(".VSCode/Tasks.json", model.ConfigKindTask)) != 1 || len(got.Find("pkg/Agents.md", model.ConfigKindInstructions)) != 1 {
		t.Fatalf("items = %+v", got.Items)
	}
}

// TestSymlinkEscapeOutsideSharedPathsNotReported is Follow-up 6's generic
// half: an escaping symlink at .github/hooks is Copilot's own location,
// not a shared one generic reads, so generic must not duplicate
// Copilot's diagnostic for it.
func TestSymlinkEscapeOutsideSharedPathsNotReported(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".github", "hooks")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if len(got.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %+v, want none: .github/hooks is Copilot's location, not a shared one", got.Diagnostics)
	}
}

func TestEscapingVSCodeSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	kittest.WriteFile(t, filepath.Join(outside, "tasks.json"), `{"tasks":[]}`)
	if err := os.Symlink(outside, filepath.Join(root, ".vscode")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := kittest.Discover(t, New(Options{}), root)
	if !got.HasDiag(".vscode: symlink resolves outside the repository") {
		t.Fatalf("diagnostics = %v", got.Diagnostics)
	}
}

func FuzzParseShared(f *testing.F) {
	for kind, path := range map[string]string{"tasks": "testdata/repo/.vscode/tasks.json", "mcp": "testdata/repo/.vscode/mcp.json", "agents": "testdata/repo/services/api/AGENTS.md"} {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(kind, data)
		}
	}
	f.Fuzz(func(t *testing.T, kind string, data []byte) {
		c := kit.NewCollector(model.SurfaceGeneric, product)
		s := c.Source(model.ScopeRepo, ".vscode/x.json", data).WithHarness(model.SurfaceVSCode)
		switch kind {
		case "tasks":
			tasksFile(s, data)
		case "mcp":
			mcpFile(s, data)
		default:
			c.Source(model.ScopeRepo, "AGENTS.md", data).Markdown(model.ConfigKindInstructions, "agents", data, kit.LooseFrontmatter)
		}
		for _, item := range c.Items() {
			kittest.CheckItem(t, item)
		}
	})
}
