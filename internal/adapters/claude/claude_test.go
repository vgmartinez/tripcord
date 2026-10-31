package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestDiscoverGolden(t *testing.T) {
	t.Parallel()
	root := copyFixtureRepo(t)
	managed, err := filepath.Abs(filepath.Join("testdata", "managed", "managed-settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	adapter := New(Options{
		HomeDir:        home,
		ManagedPaths:   []string{managed},
		IncludeUser:    true,
		IncludeManaged: true,
	})
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"permissions":{"allow":["Bash(git status)"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"user":{"command":"user-mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := adapter.Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if err := item.Validate(); err != nil {
			t.Fatalf("invalid item %+v: %v", item, err)
		}
	}
	got, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = bytes.ReplaceAll(got, []byte(filepath.ToSlash(managed)), []byte("/etc/claude-code/managed-settings.json"))
	assertGolden(t, "discover.golden", append(got, '\n'))
}

func TestDetect(t *testing.T) {
	t.Parallel()
	adapter := New(Options{})
	if adapter.Detect(t.TempDir()) {
		t.Fatal("Detect reported an empty repository")
	}
	if !adapter.Detect(copyFixtureRepo(t)) {
		t.Fatal("Detect did not report fixture config")
	}
}

func TestDiscoverRejectsMalformedAndOversizeJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data []byte
	}{
		{name: "malformed", data: []byte("{ // comments are invalid JSON\n}")},
		{name: "oversize", data: bytes.Repeat([]byte("a"), int(adapters.MaxConfigFileBytes)+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := New(Options{}).Discover(context.Background(), root)
			if err == nil {
				t.Fatal("Discover succeeded for invalid settings")
			}
		})
	}
}

func TestDiscoverSkipsRepoSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(outside, []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := New(Options{}).Discover(context.Background(), root)
	if !errors.Is(err, adapters.ErrUnsafePath) {
		t.Fatalf("Discover error = %v, want ErrUnsafePath", err)
	}
}

func FuzzParseConfig(f *testing.F) {
	for _, seed := range []struct {
		kind string
		path string
	}{
		{kind: "settings", path: "testdata/repo/.claude/settings.json"},
		{kind: "mcp", path: "testdata/repo/.mcp.json"},
		{kind: "skill", path: "testdata/repo/.claude/skills/review/SKILL.md"},
	} {
		data, err := os.ReadFile(seed.path)
		if err == nil {
			f.Add(seed.kind, data)
		}
	}
	f.Fuzz(func(t *testing.T, path string, data []byte) {
		switch path {
		case "mcp":
			_, _ = parseMCP(model.ScopeRepo, ".mcp.json", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data)
		case "skill":
			_, _ = parseSkill(model.ScopeRepo, ".claude/skills/a/SKILL.md", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data)
		default:
			_, _ = parseSettings(model.ScopeRepo, ".claude/settings.json", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", data)
		}
	})
}

func copyFixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	err := filepath.WalkDir(filepath.Join("testdata", "repo"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(filepath.Join("testdata", "repo"), path)
		if err != nil {
			return err
		}
		destination := filepath.Join(root, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}
