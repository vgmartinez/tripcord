package scriptcheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestRepoScriptFailClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "run.sh"), []byte("echo decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "run.sh"), []byte("echo in-repo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scripts := []string{
		`set -a && source .env && rm -rf /`,
		`set -a && source .env && notes-mcp`,
		`set -a && source .env && evil-mcp "$TOKEN"`,
		`${X:-rm} -rf /`,
		"set -a\nsource .env\nrm -rf /",
		"set -a\nsource .env\nnotes-mcp",
		"set -a\nsource .env\nevil-mcp \"$TOKEN\"",
		`cd evildir && bash run.sh`,
		`cd evildir && ./run.sh`,
		`pushd evildir && ./run.sh`,
		`env -C /tmp bash scripts/run.sh`,
		`sudo --chdir /tmp bash scripts/run.sh`,
		`sudo -D /tmp bash scripts/run.sh`,
	}
	for _, script := range scripts {
		assertRepoScript(t, root, script, false)
	}
	assertRepoArgv(t, root, false, "env", "-C", "/tmp", "bash", "scripts/run.sh")
	assertRepoArgv(t, root, false, "sudo", "--chdir", "/tmp", "bash", "scripts/run.sh")
	assertRepoArgv(t, root, false, "sudo", "-D", "/tmp", "bash", "scripts/run.sh")
	assertRepoScript(t, root, "npx -y pkg", true)
	assertRepoScript(t, root, "pnpm dlx pkg", true)
	assertRepoScript(t, root, "bunx pkg", true)
	assertRepoScript(t, root, "uvx pkg", true)
	assertRepoScript(t, root, "bun x pkg", true)
}

func assertRepoArgv(t *testing.T, root string, want bool, argv ...string) {
	t.Helper()
	if len(argv) == 0 {
		t.Fatal("empty argv")
	}
	payload := map[string]any{"command": argv[0]}
	if len(argv) > 1 {
		args := make([]any, len(argv)-1)
		for i, a := range argv[1:] {
			args[i] = a
		}
		payload["args"] = args
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	items := []model.ConfigItem{{
		Harness: model.HarnessClaude,
		Scope:   model.ScopeRepo,
		Path:    ".mcp.json",
		Kind:    model.ConfigKindMCPServer,
		Payload: raw,
	}}
	if err := Annotate(root, items); err != nil {
		t.Fatal(err)
	}
	if items[0].RepoScript != want {
		t.Fatalf("RepoScript(%q) = %v, want %v", argv, items[0].RepoScript, want)
	}
}
