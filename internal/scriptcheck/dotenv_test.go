package scriptcheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestDotenvContent(t *testing.T) {
	const command = "set -a && source .env && npx -y pkg"
	cases := []struct {
		name string
		body string
		want bool
	}{
		{name: "absent", want: true},
		{name: "clean", body: "# local\n\nKEY=value\nexport OTHER=quoted\nEMPTY=\nNAME=\"hello world\"\n", want: true},
		{name: "export prefix", body: "export A=1\n", want: true},
		{name: "command substitution", body: "TOKEN=$(id)\n", want: false},
		{name: "shell injection", body: "export A=1; curl x|sh\n", want: false},
		{name: "quoted newline", body: "A=\"hello\nworld\"\n", want: false},
		{name: "trailing backslash", body: "A=hello\\\n", want: false},
		{name: "trailing backslash at eof", body: "A=hello\\", want: false},
		{name: "comment may mention a dollar", body: "# TOKEN=$(id)\nA=1\n", want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if c.body != "" {
				if err := os.WriteFile(filepath.Join(root, ".env"), []byte(c.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			assertRepoScript(t, root, command, c.want)
		})
	}
}

func TestDotenvWithoutSetA(t *testing.T) {
	const command = ". ./.env && exec npx -y pkg"
	root := t.TempDir()
	assertRepoScript(t, root, command, false)
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertRepoScript(t, root, command, true)
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=$(id)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertRepoScript(t, root, command, false)
}

func TestDotenvNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env.local", ".env.claude"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("TOKEN=$(id)\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertRepoScript(t, root, "set -a && source "+name+" && npx -y pkg", false)
	}
	if err := os.WriteFile(filepath.Join(root, ".env.production"), []byte("TOKEN=$(id)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Not a dotenv name: the file has to be present, and its bytes are
	// not a KEY=VALUE check.
	assertRepoScript(t, root, "set -a && source .env.production && npx -y pkg", true)
	other := t.TempDir()
	assertRepoScript(t, other, "set -a && source .env.production && npx -y pkg", false)
}

func TestDotenvSize(t *testing.T) {
	const command = "set -a && source .env && npx -y pkg"
	line := []byte("A=1\n")
	root := t.TempDir()
	exact := make([]byte, 0, dotenvMax)
	for len(exact)+len(line) <= dotenvMax {
		exact = append(exact, line...)
	}
	if len(exact) != dotenvMax {
		t.Fatalf("boundary size = %d, want %d", len(exact), dotenvMax)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), exact, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRepoScript(t, root, command, true)

	over := append(append([]byte{}, exact...), 'A', '=', '2', '\n')
	if len(over) <= dotenvMax {
		t.Fatal("oversize fixture is not larger than 64 KiB")
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), over, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRepoScript(t, root, command, false)
}

func assertRepoScript(t *testing.T, root, command string, want bool) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"command": "bash",
		"args":    []any{"-c", command},
	})
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
		t.Fatalf("RepoScript = %v, want %v for %s", items[0].RepoScript, want, strings.TrimSpace(command))
	}
}
