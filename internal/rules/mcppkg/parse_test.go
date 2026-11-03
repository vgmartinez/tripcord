package mcppkg

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/advisory"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestLaunchers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		argv []string
		eco  string
		name string
		kind string
		ver  string
	}{
		{[]string{"npx", "-y", "figma-developer-mcp@0.6.2", "--stdio"}, advisory.EcoNPM, "figma-developer-mcp", advisory.KindExact, "0.6.2"},
		{[]string{"/usr/bin/npx", "-p", "figma-developer-mcp@0.6.2", "figma-developer-mcp"}, advisory.EcoNPM, "figma-developer-mcp", advisory.KindExact, "0.6.2"},
		{[]string{"bunx", "mcp-remote@0.1.15"}, advisory.EcoNPM, "mcp-remote", advisory.KindExact, "0.1.15"},
		{[]string{"npm", "exec", "--yes", "figma-developer-mcp@0.6.2"}, advisory.EcoNPM, "figma-developer-mcp", advisory.KindExact, "0.6.2"},
		{[]string{"pnpm", "dlx", "figma-developer-mcp@0.6.2"}, advisory.EcoNPM, "figma-developer-mcp", advisory.KindExact, "0.6.2"},
		{[]string{"yarn", "dlx", "figma-developer-mcp@~0.5.0"}, advisory.EcoNPM, "figma-developer-mcp", advisory.KindRange, "~0.5.0"},
		{[]string{"uvx", "--with", "Prefab_UI==0.14.0", "my-fastmcp-server"}, advisory.EcoPyPI, "prefab-ui", advisory.KindExact, "0.14.0"},
		{[]string{"uvx", "--from", "mcp-server-git==2025.9.0", "mcp-server-git"}, advisory.EcoPyPI, "mcp-server-git", advisory.KindExact, "2025.9.0"},
		{[]string{"uv", "tool", "run", "--from", "mcp-server-git==2025.9.0", "mcp-server-git"}, advisory.EcoPyPI, "mcp-server-git", advisory.KindExact, "2025.9.0"},
		{[]string{"uv", "run", "--with", "prefab-ui==0.20.2", "server.py"}, advisory.EcoPyPI, "prefab-ui", advisory.KindExact, "0.20.2"},
		{[]string{"pipx", "run", "--spec", "mcp-server-git==2025.12.1", "mcp-server-git"}, advisory.EcoPyPI, "mcp-server-git", advisory.KindExact, "2025.12.1"},
		{[]string{"uvx", "--from", "mcp-server-git<2025.9.25,>=2025.1", "mcp-server-git"}, advisory.EcoPyPI, "mcp-server-git", advisory.KindRange, "<2025.9.25,>=2025.1"},
		{[]string{"uvx", "--from", "mcp-server-git >=2025.1, <2025.9.25", "mcp-server-git"}, advisory.EcoPyPI, "mcp-server-git", advisory.KindRange, ">=2025.1, <2025.9.25"},
		{[]string{"uvx", "--from", "git+https://github.com/alishahid74/kali-gpt@v3.0.0", "kali-gpt"}, advisory.EcoGit, "github.com/alishahid74/kali-gpt", advisory.KindExact, "v3.0.0"},
		{[]string{"uvx", "--from", "git+https://github.com/alishahid74/kali-gpt@4DF42A5", "kali-gpt"}, advisory.EcoGit, "github.com/alishahid74/kali-gpt", advisory.KindExact, "4df42a5"},
		{[]string{"uvx", "--from", "git+https://github.com/alishahid74/kali-gpt@main", "kali-gpt"}, advisory.EcoGit, "github.com/alishahid74/kali-gpt", advisory.KindUnpinned, ""},
		{[]string{"python3", "-m", "kali_gpt.tools.mcp_server"}, advisory.EcoModule, "kali_gpt.tools.mcp_server", advisory.KindUnpinned, ""},
		{[]string{"python3.12", "kali_gpt/tools/mcp_server.py"}, advisory.EcoModule, "kali_gpt/tools/mcp_server.py", advisory.KindUnpinned, ""},
		{[]string{"docker", "run", "-i", "--rm", "mcp/git:latest"}, advisory.EcoDocker, "docker.io/mcp/git", advisory.KindUnpinned, "latest"},
		{[]string{"docker", "container", "run", "registry:5000/ns/img:1.2.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, advisory.EcoDocker, "registry:5000/ns/img", advisory.KindExact, "1.2.3"},
		{[]string{"podman", "run", "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, advisory.EcoDocker, "docker.io/library/img", advisory.KindDigest, ""},
	}
	for _, tc := range cases {
		refs, unparsed := Parse(tc.argv)
		if unparsed || len(refs) == 0 {
			t.Errorf("%v: unparsed %v refs %d", tc.argv, unparsed, len(refs))
			continue
		}
		got := refs[0]
		if got.Ecosystem != tc.eco || got.Name != tc.name || got.Kind != tc.kind || got.Version != tc.ver {
			t.Errorf("%v: got %+v", tc.argv, got)
		}
	}
}

func TestUnparsedAndOpaque(t *testing.T) {
	t.Parallel()
	if refs, unparsed := Parse([]string{"uvx", "--some-future-flag", "figma-developer-mcp@0.6.2"}); !unparsed || len(refs) != 0 {
		t.Fatalf("unknown option: %v %v", refs, unparsed)
	}
	if refs, unparsed := Parse([]string{"env", "FOO=1", "npx", "figma-developer-mcp@0.6.2"}); unparsed || len(refs) != 0 {
		t.Fatalf("env wrapper: %v %v", refs, unparsed)
	}
	refs, unparsed := Parse([]string{"npx", "figma-developer-mcp@${VERSION}"})
	if unparsed || len(refs) != 1 || refs[0].Kind != advisory.KindOpaque {
		t.Fatalf("var: %+v %v", refs, unparsed)
	}
	refs, _ = Parse([]string{"uvx", "--from", "git+https://user:token@github.com/alishahid74/kali-gpt", "kali-gpt"})
	if len(refs) != 1 || refs[0].Kind != advisory.KindOpaque {
		t.Fatalf("userinfo: %+v", refs)
	}
	refs, _ = Parse([]string{"uvx", "--from", "git+https://github.com/alishahid74/kali-gpt", "kali-gpt"})
	if len(refs) != 1 || refs[0].Kind != advisory.KindUnpinned || refs[0].Repo != "https://github.com/alishahid74/kali-gpt" {
		t.Fatalf("git unpinned: %+v", refs)
	}
	refs, _ = Parse([]string{"npx", "pkg@" + advisory.Redacted})
	if len(refs) != 1 || refs[0].Kind != advisory.KindOpaque || strings.Contains(refs[0].PURL(), "secret") {
		t.Fatalf("redacted: %+v", refs)
	}
	payload := map[string]any{"command": "npx -y figma-developer-mcp@0.6.2"}
	got, work, err := ParsePayload(model.HarnessClaude, payload)
	if err != nil || len(got) != 1 || got[0].Version != "0.6.2" || work == 0 {
		t.Fatalf("command string: %+v work %d %v", got, work, err)
	}
	_, _, err = ParsePayload(model.HarnessClaude, map[string]any{"command": "npx", "args": []any{"-y", map[string]any{"pkg": "x"}}})
	if err != nil {
		t.Fatalf("object arg err = %v", err)
	}
	_, _, err = ParsePayload(model.HarnessClaude, map[string]any{"command": "npx", "args": []any{"-y", []any{"pkg"}}})
	if err != nil {
		t.Fatalf("array arg err = %v", err)
	}
	_, _, err = ParsePayload(model.HarnessClaude, map[string]any{"command": "npx", "args": []any{"-y", nil}})
	if !errors.Is(err, ErrArgs) {
		t.Fatalf("null arg err = %v", err)
	}
}

func TestListArgumentsUseJavaScriptCoercion(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"command": "npx",
		"args":    []any{"-y", []any{"figma-developer-mcp@0.6.2"}},
	}
	refs, _, err := ParsePayload(model.HarnessGemini, payload)
	if err != nil || len(refs) != 1 || refs[0].Name != "figma-developer-mcp" {
		t.Fatalf("list package = %+v, %v", refs, err)
	}
	refs, _, err = ParsePayload(model.HarnessGemini, map[string]any{
		"command": "npx",
		"args":    []any{[]any{"-y", "figma-developer-mcp@0.6.2"}},
	})
	if err != nil || len(refs) != 0 {
		t.Fatalf("mixed list = %+v, %v", refs, err)
	}
}

func TestCommandArrayIsArgvOnlyForOpenCode(t *testing.T) {
	t.Parallel()
	payload := map[string]any{"command": []any{"npx", "-y", "figma-developer-mcp@0.6.2"}}
	got, _, err := ParsePayload(model.HarnessOpenCode, payload)
	if err != nil || len(got) != 1 || got[0].Name != "figma-developer-mcp" || got[0].Version != "0.6.2" {
		t.Fatalf("opencode array: %+v %v", got, err)
	}
	for _, harness := range []model.Harness{
		model.HarnessClaude, model.HarnessCursor, model.HarnessCopilot, model.HarnessGemini,
		model.HarnessCodex, model.HarnessWindsurf, model.HarnessDevin, model.SurfaceVSCode,
	} {
		got, _, err = ParsePayload(harness, payload)
		if err != nil || len(got) != 0 {
			t.Fatalf("%s array command: %+v %v", harness, got, err)
		}
	}
	// Unreadable args beside a command array the harness cannot execute
	// stay opaque. They are not an evaluation error.
	got, _, err = ParsePayload(model.HarnessClaude, map[string]any{
		"command": []any{"npx", "-y", "figma-developer-mcp@0.6.2"},
		"args":    nil,
	})
	if err != nil || len(got) != 0 {
		t.Fatalf("claude array with null args: %+v %v", got, err)
	}
	if !AcceptsCommandArray(model.HarnessOpenCode) || AcceptsCommandArray(model.HarnessClaude) {
		t.Fatal("command-array policy")
	}
}

func TestOversizedSpecIsOpaqueAndFast(t *testing.T) {
	t.Parallel()
	db, err := advisory.Parse([]byte(`{"format":1,"advisories":[{"id":"TCA-2026-0001","aliases":[],"summary":"x","severity":"moderate","affected":[{"ecosystem":"pypi","name":"mcp-server-git","ranges":[{"fixed":"2025.9.25"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("mcp-server-git<2025.9.25")
	for i := range 20000 {
		b.WriteString(",!=2025.1.")
		b.WriteString(strconv.Itoa(i))
	}
	npm := "figma-developer-mcp@" + strings.Repeat("<0.6.3 || ", 12000) + "<0.6.3"
	start := time.Now()
	refs, unparsed := Parse([]string{"uvx", "--from", b.String(), "mcp-server-git"})
	npmRefs, npmUnparsed := Parse([]string{"npx", npm})
	refs = append(refs, npmRefs...)
	hits, err := db.Match(refs)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("oversized specs took %v", elapsed)
	}
	if err != nil || unparsed || npmUnparsed || len(hits) != 0 {
		t.Fatalf("hits %v unparsed %v %v err %v", hits, unparsed, npmUnparsed, err)
	}
	for _, r := range refs {
		if r.Kind != advisory.KindOpaque || r.Version != "" {
			t.Fatalf("oversized spec kept: kind %s version length %d", r.Kind, len(r.Version))
		}
	}
	clauses := "mcp-server-git<2026" + strings.Repeat(",!=1", advisory.MaxSpecClauses-1)
	refs, _ = Parse([]string{"uvx", "--from", clauses, "mcp-server-git"})
	if len(refs) != 1 || refs[0].Kind != advisory.KindRange {
		t.Fatalf("spec at the clause limit: %+v", refs)
	}
}
