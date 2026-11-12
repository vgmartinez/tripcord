package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/hiddenchar"
	"github.com/vgmartinez/tripcord/internal/preopen/preopentest"
)

// TestOversizePlaceholderScanMatchesFullBlob compares a full tree
// (what preopen on f08138f would write for blobs over 1 MiB, when the
// 1 GiB budget allows it) with a tree whose over-cap blobs are
// placeholders of cap+1 bytes (what preopen writes now). Discover,
// scriptcheck, hiddenchar, and the engine must produce the same
// findings and the same diagnostics.
func TestOversizePlaceholderScanMatchesFullBlob(t *testing.T) {
	preopentest.RequireTools(t)
	preopenTemp(t)

	const sums = "abababababababababababababababababababababababababababababababab  tool.bin\n"
	copilot := strings.Join([]string{
		"on: workflow_dispatch",
		"jobs:",
		"  copilot-setup-steps:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - uses: actions/checkout@v4",
		"      - run: |",
		"          curl -fsSLo tool.bin https://get.tools.example.invalid/tool.bin",
		"          sha256sum -c SHA256SUMS",
		"          chmod +x tool.bin && ./tool.bin",
	}, "\n") + "\n"
	mcp := `{
  "mcpServers": {
    "helper": {
      "command": "bash",
      "args": ["-c", "set -a && source .env && npx -y notes-mcp"]
    }
  }
}
`
	// Hidden bidi in a 2 MiB AGENTS.md must not be scanned on either
	// tree: the file exceeds MaxConfigFileBytes, so hiddenchar never
	// sees the bytes.
	agentsFull := append([]byte{0xe2, 0x80, 0xaa}, bytes.Repeat([]byte("A"), 2<<20)...) // U+202A
	settings := preopentest.ClaudeSettings

	writeTree := func(dir string, toolSize int64, agents []byte, envSize int64) {
		t.Helper()
		preopentest.WriteFile(t, filepath.Join(dir, ".claude", "settings.json"), settings, 0o644)
		preopentest.WriteFile(t, filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
		preopentest.WriteFile(t, filepath.Join(dir, ".github", "workflows", "copilot-setup-steps.yml"), copilot, 0o644)
		preopentest.WriteFile(t, filepath.Join(dir, ".mcp.json"), mcp, 0o644)
		writeSparse(t, filepath.Join(dir, "tool.bin"), toolSize)
		writeSparse(t, filepath.Join(dir, ".env"), envSize)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "AGENTS.md"), agents, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	full := t.TempDir()
	hole := t.TempDir()
	writeTree(full, 2<<20, agentsFull, 2<<20)
	writeTree(hole, adapters.MaxConfigFileBytes+1, bytes.Repeat([]byte("x"), int(adapters.MaxConfigFileBytes+1)), adapters.MaxConfigFileBytes+1)

	fullOut, fullErr, fullCode := scanJSON(t, full)
	holeOut, holeErr, holeCode := scanJSON(t, hole)
	if fullCode != holeCode {
		t.Fatalf("exit full=%d hole=%d\nfull stderr: %s\nhole stderr: %s", fullCode, holeCode, fullErr, holeErr)
	}

	fullKeys := recordKeys(t, fullOut)
	holeKeys := recordKeys(t, holeOut)
	if !slices.Equal(fullKeys, holeKeys) {
		t.Fatalf("scan records diverged\nfull: %v\nhole: %v", fullKeys, holeKeys)
	}

	// Sanity: the hook still fires, the oversized instruction file is a
	// diagnostic not a hidden-char finding, and checksum credit does not
	// flip just because tool.bin is a placeholder.
	joined := strings.Join(fullKeys, "\n")
	if !strings.Contains(joined, "finding TC-CFG-001 .claude/settings.json") {
		t.Fatalf("missing hook finding:\n%s", joined)
	}
	if strings.Contains(joined, "finding TC-CFG-011") || strings.Contains(joined, "finding TC-CFG-012") {
		t.Fatalf("hidden-char finding on an unscanned oversize AGENTS.md:\n%s", joined)
	}
	if !strings.Contains(joined, "diagnostic AGENTS.md") || !strings.Contains(joined, "file exceeds size limit") {
		t.Fatalf("missing too-large diagnostic for AGENTS.md:\n%s", joined)
	}
	// Confirm the full AGENTS.md really would have hidden chars if it
	// had been read: this guards the test fixture.
	if h, _ := hiddenchar.Scan(agentsFull); h.Total == 0 {
		t.Fatal("fixture AGENTS.md has no hidden chars to miss")
	}
}

func writeSparse(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func scanJSON(t *testing.T, root string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run([]string{"scan", "--format", "json", root}, &out, &errb)
	return out.String(), errb.String(), code
}

func recordKeys(t *testing.T, raw string) []string {
	t.Helper()
	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			Schema, Rule, Message, Severity string
			Location                        struct {
				Path string
			}
			Path string
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("json: %v\n%s", err, line)
		}
		switch rec.Schema {
		case "tripcord.finding/v1":
			keys = append(keys, "finding "+rec.Rule+" "+rec.Location.Path+" "+rec.Severity)
		case "tripcord.diagnostic/v1":
			path := rec.Path
			if path == "" {
				path = rec.Location.Path
			}
			keys = append(keys, "diagnostic "+path+" "+rec.Message)
		}
	}
	slices.Sort(keys)
	return keys
}
