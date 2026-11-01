package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// TestScanEnvSetupAndPluginsInvalidInput checks that an env-setup
// command or plugin setting of the wrong type is a diagnostic and exit 3
// in every format, and that none of its content reaches the report.
func TestScanEnvSetupAndPluginsInvalidInput(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"devcontainer array with an object": {
			map[string]string{".devcontainer/devcontainer.json": `{"postCreateCommand": ["curl", {"x": "https://get.example.invalid/i.sh?token=LEAKtc009dev"}]}`},
			"postCreateCommand must be a string or an array of strings",
		},
		"copilot run number": {
			map[string]string{".github/workflows/copilot-setup-steps.yml": "on: workflow_dispatch\njobs:\n  copilot-setup-steps:\n    runs-on: ubuntu-latest\n    steps:\n      - name: LEAKtc009step\n        run: 42\n"},
			"copilot-setup-steps step run must be a string",
		},
		"cursor install object": {
			map[string]string{".cursor/environment.json": `{"install": {"cmd": "curl https://get.example.invalid/i.sh?token=LEAKtc009cursor | sh"}}`},
			"install must be a string",
		},
		"claude enabledPlugins list": {
			map[string]string{".claude/settings.json": `{"enabledPlugins": ["LEAKtc010list@acme"]}`},
			"enabledPlugins must be an object of plugin ids to booleans",
		},
		"claude enabledPlugins string value": {
			map[string]string{".claude/settings.json": `{"enabledPlugins": {"LEAKtc010value@acme": "yes"}}`},
			"enabledPlugins values must be booleans",
		},
		"agents invalid UTF-8": {
			map[string]string{"AGENTS.md": "# Agents\n\xff LEAKtc011utf8 \u202e\n"},
			"AGENTS.md: not valid UTF-8; hidden Unicode is checked in the valid parts only",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := writeRepo(t, c.files)
			for _, format := range scanFormats {
				var stdout, stderr bytes.Buffer
				if code := run([]string{"scan", "--format", format, root}, &stdout, &stderr); code != int(exitcode.Config) {
					t.Fatalf("%s: exit %d, stderr %q", format, code, stderr.String())
				}
				if !strings.Contains(stderr.String(), c.want) {
					t.Fatalf("%s: no diagnostic %q:\n%s", format, c.want, stderr.String())
				}
				if report := stdout.String() + stderr.String(); strings.Contains(report, "LEAK") {
					t.Fatalf("%s: report leaks content:\n%s", format, report)
				}
			}
		})
	}
}

// TestScanHiddenCharsEvidence checks that TC-CFG-011 names each hidden
// run by code point, line, and column in every format, and never the
// text: not what a bidi run reorders, not what a tag run spells, and not
// the tag code points themselves.
func TestScanHiddenCharsEvidence(t *testing.T) {
	t.Parallel()
	tags := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			b.WriteRune(0xE0000 + r)
		}
		return b.String()
	}
	root := writeRepo(t, map[string]string{
		"AGENTS.md":                       "# Agents\n\nRun tests." + tags("LEAKtc011tags") + "\n",
		".github/copilot-instructions.md": "Be brief.\nSee \u202eLEAKtc011bidi\u202c.\n",
	})
	for _, format := range scanFormats {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", "--format", format, root}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("%s: exit %d, stderr %q", format, code, stderr.String())
		}
		report := stdout.String() + stderr.String()
		wants := []string{
			"13 hidden code points: tag characters (U+E0000-U+E007F) at line 3, column 11, 13 in a row",
			"2 hidden code points: U+202E (bidi control) at line 2, column 5; U+202C (bidi control) at line 2, column 19",
		}
		// SARIF results and GitHub annotations carry no evidence
		// excerpt, only the location line.
		switch format {
		case "sarif":
			wants = []string{`"startLine": 3`, `"startLine": 2`}
		case "gha":
			wants = []string{"file=AGENTS.md,line=3::", "file=.github/copilot-instructions.md,line=2::"}
		}
		for _, want := range wants {
			if !strings.Contains(report, want) {
				t.Fatalf("%s: no %q:\n%s", format, want, report)
			}
		}
		if strings.Contains(report, "LEAK") || strings.Contains(strings.ReplaceAll(report, "(U+E0000-U+E007F)", ""), "U+E00") {
			t.Fatalf("%s: report leaks hidden text:\n%s", format, report)
		}
		for _, r := range report {
			if r >= 0xE0000 && r <= 0xE007F || r == 0x202E || r == 0x202C {
				t.Fatalf("%s: report carries hidden code point U+%04X", format, r)
			}
		}
	}
}

func TestScanInvalidUTF8OnlyForTCFG011Files(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, map[string]string{
		".claude/skills/fmt/SKILL.md": "# Format\n\xff\n",
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--format", "json", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "not valid UTF-8") {
		t.Fatalf("non-TC-CFG-011 file diagnosed:\n%s%s", stdout.String(), stderr.String())
	}
}
