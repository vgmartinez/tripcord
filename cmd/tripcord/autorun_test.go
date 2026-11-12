package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/txtar"
)

// autorunDoc is one tripcord.autorun_hook/v1 JSON document.
type autorunDoc struct {
	Schema        string `json:"schema"`
	Informational bool   `json:"informational"`
	Harness       string `json:"harness"`
	Path          string `json:"path"`
	Line          int    `json:"line"`
	Event         string `json:"event"`
	Command       string `json:"command"`
	Target        string `json:"target"`
}

// autorunFixture is what scanning one testdata/autorun fixture must give:
// the inventory, the rules of the findings, the exit code with the
// default fail-on, and a message every diagnostic or warning on stderr
// must include (empty: none).
type autorunFixture struct {
	autorun []autorunDoc
	rules   []string
	exit    exitcode.Code
	stderr  string
}

func autorunEntry(harness, path string, line int, event, command, target string) autorunDoc {
	return autorunDoc{Schema: "tripcord.autorun_hook/v1", Informational: true, Harness: harness, Path: path, Line: line, Event: event, Command: command, Target: target}
}

var autorunFixtures = map[string]autorunFixture{
	"claude-sessionstart": {autorun: []autorunDoc{
		autorunEntry("claude", ".claude/settings.json", 6, "SessionStart", "./scripts/setup.sh", "scripts/setup.sh"),
	}},
	"claude-setup": {autorun: []autorunDoc{
		autorunEntry("claude", ".claude/settings.json", 6, "Setup", "bash scripts/init.sh", "scripts/init.sh"),
	}},
	"cursor-sessionstart": {autorun: []autorunDoc{
		autorunEntry("cursor", ".cursor/hooks.json", 5, "sessionStart", "node .cursor/hooks/start.mjs", ".cursor/hooks/start.mjs"),
	}},
	"claude-project-dir-two-scripts": {autorun: []autorunDoc{
		autorunEntry("claude", ".claude/settings.json", 8, "SessionStart", `"$CLAUDE_PROJECT_DIR"/.claude/hooks/a.sh && ./scripts/b.sh`, ".claude/hooks/a.sh"),
		autorunEntry("claude", ".claude/settings.json", 8, "SessionStart", `"$CLAUDE_PROJECT_DIR"/.claude/hooks/a.sh && ./scripts/b.sh`, "scripts/b.sh"),
	}},
	"not-listed-non-repo-command": {},
	"not-listed-other-events":     {},
	"not-listed-missing-script":   {rules: []string{"TC-CFG-006"}},
	"mod-module": {
		autorun: []autorunDoc{autorunEntry("claude", "hooks/hooks.json", 1, "modules", "./register.tsx", "hooks/register.tsx")},
		rules:   []string{"TC-CFG-010"},
	},
	"plugin-hooks-empty-object":     {rules: []string{"TC-CFG-010"}, stderr: "hooks/hooks.json: plugin hooks.json declares no hooks"},
	"plugin-hooks-description-only": {rules: []string{"TC-CFG-010"}, stderr: "hooks/hooks.json: plugin hooks.json declares no hooks"},
	"plugin-hooks-unknown-key":      {rules: []string{"TC-CFG-010"}, exit: exitcode.Config, stderr: `plugin hooks.json has no hooks object; unknown key "unknown"`},
	"mod-modules-two-paths":         {rules: []string{"TC-CFG-010"}, exit: exitcode.Config, stderr: "plugin hooks.json modules must be an array with one path"},
	"mod-modules-not-array":         {rules: []string{"TC-CFG-010"}, exit: exitcode.Config, stderr: "plugin hooks.json modules must be an array with one path"},
	"mod-modules-absolute":          {rules: []string{"TC-CFG-010"}, exit: exitcode.Config, stderr: `plugin hooks.json module "/opt/register.tsx" is not a relative path`},
	"mod-modules-escapes-plugin":    {rules: []string{"TC-CFG-010"}, exit: exitcode.Config, stderr: `plugin hooks.json module "../../register.tsx" is outside its plugin directory`},
}

// autorunScanJSON splits JSON scan output into finding rules, inventory
// documents, and the count of diagnostic documents. Any other document
// fails the test.
func autorunScanJSON(t *testing.T, stdout string) (rules []string, autorun []autorunDoc, diags int) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		var head struct {
			Schema string `json:"schema"`
			Rule   string `json:"rule"`
		}
		if err := json.Unmarshal([]byte(line), &head); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		switch head.Schema {
		case "tripcord.finding/v1":
			rules = append(rules, head.Rule)
		case "tripcord.diagnostic/v1":
			diags++
		case "tripcord.autorun_hook/v1":
			var doc autorunDoc
			dec := json.NewDecoder(strings.NewReader(line))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&doc); err != nil {
				t.Fatalf("%v: %s", err, line)
			}
			autorun = append(autorun, doc)
		default:
			t.Fatalf("unknown document %s", line)
		}
	}
	return rules, autorun, diags
}

// withoutKeyNote drops the fingerprint key note a scan prints on stderr
// in CI, which is not about the fixture.
func withoutKeyNote(stderr string) string {
	var kept []string
	for _, line := range strings.SplitAfter(stderr, "\n") {
		if !strings.Contains(line, "fingerprint key") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "")
}

func unpackAutorunFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "autorun", name+".txtar"))
	if err != nil {
		t.Fatal(err)
	}
	return txtar.Unpack(t, txtar.Parse(raw))
}

// TestAutorunInventoryFixtures scans each fixture: the inventory lists
// exactly the expected entries, and the findings and exit code are the
// ones the fixture expects, with and without --fail-on low.
func TestAutorunInventoryFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "autorun", "*.txtar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(autorunFixtures) {
		t.Fatalf("%d fixtures, %d expectations", len(files), len(autorunFixtures))
	}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".txtar")
		want, ok := autorunFixtures[name]
		if !ok {
			t.Fatalf("fixture %s has no expectation", name)
		}
		t.Run(name, func(t *testing.T) {
			dir := unpackAutorunFixture(t, name)
			code, stdout, stderr := runCLI(t, "scan", "--format", "json", dir)
			if code != int(want.exit) {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, want.exit, stdout, stderr)
			}
			rules, autorun, _ := autorunScanJSON(t, stdout)
			if !slices.Equal(rules, want.rules) {
				t.Fatalf("rules %v, want %v", rules, want.rules)
			}
			if !slices.Equal(autorun, want.autorun) {
				t.Fatalf("inventory\n got %+v\nwant %+v", autorun, want.autorun)
			}
			stderr = withoutKeyNote(stderr)
			if want.stderr == "" && stderr != "" {
				t.Fatalf("stderr: %s", stderr)
			}
			if want.stderr != "" && !strings.Contains(stderr, want.stderr) {
				t.Fatalf("stderr %q, want %q", stderr, want.stderr)
			}
			// --fail-on low fails on any finding and on nothing else: the
			// inventory never changes the exit code.
			lowCode, lowOut, _ := runCLI(t, "scan", "--format", "json", "--fail-on", "low", dir)
			wantLow := want.exit
			if wantLow == exitcode.OK && len(want.rules) > 0 {
				wantLow = exitcode.Findings
			}
			if lowCode != int(wantLow) || lowOut != stdout {
				t.Fatalf("--fail-on low: exit %d, want %d\n%s", lowCode, wantLow, lowOut)
			}
		})
	}
}

// TestAutorunWarningCountsOnce checks that an empty plugin hooks.json
// counts as one warning in the text summary and leaves the exit at 0.
func TestAutorunWarningCountsOnce(t *testing.T) {
	dir := unpackAutorunFixture(t, "plugin-hooks-empty-object")
	code, stdout, _ := runCLI(t, "scan", dir)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "; 1 warning(s); exit 0\n") || !strings.Contains(stdout, "warning: claude: hooks/hooks.json: plugin hooks.json declares no hooks\n") {
		t.Fatalf("text:\n%s", stdout)
	}
}

// TestAutorunTextViews checks where the text view lists the inventory:
// preopen by default, scan only with -v. The finding lines and the
// summary are the same with or without it.
func TestAutorunTextViews(t *testing.T) {
	files := map[string]string{
		".claude/settings.json": txtarMember(t, "cmd/tripcord/testdata/autorun/claude-sessionstart.txtar", ".claude/settings.json"),
		"scripts/setup.sh":      txtarMember(t, "cmd/tripcord/testdata/autorun/claude-sessionstart.txtar", "scripts/setup.sh"),
	}
	repo := preopenRepo(t, files)
	preopenTemp(t)

	const heading = "auto-run hooks (informational, not findings):\n"
	const entry = "  claude .claude/settings.json:6 SessionStart: scripts/setup.sh\n"
	var stdout, stderr bytes.Buffer
	if code := run([]string{"preopen", repo}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("preopen = %d\nstderr: %s", code, stderr.String())
	}
	want := "0 finding(s): 0 critical, 0 high, 0 medium, 0 low; 0 warning(s); exit 0\n" + heading + entry + "re-run with -v for details\n"
	if stdout.String() != want {
		t.Fatalf("preopen text:\n%s\nwant:\n%s", stdout.String(), want)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("scan = %d\nstderr: %s", code, stderr.String())
	}
	if got := stdout.String(); got != "0 finding(s): 0 critical, 0 high, 0 medium, 0 low; 0 warning(s); exit 0\nre-run with -v for details\n" {
		t.Fatalf("scan text lists the inventory without -v:\n%s", got)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "-v", repo}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("scan -v = %d\nstderr: %s", code, stderr.String())
	}
	wantV := "auto-run hook (informational, not a finding): claude .claude/settings.json:6 SessionStart: scripts/setup.sh | command: ./scripts/setup.sh\n" +
		"0 finding(s): 0 critical, 0 high, 0 medium, 0 low; 0 warning(s)\n"
	if stdout.String() != wantV {
		t.Fatalf("scan -v text:\n%s\nwant:\n%s", stdout.String(), wantV)
	}
}

// TestAutorunSARIFIsANotification checks that the inventory is a note
// in toolExecutionNotifications and never a result.
func TestAutorunSARIFIsANotification(t *testing.T) {
	dir := unpackAutorunFixture(t, "claude-sessionstart")
	code, stdout, stderr := runCLI(t, "scan", "--format", "sarif", dir)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var log struct {
		Runs []struct {
			Results     []json.RawMessage `json:"results"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
				Notes               []struct {
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
					Level string `json:"level"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 0 || len(log.Runs[0].Invocations) != 1 {
		t.Fatalf("sarif:\n%s", stdout)
	}
	inv := log.Runs[0].Invocations[0]
	if !inv.ExecutionSuccessful || len(inv.Notes) != 1 || inv.Notes[0].Level != "note" ||
		inv.Notes[0].Message.Text != "auto-run hook (informational, not a finding): claude .claude/settings.json:6 SessionStart: scripts/setup.sh" {
		t.Fatalf("sarif:\n%s", stdout)
	}
}

// TestAutorunSince checks that --since keeps only entries of
// changed files, like findings.
func TestAutorunSince(t *testing.T) {
	files := map[string]string{
		".claude/settings.json": txtarMember(t, "cmd/tripcord/testdata/autorun/claude-sessionstart.txtar", ".claude/settings.json"),
		"scripts/setup.sh":      txtarMember(t, "cmd/tripcord/testdata/autorun/claude-sessionstart.txtar", "scripts/setup.sh"),
	}
	repo := preopenRepo(t, files)
	code, stdout, stderr := runCLI(t, "scan", "--format", "json", "--since", "HEAD", repo)
	if code != int(exitcode.OK) || stdout != "" {
		t.Fatalf("--since HEAD: exit %d\n%s%s", code, stdout, stderr)
	}
}

// TestAutorunRedactsCommand checks that a credential in an auto-run
// hook's command never reaches the inventory, in any format that
// carries it.
func TestAutorunRedactsCommand(t *testing.T) {
	for _, canary := range redactionCanaries {
		if canary.argv != nil || strings.ContainsAny(canary.text, "\\\n") {
			continue
		}
		t.Run(canary.class, func(t *testing.T) {
			dir := t.TempDir()
			settings, err := json.Marshal(map[string]any{"hooks": map[string]any{"SessionStart": []any{
				map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "./scripts/setup.sh; " + canary.text}}},
			}}})
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, ".claude/settings.json", string(settings))
			writeTestFile(t, dir, "scripts/setup.sh", "#!/bin/sh\n")
			var listed bool
			for _, args := range [][]string{
				{"scan", "--format", "json", dir},
				{"scan", "--format", "sarif", dir},
				{"scan", "-v", dir},
			} {
				_, stdout, stderr := runCLI(t, args...)
				if strings.Contains(stdout+stderr, canary.secret) {
					t.Fatalf("%v leaked %s:\n%s%s", args, canary.secret, stdout, stderr)
				}
				listed = listed || strings.Contains(stdout, "scripts/setup.sh")
			}
			if !listed {
				t.Fatal("the hook was not listed, so the check proves nothing")
			}
		})
	}
}
