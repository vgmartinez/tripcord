package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/exitcode"
)

func TestVersion(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		{"version"},
		{"--version"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if got, want := stdout.String(), version+"\n"; got != want {
				t.Fatalf("stdout = %q, want %q", got, want)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		nil,
		{"help"},
		{"-h"},
		{"--help"},
	}
	for _, args := range cases {
		name := "no args"
		if len(args) > 0 {
			name = strings.Join(args, " ")
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if got := stdout.String(); got != usage {
				t.Fatalf("stdout = %q, want usage text", got)
			}
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestVersionWriteError(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := run([]string{"version"}, failWriter{}, &stderr); code != int(exitcode.Internal) {
		t.Fatalf("exit code = %d, want %d (internal or I/O error)", code, exitcode.Internal)
	}
}

func TestScanHelpWriteError(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	if code := run([]string{"scan", "--help"}, failWriter{}, &stderr); code != int(exitcode.Internal) {
		t.Fatalf("exit code = %d, want %d (internal or I/O error)", code, exitcode.Internal)
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run([]string{"unknown"}, &stdout, &stderr)
	if code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, want %d (configuration error)", code, exitcode.Config)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if got, want := stderr.String(), "tripcord: unknown command \"unknown\"\n\n"+usage; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestScanTextGolden(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	assertGolden(t, "scan-text.golden", stdout.String())
}

func TestScanClaudeFixtureJSON(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"tripcord hook"}]}]}}`
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--format", "json", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("json output = %q, want no findings", stdout.String())
	}
}

func TestScanReportsIncompleteDiscovery(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "evil\x1b[2J", ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"hooks":{},"Hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "md", "sarif", "text"} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run([]string{"scan", "--format", format, root}, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			msg := stderr.String()
			report := stdout.String()
			if !strings.Contains(msg, "case-variant keys") || !strings.Contains(msg, "scan is incomplete") || strings.Contains(msg, "\x1b") || strings.Contains(msg, root) {
				t.Fatalf("stderr = %q", msg)
			}
			if strings.Contains(report, "\x1b") || strings.Contains(report, root) || !strings.Contains(report, "case-variant keys") {
				t.Fatalf("report = %s", report)
			}
			switch format {
			case "json":
				if !strings.Contains(report, `"schema":"tripcord.diagnostic/v1"`) || !strings.Contains(report, `"incomplete":true`) {
					t.Fatalf("json = %s", report)
				}
			case "md":
				if !strings.Contains(report, "The scan is incomplete.") {
					t.Fatalf("markdown = %s", report)
				}
			case "sarif":
				if !strings.Contains(report, `"executionSuccessful": false`) || !strings.Contains(report, `"toolExecutionNotifications"`) {
					t.Fatalf("sarif = %s", report)
				}
			case "text":
				if !strings.Contains(report, "scan incomplete") {
					t.Fatalf("text = %s", report)
				}
			}
		})
	}
}

func TestScanSecretsAndAllDoNotScan(t *testing.T) {
	t.Parallel()
	const want = "tripcord scan: secret scanning lands in v1; v0 supports --config only\n"
	for _, flagName := range []string{"--secrets", "--all"} {
		t.Run(flagName, func(t *testing.T) {
			t.Parallel()
			outputPath := filepath.Join(t.TempDir(), "findings.txt")
			var stdout, stderr bytes.Buffer
			// A missing repository would fail discovery if scanning started.
			args := []string{"scan", flagName, "--output", outputPath, filepath.Join(t.TempDir(), "missing-repo")}
			if code := run(args, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stdout.Len() != 0 || stderr.String() != want {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
			if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Fatalf("scan wrote %s: %v", outputPath, err)
			}
		})
	}
}

func TestScanHelpMarksSecretFlagsAsV1(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run([]string{"scan", arg}, &stdout, &stderr); code != int(exitcode.OK) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			help := stdout.String()
			for _, flagName := range []string{"-secrets", "-all"} {
				if !strings.Contains(help, flagName) || !strings.Contains(help, "(v1) not available") {
					t.Fatalf("help = %q", help)
				}
			}
		})
	}
}

func TestScanFlagErrors(t *testing.T) {
	t.Parallel()
	dir := outsideGit(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"format", []string{"scan", "--format", "xml", dir}, "output format"},
		{"config and secrets", []string{"scan", "--config", "--secrets", dir}, "mutually exclusive"},
		{"config and all", []string{"scan", "--config", "--all", dir}, "mutually exclusive"},
		{"secrets and all", []string{"scan", "--secrets", "--all", dir}, "mutually exclusive"},
		{"scope", []string{"scan", "--scope", "workspace", dir}, "--scope"},
		{"harness", []string{"scan", "--harness", "vscode", dir}, "not a supported harness"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestScanFlagsAfterPath(t *testing.T) {
	t.Parallel()
	dir := outsideGit(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir, "--format", "text"}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), "0 finding(s)") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestScanScope(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--scope", "user", "--format", "text", root}, &stdout, &stderr); code != int(exitcode.OK) || stderr.Len() != 0 {
		t.Fatalf("user scope exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", root, "--scope", "repo"}, &stdout, &stderr); code != int(exitcode.Config) || !strings.Contains(stderr.String(), "incomplete") {
		t.Fatalf("repo scope exit %d stderr %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--scope", "repo", "--harness", "generic", root}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("generic scope exit %d stderr %q", code, stderr.String())
	}
}

func TestLegacyNoteDoesNotFailScan(t *testing.T) {
	legacy := t.TempDir()
	restore := claude.SetLegacyManagedDirForTest(legacy)
	t.Cleanup(restore)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--scope", "managed", "--format", "json", root}, &stdout, &stderr)
	if code != int(exitcode.OK) {
		t.Fatalf("exit %d stderr %q stdout %q", code, stderr.String(), stdout.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "not scanned") || strings.Contains(msg, "incomplete") || strings.Contains(msg, legacy) {
		t.Fatalf("stderr = %q", msg)
	}
	if strings.Contains(stdout.String(), "tripcord.diagnostic") || strings.Contains(stdout.String(), "incomplete") {
		t.Fatalf("report = %s", stdout.String())
	}
}

func TestPartitionDiagnostics(t *testing.T) {
	t.Parallel()
	blocking, notes := partitionDiagnostics([]adapters.Diagnostic{
		{Message: "note", Informational: true},
		{Message: "bad"},
	})
	if len(notes) != 1 || notes[0].Message != "note" || len(blocking) != 1 || blocking[0].Message != "bad" {
		t.Fatalf("blocking %+v notes %+v", blocking, notes)
	}
}

func outsideGit(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tripcord-scan-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s--- want ---\n%s", name, got, want)
	}
}
