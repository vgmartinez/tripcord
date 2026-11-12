package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

// TestPreopenTextFitsOneScreen checks the default text view of a typical
// two-finding repository: at most 24 lines, each at most 80 visible
// columns, a summary with the exit verdict, the rule ids, no OSC 8
// escapes on a piped stdout, and -v restoring the evidence, fix, and
// fingerprint.
func TestPreopenTextFitsOneScreen(t *testing.T) {
	repo := preopenRepo(t, map[string]string{
		".vscode/tasks.json":                        txtarMember(t, "rules/TC-CFG-002.test/positivos/folderopen-local-script.txtar", ".vscode/tasks.json"),
		".github/workflows/copilot-setup-steps.yml": txtarMember(t, "rules/TC-CFG-009.test/positivos/copilot-curl-pipe-sh.txtar", ".github/workflows/copilot-setup-steps.yml"),
	})
	preopenTemp(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"preopen", repo}, &stdout, &stderr)
	if code != int(exitcode.Findings) {
		t.Fatalf("preopen = %d, want %d\nstderr: %s\nstdout: %s", code, exitcode.Findings, stderr.String(), stdout.String())
	}
	got := stdout.String()
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) == 0 || len(lines) > 24 {
		t.Fatalf("%d lines, want 1..24:\n%s", len(lines), got)
	}
	for i, line := range lines {
		visible := osc8.ReplaceAllString(line, "")
		if n := utf8.RuneCountInString(visible); n > 80 {
			t.Fatalf("line %d visible width %d > 80: %q", i+1, n, visible)
		}
	}
	if !strings.Contains(lines[0], "exit 1") || !strings.Contains(lines[0], "finding(s)") {
		t.Fatalf("summary = %q", lines[0])
	}
	if lines[len(lines)-1] != "re-run with -v for details" {
		t.Fatalf("hint = %q", lines[len(lines)-1])
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("piped preopen contained a terminal escape:\n%q", got)
	}
	for _, id := range []string{"TC-CFG-002", "TC-CFG-009"} {
		if !strings.Contains(got, id) {
			t.Fatalf("missing %s:\n%s", id, got)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"preopen", "-v", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("preopen -v = %d, want %d\nstderr: %s", code, exitcode.Findings, stderr.String())
	}
	detail := stdout.String()
	for _, want := range []string{"fingerprint:", "fix:", "VS Code task that runs when the folder opens (also Cursor and Windsurf)", "TC-CFG-009"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("-v output missing %q:\n%s", want, detail)
		}
	}
	if strings.Contains(detail, "re-run with -v") {
		t.Fatalf("-v output still has the compact hint:\n%s", detail)
	}

	stdout.Reset()
	plain := bytes.Buffer{}
	verbose := bytes.Buffer{}
	if code := run([]string{"preopen", "--format", "json", repo}, &plain, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("json = %d\n%s", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"preopen", "--format", "json", "--verbose", repo}, &verbose, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("json -v = %d\n%s", code, stderr.String())
	}
	if plain.String() != verbose.String() {
		t.Fatal("json output changed with --verbose")
	}
	stderr.Reset()
	sarif := bytes.Buffer{}
	sarifV := bytes.Buffer{}
	if code := run([]string{"preopen", "--format", "sarif", repo}, &sarif, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("sarif = %d\n%s", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"preopen", "--format", "sarif", "-v", repo}, &sarifV, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("sarif -v = %d\n%s", code, stderr.String())
	}
	if sarif.String() != sarifV.String() {
		t.Fatal("sarif output changed with -v")
	}
}

var osc8 = regexp.MustCompile(`\x1b]8;;[^\x1b]*\x1b\\`)

func txtarMember(t *testing.T, rel, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	marker := "-- " + name + " --\n"
	rest, ok := strings.CutPrefix(string(data), marker)
	if !ok {
		i := strings.Index(string(data), "\n"+marker)
		if i < 0 {
			t.Fatalf("%s has no member %s", rel, name)
		}
		rest = string(data)[i+1+len(marker):]
	}
	if j := strings.Index(rest, "\n-- "); j >= 0 {
		rest = rest[:j+1]
	}
	return rest
}
