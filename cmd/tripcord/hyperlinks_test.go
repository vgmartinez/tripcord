package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

func TestTextHyperlinksConditions(t *testing.T) {
	terminal := func(io.Writer) bool { return true }
	piped := func(io.Writer) bool { return false }
	cases := []struct {
		name       string
		outputPath string
		terminal   bool
		env        map[string]string
		want       bool
	}{
		{name: "tty stdout", terminal: true, want: true},
		{name: "piped stdout", terminal: false, want: false},
		{name: "output file", outputPath: "report.txt", terminal: true, want: false},
		{name: "NO_COLOR", terminal: true, env: map[string]string{"NO_COLOR": "1"}, want: false},
		{name: "TERM=dumb", terminal: true, env: map[string]string{"TERM": "dumb"}, want: false},
		{name: "CI set", terminal: true, env: map[string]string{"CI": "true"}, want: false},
		{name: "FORCE_HYPERLINK=1 on a pipe", terminal: false, env: map[string]string{"FORCE_HYPERLINK": "1"}, want: true},
		{name: "FORCE_HYPERLINK=0 on a tty", terminal: true, env: map[string]string{"FORCE_HYPERLINK": "0"}, want: false},
		{name: "FORCE_HYPERLINK=1 with NO_COLOR and CI", terminal: false, outputPath: "report.txt", env: map[string]string{"FORCE_HYPERLINK": "1", "NO_COLOR": "1", "CI": "true", "TERM": "dumb"}, want: true},
		{name: "empty NO_COLOR on a tty", terminal: true, env: map[string]string{"NO_COLOR": ""}, want: true},
		{name: "stdout dash is still stdout", outputPath: "-", terminal: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(key string) string {
				if tc.env != nil {
					if v, ok := tc.env[key]; ok {
						return v
					}
				}
				return ""
			}
			isTerm := piped
			if tc.terminal {
				isTerm = terminal
			}
			orig := stdoutIsTerminal
			stdoutIsTerminal = isTerm
			defer func() { stdoutIsTerminal = orig }()
			got := textHyperlinksEnv(tc.outputPath, os.Stdout, getenv)
			if got != tc.want {
				t.Fatalf("textHyperlinksEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScanTextHyperlinksPipedAndOutput(t *testing.T) {
	repo := scanHyperlinkRepo(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("piped scan = %d\nstderr: %s\nstdout: %s", code, stderr.String(), stdout.String())
	}
	if strings.Contains(stdout.String(), "\x1b") {
		t.Fatalf("piped stdout contained a terminal escape:\n%q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "TC-CFG-002") {
		t.Fatalf("piped stdout missing rule id:\n%s", stdout.String())
	}

	out := filepath.Join(t.TempDir(), "report.txt")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "--output", out, repo}, &stdout, &stderr); code != int(exitcode.Findings) {
		t.Fatalf("--output scan = %d\nstderr: %s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\x1b") {
		t.Fatalf("--output file contained a terminal escape:\n%q", data)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty when writing a file", stdout.String())
	}
}

func TestScanTextHyperlinksForceAndTTY(t *testing.T) {
	repo := scanHyperlinkRepo(t)

	t.Run("injected tty emits links", func(t *testing.T) {
		t.Setenv("CI", "")
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm")
		t.Setenv("FORCE_HYPERLINK", "")
		orig := stdoutIsTerminal
		stdoutIsTerminal = func(io.Writer) bool { return true }
		defer func() { stdoutIsTerminal = orig }()
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("tty scan = %d\nstderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "\x1b]8;;https://github.com/vgmartinez/tripcord/blob/") {
			t.Fatalf("tty stdout missing a rule-doc link:\n%q", stdout.String())
		}
	})

	t.Run("NO_COLOR on a tty suppresses links", func(t *testing.T) {
		t.Setenv("CI", "")
		t.Setenv("NO_COLOR", "1")
		t.Setenv("TERM", "xterm")
		t.Setenv("FORCE_HYPERLINK", "")
		orig := stdoutIsTerminal
		stdoutIsTerminal = func(io.Writer) bool { return true }
		defer func() { stdoutIsTerminal = orig }()
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("NO_COLOR scan = %d\nstderr: %s", code, stderr.String())
		}
		if strings.Contains(stdout.String(), "\x1b") {
			t.Fatalf("NO_COLOR stdout contained a terminal escape:\n%q", stdout.String())
		}
	})

	t.Run("TERM=dumb on a tty suppresses links", func(t *testing.T) {
		t.Setenv("CI", "")
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "dumb")
		t.Setenv("FORCE_HYPERLINK", "")
		orig := stdoutIsTerminal
		stdoutIsTerminal = func(io.Writer) bool { return true }
		defer func() { stdoutIsTerminal = orig }()
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("TERM=dumb scan = %d\nstderr: %s", code, stderr.String())
		}
		if strings.Contains(stdout.String(), "\x1b") {
			t.Fatalf("TERM=dumb stdout contained a terminal escape:\n%q", stdout.String())
		}
	})

	t.Run("FORCE_HYPERLINK=1 on a pipe emits links", func(t *testing.T) {
		t.Setenv("FORCE_HYPERLINK", "1")
		t.Setenv("CI", "true")
		t.Setenv("NO_COLOR", "1")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("FORCE_HYPERLINK=1 scan = %d\nstderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "\x1b]8;;https://github.com/vgmartinez/tripcord/blob/") {
			t.Fatalf("FORCE_HYPERLINK=1 stdout missing a rule-doc link:\n%q", stdout.String())
		}
	})

	t.Run("FORCE_HYPERLINK=0 on a tty suppresses links", func(t *testing.T) {
		t.Setenv("FORCE_HYPERLINK", "0")
		t.Setenv("CI", "")
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm")
		orig := stdoutIsTerminal
		stdoutIsTerminal = func(io.Writer) bool { return true }
		defer func() { stdoutIsTerminal = orig }()
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", repo}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("FORCE_HYPERLINK=0 scan = %d\nstderr: %s", code, stderr.String())
		}
		if strings.Contains(stdout.String(), "\x1b") {
			t.Fatalf("FORCE_HYPERLINK=0 stdout contained a terminal escape:\n%q", stdout.String())
		}
	})
}

func scanHyperlinkRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".vscode", "tasks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := txtarMember(t, "rules/TC-CFG-002.test/positivos/folderopen-local-script.txtar", ".vscode/tasks.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}
