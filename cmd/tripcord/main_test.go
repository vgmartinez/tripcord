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

func TestScanV0SecretsError(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--secrets"}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "not available in v0") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
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
