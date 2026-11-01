package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/fpkey"
)

// These tests set process environment, so none of them is parallel.

const keyTestSecret = "zsK01q-mcp-secret"

func keyTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mcp := `{"mcpServers":{"app":{"command":"docker","args":["run","-e","PRIVATE_KEY=` + keyTestSecret + `","img:1"]}}}`
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(mcp), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func setKeyEnv(t *testing.T, home string, vars map[string]string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, name := range []string{"CI", "GITHUB_ACTIONS", fpkey.EnvVar} {
		t.Setenv(name, vars[name])
	}
}

func scanAllFormats(t *testing.T, root string, wantCode exitcode.Code) string {
	t.Helper()
	var all strings.Builder
	for _, format := range []string{"text", "json", "sarif", "md", "gha"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", "--format", format, root}, &stdout, &stderr); code != int(wantCode) {
			t.Fatalf("%s: exit %d, want %d; stderr: %s", format, code, wantCode, stderr.String())
		}
		all.WriteString(stdout.String())
		all.WriteString(stderr.String())
	}
	return all.String()
}

func TestScanCreatesKeyFileLocally(t *testing.T) {
	home := t.TempDir()
	setKeyEnv(t, home, nil)
	out := scanAllFormats(t, keyTestRepo(t), exitcode.OK)
	info, err := os.Stat(fpkey.Path(home))
	if err != nil {
		t.Fatalf("local scan did not create %s: %v", fpkey.LogicalPath, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %o, want 600", info.Mode().Perm())
	}
	key, err := os.ReadFile(fpkey.Path(home))
	if err != nil {
		t.Fatal(err)
	}
	if k := strings.TrimSpace(string(key)); len(k) < fpkey.MinKeyBytes || strings.Contains(out, k) {
		t.Fatalf("key missing or printed (len %d)", len(k))
	}
	if strings.Contains(out, keyTestSecret) {
		t.Fatalf("output leaks the secret:\n%s", out)
	}
}

func TestScanNeverCreatesKeyFileInCI(t *testing.T) {
	for _, vars := range []map[string]string{{"CI": "true"}, {"GITHUB_ACTIONS": "true"}} {
		home := t.TempDir()
		setKeyEnv(t, home, vars)
		scanAllFormats(t, keyTestRepo(t), exitcode.OK)
		if _, err := os.Stat(filepath.Dir(fpkey.Path(home))); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%v: CI scan created %s: %v", vars, fpkey.LogicalPath, err)
		}
	}
}

func TestScanEnvKeyNeverPrinted(t *testing.T) {
	const key = "zsKey-env-fingerprint-key-0123456789"
	home := t.TempDir()
	setKeyEnv(t, home, map[string]string{"CI": "true", fpkey.EnvVar: key})
	out := scanAllFormats(t, keyTestRepo(t), exitcode.OK)
	if strings.Contains(out, key) || strings.Contains(out, keyTestSecret) {
		t.Fatalf("output leaks the key or the secret:\n%s", out)
	}
	if _, err := os.Stat(filepath.Dir(fpkey.Path(home))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("env key still created a key file: %v", err)
	}
}

func TestScanRejectsShortEnvKey(t *testing.T) {
	const key = "zsShortKey"
	setKeyEnv(t, t.TempDir(), map[string]string{fpkey.EnvVar: key})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", keyTestRepo(t)}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitcode.Config, stderr.String())
	}
	if !strings.Contains(stderr.String(), fpkey.EnvVar) || strings.Contains(stdout.String()+stderr.String(), key) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestScanFallsBackToS1WhenKeyFileUnavailable(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".tripcord"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setKeyEnv(t, home, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", keyTestRepo(t)}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "s1") || strings.Contains(stderr.String(), home) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
