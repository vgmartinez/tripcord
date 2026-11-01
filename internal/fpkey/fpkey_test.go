package fpkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const secret = "fpkey-test-secret-value-0123456789"

func env(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

func TestNewTrimsAndRejectsShortKeys(t *testing.T) {
	t.Parallel()
	a, err := New("  " + secret + "\n")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	if a.Sum("d", []string{"x"}, 16) != b.Sum("d", []string{"x"}, 16) {
		t.Fatal("surrounding space changed the key")
	}
	_, err = New("short-key-123")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if strings.Contains(err.Error(), "short-key-123") {
		t.Fatalf("error names the key: %v", err)
	}
}

func TestSum(t *testing.T) {
	t.Parallel()
	k, _ := New(secret)
	other, _ := New(secret + "-other")
	first := k.Sum("d", []string{"a", "b"}, 16)
	for range 200 {
		if got := k.Sum("d", []string{"a", "b"}, 16); got != first {
			t.Fatalf("Sum not deterministic: %s then %s", first, got)
		}
	}
	if len(first) != 16 || strings.Trim(first, "0123456789abcdef") != "" {
		t.Fatalf("Sum = %q, want 16 lowercase hex", first)
	}
	for name, got := range map[string]string{
		"other key":      other.Sum("d", []string{"a", "b"}, 16),
		"other domain":   k.Sum("e", []string{"a", "b"}, 16),
		"other boundary": k.Sum("d", []string{"a\x00b"}, 16),
		"other parts":    k.Sum("d", []string{"a", "c"}, 16),
	} {
		if got == first {
			t.Errorf("%s: same sum %s", name, got)
		}
	}
}

func TestKeyNeverPrints(t *testing.T) {
	t.Parallel()
	k, _ := New(secret)
	raw, err := json.Marshal(struct{ K *Key }{k})
	if err != nil {
		t.Fatal(err)
	}
	outputs := []string{
		fmt.Sprintf("%v %+v %#v %s %q %x %X %d", k, k, k, k, k, k, k, k),
		fmt.Sprintf("%v %+v", *k, struct{ K *Key }{k}),
		k.String(), k.GoString(), string(raw),
	}
	for _, out := range outputs {
		if strings.Contains(out, secret) || strings.Contains(out, fmt.Sprintf("%x", secret)) {
			t.Fatalf("key printed: %s", out)
		}
	}
	for _, out := range []string{fmt.Sprintf("%v", k), fmt.Sprintf("%d", *k), fmt.Sprintf("%#v", *k)} {
		if out != placeholder {
			t.Fatalf("formatted key = %q, want %q", out, placeholder)
		}
	}
}

func TestLoadPrefersEnv(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	k, src, err := Load(Options{Home: home, Getenv: env(map[string]string{EnvVar: secret})})
	if err != nil || src != SourceEnv || !k.Present() {
		t.Fatalf("Load = %v, %v, %v", k, src, err)
	}
	if _, err := os.Stat(Path(home)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("env key still created a key file: %v", err)
	}
	fromFile := writeKey(t, t.TempDir(), secret)
	if k.Sum("d", []string{"x"}, 16) != fromFile.Sum("d", []string{"x"}, 16) {
		t.Fatal("the same text in the env var and the key file is a different key")
	}
}

func TestLoadRejectsShortEnvKey(t *testing.T) {
	t.Parallel()
	_, _, err := Load(Options{Home: t.TempDir(), Getenv: env(map[string]string{EnvVar: "tooshort"})})
	if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "tooshort") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadCreatesKeyFileLocally(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	k, src, err := Load(Options{Home: home, Getenv: env(nil)})
	if err != nil || src != SourceCreated || !k.Present() {
		t.Fatalf("Load = %v, %v, %v", k, src, err)
	}
	info, err := os.Stat(Path(home))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Stat(filepath.Dir(Path(home)))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("key file mode %o, want 600", perm)
		}
		if perm := dir.Mode().Perm(); perm != 0o700 {
			t.Fatalf("key directory mode %o, want 700", perm)
		}
	}
	again, src, err := Load(Options{Home: home, Getenv: env(nil)})
	if err != nil || src != SourceFile {
		t.Fatalf("second Load = %v, %v", src, err)
	}
	if again.Sum("d", []string{"x"}, 16) != k.Sum("d", []string{"x"}, 16) {
		t.Fatal("second Load read a different key")
	}
}

func TestLoadNeverCreatesInCI(t *testing.T) {
	t.Parallel()
	for _, vars := range []map[string]string{
		{"CI": "true"}, {"CI": "1"}, {"GITHUB_ACTIONS": "true"}, {"CI": "woodpecker"},
	} {
		home := t.TempDir()
		k, src, err := Load(Options{Home: home, Getenv: env(vars)})
		if err != nil || src != SourceNone || k.Present() {
			t.Fatalf("%v: Load = %v, %v, %v", vars, k, src, err)
		}
		if _, err := os.Stat(filepath.Dir(Path(home))); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%v: CI created %s: %v", vars, LogicalPath, err)
		}
	}
	for _, vars := range []map[string]string{{"CI": "false"}, {"CI": "0"}, {"GITHUB_ACTIONS": ""}} {
		if IsCI(env(vars)) {
			t.Fatalf("%v counts as CI", vars)
		}
	}
}

func TestLoadReadsExistingFileInCI(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	want := writeKey(t, home, secret)
	k, src, err := Load(Options{Home: home, Getenv: env(map[string]string{"CI": "true"})})
	if err != nil || src != SourceFile || k.Sum("d", nil, 16) != want.Sum("d", nil, 16) {
		t.Fatalf("Load = %v, %v", src, err)
	}
}

func TestLoadConcurrentCreateAgrees(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	sums := make([]string, 16)
	var wg sync.WaitGroup
	for i := range sums {
		wg.Go(func() {
			k, _, err := Load(Options{Home: home, Getenv: env(nil)})
			if err != nil {
				t.Error(err)
				return
			}
			sums[i] = k.Sum("d", nil, 16)
		})
	}
	wg.Wait()
	for _, s := range sums {
		if s != sums[0] {
			t.Fatalf("concurrent Load disagrees: %v", sums)
		}
	}
}

func TestLoadUnavailable(t *testing.T) {
	t.Parallel()
	// A failing random source with no key file anywhere is a genuinely
	// missing key source, not broken existing material: s1 fallback is
	// still safe (ErrUnavailable), not a hard failure.
	_, src, err := Load(Options{Home: t.TempDir(), Getenv: env(nil), Rand: failingReader{}})
	if !errors.Is(err, ErrUnavailable) || src != SourceNone {
		t.Fatalf("Load with a failing random source = %v, %v", src, err)
	}
	if errors.Is(err, ErrKeyUnusable) {
		t.Fatalf("a missing key source must not be reported as broken material: %v", err)
	}
}

// TestLoadFailsClosedOnBrokenExistingMaterial covers every "key material
// exists but is broken" case from the researcher's review: each must
// wrap ErrKeyUnusable (never the soft ErrUnavailable) and must never
// name the home directory, so the scan can fail closed with an
// actionable, non-leaking message.
func TestLoadFailsClosedOnBrokenExistingMaterial(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]func(t *testing.T, home string){
		"home dir is a regular file": func(t *testing.T, home string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(home, ".tripcord"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"key path is a directory": func(t *testing.T, home string) {
			t.Helper()
			if err := os.MkdirAll(Path(home), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"key file is a symlink": func(t *testing.T, home string) {
			t.Helper()
			target := writeOutsideKey(t, "elsewhere-key-0123456789abcdef")
			if err := os.MkdirAll(filepath.Dir(Path(home)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, Path(home)); err != nil {
				t.Fatal(err)
			}
		},
		"key file is a broken symlink": func(t *testing.T, home string) {
			t.Helper()
			if err := os.MkdirAll(filepath.Dir(Path(home)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "does-not-exist"), Path(home)); err != nil {
				t.Fatal(err)
			}
		},
		"key dir is a symlink": func(t *testing.T, home string) {
			t.Helper()
			target := t.TempDir()
			if err := os.Symlink(target, filepath.Dir(Path(home))); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			setup(t, home)
			_, src, err := Load(Options{Home: home, Getenv: env(nil)})
			if !errors.Is(err, ErrKeyUnusable) || src != SourceNone {
				t.Fatalf("Load = %v, %v, want ErrKeyUnusable", src, err)
			}
			if errors.Is(err, ErrUnavailable) {
				t.Fatalf("broken material must not report the soft ErrUnavailable: %v", err)
			}
			if strings.Contains(err.Error(), home) {
				t.Fatalf("error names the home directory: %v", err)
			}
		})
	}
}

func TestLoadFailsClosedOnLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows; see fpkey_windows.go")
	}
	t.Parallel()
	t.Run("key file readable by group", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		writeRaw(t, home, secret+"\n")
		if err := os.Chmod(Path(home), 0o640); err != nil {
			t.Fatal(err)
		}
		_, src, err := Load(Options{Home: home, Getenv: env(nil)})
		if !errors.Is(err, ErrKeyUnusable) || src != SourceNone {
			t.Fatalf("Load = %v, %v, want ErrKeyUnusable", src, err)
		}
	})
	t.Run("key dir writable by others", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		writeRaw(t, home, secret+"\n")
		if err := os.Chmod(filepath.Dir(Path(home)), 0o707); err != nil {
			t.Fatal(err)
		}
		_, src, err := Load(Options{Home: home, Getenv: env(nil)})
		if !errors.Is(err, ErrKeyUnusable) || src != SourceNone {
			t.Fatalf("Load = %v, %v, want ErrKeyUnusable", src, err)
		}
	})
}

func TestLoadRejectsBadKeyFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeRaw(t, home, "short\n")
	_, _, err := Load(Options{Home: home, Getenv: env(nil)})
	if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "short\n") {
		t.Fatalf("err = %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func writeRaw(t *testing.T, home, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(Path(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(home), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeOutsideKey writes a key file in its own directory, outside any
// home used by the test, and returns its path. It is used as a symlink
// target so the symlink itself, not the target's permissions, is what a
// test is checking.
func writeOutsideKey(t *testing.T, text string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fingerprint.key")
	if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeKey(t *testing.T, home, text string) *Key {
	t.Helper()
	writeRaw(t, home, text+"\n")
	k, src, err := Load(Options{Home: home, Getenv: env(nil)})
	if err != nil || src != SourceFile {
		t.Fatalf("Load = %v, %v", src, err)
	}
	return k
}
