package fpkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// secret is a valid key for these tests: 64 hex characters, matching
// both New's minimum length and a generated key file's exact length, so
// it can also be written as a key file's content.
const secret = "0ddba11a0ddba11a0ddba11a0ddba11a0ddba11a0ddba11a0ddba11a0ddba11a"

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

// TestNewHexCaseIsTheSameKey is the researcher review's normalization:
// the HMAC key is the decoded bytes, so uppercase and lowercase
// spellings of one hex string produce the same discriminator and
// therefore the same fingerprint.
func TestNewHexCaseIsTheSameKey(t *testing.T) {
	t.Parallel()
	lower, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	upper, err := New(strings.ToUpper(secret))
	if err != nil {
		t.Fatal(err)
	}
	mixedText := strings.ToUpper(secret[:16]) + secret[16:]
	mixed, err := New(mixedText)
	if err != nil {
		t.Fatal(err)
	}
	want := lower.Sum("tripcord.sig.k1", []string{"zsM01q"}, 16)
	for name, k := range map[string]*Key{"upper": upper, "mixed": mixed} {
		if got := k.Sum("tripcord.sig.k1", []string{"zsM01q"}, 16); got != want {
			t.Fatalf("%s Sum = %s, want %s (same fingerprint discriminator)", name, got, want)
		}
	}
	if lower.Sum("tripcord.sig.k1", []string{"other"}, 16) == want {
		t.Fatal("a different secret kept the discriminator")
	}
}

func TestNewRejectsOddLengthHex(t *testing.T) {
	t.Parallel()
	odd := secret + "a"
	_, err := New(odd)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "odd") || strings.Contains(err.Error(), odd) {
		t.Fatalf("err = %v", err)
	}
}

func TestSum(t *testing.T) {
	t.Parallel()
	k, _ := New(secret)
	other, err := New("f00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabe")
	if err != nil {
		t.Fatal(err)
	}
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

// TestLoadNeverCreatesInCI also covers the researcher review's request
// that CI print an actionable note: Load now reports ErrCIFallback
// (which still satisfies errors.Is(err, ErrUnavailable), so an existing
// caller checking only the general case keeps working) instead of a nil
// error, so a caller such as cmd/tripcord can surface the reason on
// stderr instead of silently using s1 with no explanation at all.
func TestLoadNeverCreatesInCI(t *testing.T) {
	t.Parallel()
	for _, vars := range []map[string]string{
		{"CI": "true"}, {"CI": "1"}, {"GITHUB_ACTIONS": "true"}, {"CI": "woodpecker"},
	} {
		home := t.TempDir()
		k, src, err := Load(Options{Home: home, Getenv: env(vars)})
		if !errors.Is(err, ErrCIFallback) || !errors.Is(err, ErrUnavailable) || src != SourceNone || k.Present() {
			t.Fatalf("%v: Load = %v, %v, %v, want ErrCIFallback", vars, k, src, err)
		}
		if err.Error() != ciFallbackNote {
			t.Fatalf("%v: CI note = %q, want %q", vars, err.Error(), ciFallbackNote)
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

// TestLoadRemovesStaleTempFiles covers the researcher review's fix 5: a
// process killed between createKeyFile creating its temporary file and
// its own deferred cleanup removing it leaves that file behind forever
// otherwise. Load sweeps one old enough to be orphaned on every call
// that finds the key directory, not only when it is about to create a
// new key itself.
func TestLoadRemovesStaleTempFiles(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeKey(t, home, secret)
	dir := filepath.Dir(Path(home))
	stale := filepath.Join(dir, ".fingerprint.key.stale0123.tmp")
	fresh := filepath.Join(dir, ".fingerprint.key.fresh4567.tmp")
	nearFuture := filepath.Join(dir, ".fingerprint.key.near-future.tmp")
	farFuture := filepath.Join(dir, ".fingerprint.key.far-future.tmp")
	// A directory whose name matches the temp pattern must be left
	// alone, even when it is old enough to look stale: only a regular
	// file is a leftover from createKeyFile.
	asDir := filepath.Join(dir, ".fingerprint.key.notfile.tmp")
	for _, path := range []string{stale, fresh, nearFuture, farFuture} {
		if err := os.WriteFile(path, []byte("leftover"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-staleTempFileAge - time.Minute)
	nearAhead := time.Now().Add(3 * time.Second)
	farAhead := time.Now().Add(staleTempFileAge + time.Minute)
	for _, path := range []string{stale, asDir} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{nearFuture, farFuture} {
		mtime := farAhead
		if path == nearFuture {
			mtime = nearAhead
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := Load(Options{Home: home, Getenv: env(nil)}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stale, farFuture} {
		if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stale temp file %s was not removed: %v", filepath.Base(path), err)
		}
	}
	for _, path := range []string{fresh, nearFuture, asDir} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was removed: %v", filepath.Base(path), err)
		}
	}
}

// TestLoadStaleSweepStaysInsideHome is the researcher review's bug: the
// sweep used filepath.Glob on the whole path, so a home directory whose
// name contained a glob metacharacter deleted a sibling home's stale
// temp file ("h*" matched "hvictim") or, with an unmatched "[", matched
// nothing and left the sweep off.
func TestLoadStaleSweepStaysInsideHome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, homeName, siblingName string
	}{
		{"star", "h*", "hvictim"},
		{"question", "h?", "hx"},
		{"bracket", "h[", "ha"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			home := filepath.Join(parent, tc.homeName)
			sibling := filepath.Join(parent, tc.siblingName)
			if err := os.Mkdir(home, 0o700); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("directory name %q: %v", tc.homeName, err)
				}
				t.Fatal(err)
			}
			writeKey(t, home, secret)
			siblingTmp := filepath.Join(sibling, ".tripcord", ".fingerprint.key.stale0123.tmp")
			if err := os.MkdirAll(filepath.Dir(siblingTmp), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(siblingTmp, []byte("sibling"), 0o600); err != nil {
				t.Fatal(err)
			}
			ownTmp := filepath.Join(filepath.Dir(Path(home)), ".fingerprint.key.stale0123.tmp")
			if err := os.WriteFile(ownTmp, []byte("own"), 0o600); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-staleTempFileAge - time.Minute)
			for _, path := range []string{siblingTmp, ownTmp} {
				if err := os.Chtimes(path, old, old); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := Load(Options{Home: home, Getenv: env(nil)}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(ownTmp); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("own stale temp file was not removed: %v", err)
			}
			got, err := os.ReadFile(siblingTmp)
			if err != nil || string(got) != "sibling" {
				t.Fatalf("sibling temp file = %q, %v; a home named %q must not reach it", got, err, tc.homeName)
			}
		})
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

// TestLoadNamesSudoRootOwnershipFix is the researcher review's fix 4: a
// one-off `sudo tripcord scan` with HOME preserved (macOS's default,
// and some Linux configurations) leaves ~/.tripcord owned by root, so
// every later unprivileged run fails closed. The message must name the
// cause and the fix, not just "not owned by the current user".
func TestLoadNamesSudoRootOwnershipFix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ownership is not checked on Windows; see fpkey_windows.go")
	}
	if os.Getuid() == 0 {
		t.Skip("already root; cannot exercise a uid mismatch")
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		t.Skip("sudo not available")
	}
	if exec.Command(sudo, "-n", "true").Run() != nil {
		t.Skip("sudo requires a password in this environment")
	}
	home := t.TempDir()
	writeRaw(t, home, secret+"\n")
	dir := filepath.Dir(Path(home))
	if err := exec.Command(sudo, "-n", "chown", "-R", "0:0", dir).Run(); err != nil {
		t.Fatalf("sudo chown to root: %v", err)
	}
	t.Cleanup(func() {
		owner := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
		_ = exec.Command(sudo, "-n", "chown", "-R", owner, dir).Run()
	})
	_, src, err := Load(Options{Home: home, Getenv: env(nil)})
	if !errors.Is(err, ErrKeyUnusable) || src != SourceNone {
		t.Fatalf("Load = %v, %v, want ErrKeyUnusable", src, err)
	}
	if !strings.Contains(err.Error(), "uid 0") || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("error does not name the cause and the fix: %v", err)
	}
	if strings.Contains(err.Error(), home) {
		t.Fatalf("error names the home directory: %v", err)
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

// TestLoadRejectsBadKeyFile is the researcher review's bug 2: New
// previously only checked length, so corrupted key file content could
// silently become a "valid" key with a different fingerprint than the
// one actually on disk, instead of failing the scan closed. A key file
// must be exactly generatedKeyBytes*2 hex characters (what createKeyFile
// always writes), optionally followed by one newline; anything else
// wraps ErrInvalid.
func TestLoadRejectsBadKeyFile(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		"too short":                   "short\n",
		"truncated hex (half length)": secret[:len(secret)/2] + "\n",
		// 64 bytes of non-hex "binary" content: the same length a
		// genuine key file has, but not decodable as hex. Printable
		// so the test and its failure message stay readable; actual
		// corruption need not be printable to trip the same check.
		"not hex, same length as a real key":                      strings.Repeat("g", generatedKeyBytes*2) + "\n",
		"no trailing newline, otherwise valid but one char short": secret[:len(secret)-1],
		"trailing garbage after a valid key":                      secret + "x\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			writeRaw(t, home, content)
			_, src, err := Load(Options{Home: home, Getenv: env(nil)})
			if !errors.Is(err, ErrInvalid) || src != SourceNone {
				t.Fatalf("Load = %v, %v, want ErrInvalid", src, err)
			}
			if strings.Contains(err.Error(), strings.TrimSpace(content)) {
				t.Fatalf("error names the key content: %v", err)
			}
		})
	}
	// The one exact match must still work: this is the control case
	// proving the table above fails for the right reason, not because
	// every key is rejected.
	t.Run("exactly valid is accepted", func(t *testing.T) {
		t.Parallel()
		home := t.TempDir()
		writeRaw(t, home, secret+"\n")
		if _, _, err := Load(Options{Home: home, Getenv: env(nil)}); err != nil {
			t.Fatalf("Load = %v", err)
		}
	})
}

// TestLoadRejectsBadEnvKey is TestLoadRejectsBadKeyFile's env var
// counterpart: TRIPCORD_FINGERPRINT_KEY must also be a hex string, at
// least minKeyHexChars long, though (unlike a key file) it is not
// required to be exactly generatedKeyBytes*2 characters, since a human
// may reasonably set a longer one.
func TestLoadRejectsBadEnvKey(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]string{
		"too short":         "tooshort",
		"not hex":           strings.Repeat("g", minKeyHexChars),
		"not hex, one char": secret[:len(secret)-1] + "g",
		// Long enough to pass the minimum, even in its hex digits, but
		// not decodable: an odd length must be exit 3, not a key.
		"odd length": secret + "a",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, src, err := Load(Options{Home: t.TempDir(), Getenv: env(map[string]string{EnvVar: value})})
			if !errors.Is(err, ErrInvalid) || src != SourceNone {
				t.Fatalf("Load = %v, %v, want ErrInvalid", src, err)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatalf("error names the key: %v", err)
			}
			if name == "not hex" && !strings.Contains(err.Error(), "("+hexAlphabet+")") {
				t.Fatalf("charset in the error = %q, want (%s)", err.Error(), hexAlphabet)
			}
			if name == "odd length" && !strings.Contains(err.Error(), "odd") {
				t.Fatalf("odd-length error = %q", err.Error())
			}
		})
	}
	// A longer-than-a-file hex key is fine for the env var: there is no
	// exact-length requirement there.
	longer := secret + secret
	if _, src, err := Load(Options{Home: t.TempDir(), Getenv: env(map[string]string{EnvVar: longer})}); err != nil || src != SourceEnv {
		t.Fatalf("Load = %v, %v, want a valid longer hex key accepted", src, err)
	}
	upper, src, err := Load(Options{Home: t.TempDir(), Getenv: env(map[string]string{EnvVar: strings.ToUpper(secret)})})
	if err != nil || src != SourceEnv {
		t.Fatalf("Load = %v, %v, want uppercase hex accepted", src, err)
	}
	lower, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	if upper.Sum("d", []string{"x"}, 16) != lower.Sum("d", []string{"x"}, 16) {
		t.Fatal("uppercase env key is a different key than the same hex in lowercase")
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
