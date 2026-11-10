package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// TestMain points HOME at a temporary directory, so no test reads or
// creates the developer's ~/.tripcord/fingerprint.key, and pins the
// fingerprint mode to s1 (CI set, no key) unless a test opts into k1.
// It also compiles the core pack once per set of limits instead of once
// per scan (see cachedRules).
//
// With TRIPCORD_TEST_AS_CLI=1 the test binary is tripcord itself, so the
// end-to-end tests can pin it in a bootstrap cache without building one.
func TestMain(m *testing.M) {
	// The test binary is tripcord itself on this path. main calls
	// os.Exit, so the temporary home below is never created.
	if os.Getenv(testAsCLIEnv) == "1" {
		main()
	}
	home, err := os.MkdirTemp("", "tripcord-cmd-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, value := range map[string]string{"HOME": home, "USERPROFILE": home, "CI": "true"} {
		if err := os.Setenv(name, value); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(removeTempHome(home, 1))
		}
	}
	for _, name := range []string{fpkey.EnvVar, "GITHUB_ACTIONS"} {
		if err := os.Unsetenv(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(removeTempHome(home, 1))
		}
	}
	loadRules = cachedRules(loadRules)
	// No test reads the terminal or the go command's stdin: hook tests
	// set their own input.
	hookStdin = strings.NewReader("")
	os.Exit(removeTempHome(home, m.Run()))
}

// removeTempHome deletes the temporary HOME TestMain created. os.Exit
// skips defers, so every exit after the directory exists goes through
// here. A cleanup failure is printed and forces a non-zero status when
// the tests themselves passed.
func removeTempHome(home string, code int) int {
	if err := removeWritableTree(home); err != nil {
		fmt.Fprintln(os.Stderr, "remove temp home:", err)
		if code == 0 {
			return 1
		}
	}
	return code
}

// removeWritableTree removes path even when it holds a module cache:
// those directories are mode 0555, and RemoveAll cannot unlink a file
// in a directory the process cannot write.
func removeWritableTree(path string) error {
	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		_ = os.Chmod(p, 0o700)
		return nil
	})
	return os.RemoveAll(path)
}

func TestRemoveTempHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "fingerprint.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := removeTempHome(home, 0); got != 0 {
		t.Fatalf("code = %d, want 0", got)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("temp home = %v, want it removed", err)
	}
	if got := removeTempHome(home, 4); got != 4 {
		t.Fatalf("code = %d, want 4", got)
	}
}

func TestRemoveTempHomeReadOnlyCache(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	dir := filepath.Join(home, "go", "pkg", "mod")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "impl.go"), []byte("package p\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if got := removeTempHome(home, 0); got != 0 {
		t.Fatalf("code = %d, want 0", got)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("temp home = %v, want it removed", err)
	}
}

const testAsCLIEnv = "TRIPCORD_TEST_AS_CLI"

type compiledRules struct {
	env     *rules.Env
	catalog *rules.Catalog
	err     error
}

// cachedRules memoizes load by limits. Compiled programs carry their
// cost limit, so a test that lowers scanLimits gets its own pack. The
// pack is compiled from the embedded rules, which cannot change while
// the test binary runs.
func cachedRules(load func(rules.Limits) (*rules.Env, *rules.Catalog, error)) func(rules.Limits) (*rules.Env, *rules.Catalog, error) {
	var mu sync.Mutex
	cache := map[rules.Limits]compiledRules{}
	return func(limits rules.Limits) (*rules.Env, *rules.Catalog, error) {
		mu.Lock()
		defer mu.Unlock()
		c, ok := cache[limits]
		if !ok {
			c.env, c.catalog, c.err = load(limits)
			cache[limits] = c
		}
		return c.env, c.catalog, c.err
	}
}
