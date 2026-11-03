package main

import (
	"fmt"
	"os"
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
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "tripcord-cmd-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, value := range map[string]string{"HOME": home, "USERPROFILE": home, "CI": "true"} {
		if err := os.Setenv(name, value); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	for _, name := range []string{fpkey.EnvVar, "GITHUB_ACTIONS"} {
		if err := os.Unsetenv(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	loadRules = cachedRules(loadRules)
	// No test reads the terminal or the go command's stdin: hook tests
	// set their own input.
	hookStdin = strings.NewReader("")
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}

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
