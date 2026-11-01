package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/vgmartinez/tripcord/internal/fpkey"
)

// TestMain points HOME at a temporary directory, so no test reads or
// creates the developer's ~/.tripcord/fingerprint.key, and pins the
// fingerprint mode to s1 (CI set, no key) unless a test opts into k1.
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
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}
