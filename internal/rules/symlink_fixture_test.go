package rules

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The TC-CFG-006 positives that resolve a hook through a symlink outside
// the repository used to be committed links to /tmp and /etc. Extracting
// that tree follows the link. The same trees are built here, in a temp
// repository, so the severities stay covered without a link in git.
func TestTCFG006OutsideSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixtures run on Linux and macOS")
	}
	env := testEnv(t)
	pack, err := LoadDir(filepath.Join("..", "..", "rules"), env)
	if err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for i := range pack.Rules {
		if pack.Rules[i].ID == "TC-CFG-006" {
			rule = pack.Rules[i]
		}
	}
	if rule == nil {
		t.Fatal("TC-CFG-006 is not in the core pack")
	}
	engine := NewEngine(env, []*Rule{rule})
	outside, err := os.MkdirTemp("/tmp", "tripcord-tc-cfg-006-")
	if err != nil {
		t.Skipf("temporary target under /tmp unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(outside); err != nil {
			t.Errorf("remove temporary target: %v", err)
		}
	})
	if err := os.WriteFile(filepath.Join(outside, "hook.sh"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		command  string
		link     string
		target   string
		severity string
	}{
		{
			name:     "directory symlink into a temp directory",
			command:  "./scripts",
			link:     "scripts",
			target:   outside,
			severity: "high",
		},
		{
			name:     "script symlink to a temp directory",
			command:  "./scripts/x.sh",
			link:     "scripts/x.sh",
			target:   "/tmp",
			severity: "high",
		},
		{
			name:     "script symlink into a temp directory",
			command:  "./scripts/x.sh",
			link:     "scripts/x.sh",
			target:   filepath.Join(outside, "hook.sh"),
			severity: "high",
		},
		{
			name:     "directory symlink to /etc",
			command:  "./scripts/passwd",
			link:     "scripts",
			target:   "/etc",
			severity: "medium",
		},
		{
			name:     "script symlink to /etc/passwd",
			command:  "./scripts/x.sh",
			link:     "scripts/x.sh",
			target:   "/etc/passwd",
			severity: "medium",
		},
		{
			name:     "broken symlink",
			command:  "./scripts/x.sh",
			link:     "scripts/x.sh",
			target:   filepath.Join(outside, "missing", "x.sh"),
			severity: "medium",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			settings := filepath.Join(root, ".claude", "settings.json")
			writeFile(t, settings, `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "`+tc.command+`"}
        ]
      }
    ]
  }
}
`)
			dest := filepath.Join(root, tc.link)
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(tc.target, dest); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			items, err := adapterDiscover(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkFixture(context.Background(), engine, rule, tc.name, items, true, outcome{tc.severity}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
