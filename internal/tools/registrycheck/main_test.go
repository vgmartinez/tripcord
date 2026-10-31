package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	file := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := file("base", "TC-CFG-001 active tripcord/core@2026.11\n")
	appended := file("appended", "TC-CFG-001 active tripcord/core@2026.11\nTC-CFG-002 active tripcord/core@2026.11\n")
	removed := file("removed", "TC-CFG-002 active tripcord/core@2026.11\n")
	missing := filepath.Join(dir, "missing")

	for name, c := range map[string]struct {
		args []string
		want int
	}{
		"append":       {[]string{base, appended}, 0},
		"remove":       {[]string{base, removed}, 1},
		"no base file": {[]string{missing, base}, 0},
		"no head file": {[]string{base, missing}, 1},
		"usage":        {[]string{base}, 2},
	} {
		var stderr bytes.Buffer
		if got := run(c.args, &stderr); got != c.want {
			t.Errorf("%s: exit %d, want %d (%s)", name, got, c.want, stderr.String())
		}
	}
}
