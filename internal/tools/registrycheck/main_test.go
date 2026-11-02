package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestAdvisoryEvolution(t *testing.T) {
	dir := t.TempDir()
	oldDir := filepath.Join(dir, "old")
	newDir := filepath.Join(dir, "new")
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(dir, name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	reg := "TC-CFG-001 active tripcord/core@2026.11\n"
	one := `{"format":1,"advisories":[{"id":"TCA-2026-0001","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"npm","name":"left-pad","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`
	two := `{"format":1,"advisories":[{"id":"TCA-2026-0002","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"npm","name":"left-pad","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`
	both := `{"format":1,"advisories":[{"id":"TCA-2026-0001","aliases":[],"summary":"x","severity":"high","affected":[{"ecosystem":"npm","name":"left-pad","ranges":[{"fixed":"1.0.0"}]}],"refs":["https://example.com/a"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"},{"id":"TCA-2026-0002","aliases":[],"summary":"y","severity":"low","affected":[{"ecosystem":"npm","name":"other","ranges":[{"fixed":"2.0.0"}]}],"refs":["https://example.com/b"],"added":"tripcord/core@2026.11","reviewed":"2026-11-02"}]}`
	oldReg := write(oldDir, "REGISTRY", reg)
	write(oldDir, "ADVISORIES.json", one)
	newReg := write(newDir, "REGISTRY", reg)
	write(newDir, "ADVISORIES.json", two)
	var stderr bytes.Buffer
	if got := run([]string{oldReg, newReg}, &stderr); got != 1 {
		t.Fatalf("renumber exit %d (%s)", got, stderr.String())
	}
	write(newDir, "ADVISORIES.json", both)
	stderr.Reset()
	if got := run([]string{oldReg, newReg}, &stderr); got != 0 {
		t.Fatalf("append exit %d (%s)", got, stderr.String())
	}
	write(newDir, "ADVISORIES.json", "{")
	stderr.Reset()
	if got := run([]string{oldReg, newReg}, &stderr); got != 1 {
		t.Fatalf("schema exit %d (%s)", got, stderr.String())
	}
	if err := os.Remove(filepath.Join(newDir, "ADVISORIES.json")); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if got := run([]string{oldReg, newReg}, &stderr); got != 1 || !strings.Contains(stderr.String(), "ADVISORIES.json removed") {
		t.Fatalf("removed exit %d (%s)", got, stderr.String())
	}
	if err := os.Remove(filepath.Join(oldDir, "ADVISORIES.json")); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if got := run([]string{oldReg, newReg}, &stderr); got != 0 {
		t.Fatalf("absent in base and head exit %d (%s)", got, stderr.String())
	}
}
