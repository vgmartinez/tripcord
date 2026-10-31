package rules

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/vgmartinez/tripcord/internal/exitcode"
)

const fixturePackDir = "testdata/packs/fixture"

func fixtureRule(id, pack string) string {
	return "id: " + id + "\npack: " + pack + `
title: "t"
severity: low
harness: [claude]
files: [".mcp.json"]
when: config.kind == "mcp-server"
fix: "f"
refs: [https://example.com/doc]
`
}

func mapPack(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func goodPackFiles() map[string]string {
	return map[string]string{
		ManifestFile:                         "pack: acme/demo@2026.11\n",
		RegistryFile:                         "ACME-CFG-001 active acme/demo@2026.11\nACME-CFG-002 retired acme/demo@2026.11\n",
		"ACME-CFG-001.yaml":                  fixtureRule("ACME-CFG-001", "acme/demo"),
		"README.md":                          "ignored",
		"ACME-CFG-001.test/positivos/x.json": "{}",
	}
}

func TestLoadFixturePack(t *testing.T) {
	pack, err := LoadDir(fixturePackDir, testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if pack.Ref.String() != "fixture/demo@2026.11" || len(pack.Rules) != 3 {
		t.Fatalf("pack = %+v", pack)
	}
	for _, r := range pack.Rules {
		if r.Pack != pack.Ref {
			t.Fatalf("%s pack = %s, want the manifest %s", r.ID, r.Pack, pack.Ref)
		}
	}
}

func TestLoadCore(t *testing.T) {
	pack, err := LoadCore(testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if pack.Ref.Name != "tripcord/core" {
		t.Fatalf("core pack is %s", pack.Ref)
	}
	if len(pack.Rules) != len(activeEntries(pack.Registry)) {
		t.Fatalf("%d rules, %d active registry entries", len(pack.Rules), len(activeEntries(pack.Registry)))
	}
}

// TestCoreMatchesDisk checks that the embedded pack is the rules/ tree.
func TestCoreMatchesDisk(t *testing.T) {
	env := testEnv(t)
	core, err := LoadCore(env)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := LoadDir("../../rules", env)
	if err != nil {
		t.Fatal(err)
	}
	if core.Ref != disk.Ref || len(core.Rules) != len(disk.Rules) {
		t.Fatalf("embedded %s/%d rules, disk %s/%d rules", core.Ref, len(core.Rules), disk.Ref, len(disk.Rules))
	}
}

func activeEntries(r *Registry) []RegistryEntry {
	var out []RegistryEntry
	for _, e := range r.Entries() {
		if e.Status == StatusActive {
			out = append(out, e)
		}
	}
	return out
}

func TestLoadPackGood(t *testing.T) {
	pack, err := LoadPack(mapPack(goodPackFiles()), "mem", testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Rules) != 1 || pack.Rules[0].ID != "ACME-CFG-001" {
		t.Fatalf("rules = %+v", pack.Rules)
	}
}

func TestLoadPackRejects(t *testing.T) {
	cases := map[string]struct {
		edit func(map[string]string)
		want string
	}{
		"no manifest":          {func(m map[string]string) { delete(m, ManifestFile) }, "pack.yaml"},
		"no registry":          {func(m map[string]string) { delete(m, RegistryFile) }, "REGISTRY"},
		"bad manifest":         {func(m map[string]string) { m[ManifestFile] = "pack: demo\n" }, "pack"},
		"manifest unknown key": {func(m map[string]string) { m[ManifestFile] = "pack: acme/demo@2026.11\nx: 1\n" }, "x"},
		"file name mismatch": {func(m map[string]string) {
			m["ACME-CFG-003.yaml"] = fixtureRule("ACME-CFG-001", "acme/demo")
			m[RegistryFile] += "ACME-CFG-003 active acme/demo@2026.11\n"
		}, "does not match the file name"},
		"pack mismatch": {func(m map[string]string) {
			m["ACME-CFG-001.yaml"] = fixtureRule("ACME-CFG-001", "other/demo")
		}, "does not match the manifest"},
		"version on the rule": {func(m map[string]string) {
			m["ACME-CFG-001.yaml"] = fixtureRule("ACME-CFG-001", "acme/demo@2026.11")
		}, "version lives in pack.yaml"},
		"not registered": {func(m map[string]string) {
			m["ACME-CFG-009.yaml"] = fixtureRule("ACME-CFG-009", "acme/demo")
		}, "not in REGISTRY"},
		"retired id reused": {func(m map[string]string) {
			m["ACME-CFG-002.yaml"] = fixtureRule("ACME-CFG-002", "acme/demo")
		}, "never reused"},
		"active without file": {func(m map[string]string) { delete(m, "ACME-CFG-001.yaml") }, "is active but"},
		"registry from other pack": {func(m map[string]string) {
			m[RegistryFile] += "ACME-CFG-005 retired other/pack@2026.11\n"
		}, "not pack acme/demo"},
		"yml extension": {func(m map[string]string) { m["ACME-CFG-004.yml"] = "x" }, ".yaml extension"},
		"bad file name": {func(m map[string]string) { m["notes.yaml"] = "x: 1" }, "file name must be"},
		"bad when": {func(m map[string]string) {
			m["ACME-CFG-001.yaml"] = strings.Replace(fixtureRule("ACME-CFG-001", "acme/demo"), `config.kind == "mcp-server"`, `config.kind`, 1)
		}, "want bool"},
		"missing refs": {func(m map[string]string) {
			m["ACME-CFG-001.yaml"] = strings.Replace(fixtureRule("ACME-CFG-001", "acme/demo"), "refs: [https://example.com/doc]\n", "", 1)
		}, "refs"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := goodPackFiles()
			c.edit(files)
			_, err := LoadPack(mapPack(files), "mem", testEnv(t))
			if err == nil {
				t.Fatal("loaded")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
			var re *Error
			if !errors.As(err, &re) || re.ExitCode() != exitcode.Config {
				t.Fatalf("error %v is not a config error", err)
			}
		})
	}
}

func TestLoadPackReportsAllProblems(t *testing.T) {
	files := goodPackFiles()
	files["ACME-CFG-002.yaml"] = fixtureRule("ACME-CFG-002", "acme/demo")
	files["ACME-CFG-009.yaml"] = fixtureRule("ACME-CFG-009", "acme/demo")
	_, err := LoadPack(mapPack(files), "mem", testEnv(t))
	if err == nil || !strings.Contains(err.Error(), "ACME-CFG-002") || !strings.Contains(err.Error(), "ACME-CFG-009") {
		t.Fatalf("err = %v", err)
	}
}

func TestCatalogRejectsDuplicates(t *testing.T) {
	env := testEnv(t)
	a, err := LoadPack(mapPack(goodPackFiles()), "a", env)
	if err != nil {
		t.Fatal(err)
	}
	other := map[string]string{
		ManifestFile:        "pack: other/demo@2026.11\n",
		RegistryFile:        "ACME-CFG-001 active other/demo@2026.11\n",
		"ACME-CFG-001.yaml": fixtureRule("ACME-CFG-001", "other/demo"),
	}
	b, err := LoadPack(mapPack(other), "b", env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCatalog(a, b); err == nil || !strings.Contains(err.Error(), "duplicate rule id ACME-CFG-001") {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewCatalog(a, a); err == nil || !strings.Contains(err.Error(), "already loaded") {
		t.Fatalf("err = %v", err)
	}
	fx, err := LoadDir(fixturePackDir, env)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCatalog(a, fx)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, r := range c.Rules() {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "ACME-CFG-001,TEST-CFG-001,TEST-CFG-002,TEST-CFG-004" {
		t.Fatalf("ids = %v", ids)
	}
	if _, ok := c.Rule("TEST-CFG-002"); !ok {
		t.Fatal("lookup failed")
	}
}
