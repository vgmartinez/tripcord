package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgmartinez/tripcord/internal/embedded"
)

// skewUnknownPin is a well-formed tripcord-pr.yml pin no Tripcord wrote.
const skewUnknownPin = "1234567890abcdef1234567890abcdef12345678"

// The version-skew positives: each holds the one state its severity_when
// clause decides, so TestSeverityClausesAreCovered pins that clause.
// tracked writes each as config-item JSON rather than a raw archive (the
// trees have no settings.local.json or policy.local.yaml, so tracking
// changes nothing): an archive would carry bootstrap.sh, whose shebang
// needs an allowlist.tsv entry, and that list only shrinks.
func init() {
	for name, fx := range map[string]cfg016Fixture{
		// An embed.json version above every scanner does not buy an
		// exception for a loosened hook: H2 holds in any scan.
		"embed-inflated-version-hook-loosened": {kind: "positivos", tracked: true,
			args: []string{"init", "--embed", "--harness", "claude", "--version", "99.0.0", "--sha256", "linux-x64=" + testSHA256},
			edit: edits(replaceInFile(embedded.ClaudeSettingsPath, `"onFailure": "block"`, `"onFailure": "continue"`), rerecord)},
		"embed-pin-unknown": {kind: "positivos", tracked: true, args: embedArgs("--harness", "claude"),
			edit: edits(repinWorkflowTo(skewUnknownPin), rerecord)},
		"embed-pin-malformed": {kind: "positivos", tracked: true, args: embedArgs("--harness", "claude"),
			edit: edits(replaceInFile(embedded.WorkflowPath, "tripcord-pr.yml@"+embedded.WorkflowPin, "tripcord-pr.yml@main"), rerecord)},
		// The SessionStart entry init wrote before CLAUDE_PROJECT_DIR got
		// its :-. fallback (c8e5bdd), under the same WorkflowPin.
		"embed-render-outdated": {kind: "positivos", tracked: true, args: embedArgs("--harness", "claude"),
			edit: edits(replaceInFile(embedded.ClaudeSettingsPath, `${CLAUDE_PROJECT_DIR:-.}/.tripcord/bootstrap.sh\" session-start`, `${CLAUDE_PROJECT_DIR}/.tripcord/bootstrap.sh\" session-start`), rerecord)},
		"embed-manifest-future-schema": {kind: "positivos", tracked: true, args: embedArgs("--harness", "claude"),
			edit: replaceInFile(embedded.ManifestPath, `"tripcord.embed/v1"`, `"tripcord.embed/v2"`)},
	} {
		if _, dup := cfg016Fixtures[name]; dup {
			panic("cfg016Fixtures: " + name + " twice")
		}
		cfg016Fixtures[name] = fx
	}
}

func repinWorkflowTo(pin string) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(embedded.WorkflowPath))
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := strings.ReplaceAll(string(raw), embedded.WorkflowPin, pin)
		s = strings.ReplaceAll(s, "main@"+embedded.WorkflowPin[:7], "main@"+pin[:7])
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

type skewManifest struct {
	Files []struct {
		Path   string `json:"path"`
		Step   string `json:"step"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
	Hooks []struct {
		Path   string `json:"path"`
		Event  string `json:"event"`
		SHA256 string `json:"sha256"`
	} `json:"hooks"`
}

// rerecord rewrites the digests embed.json records for bootstrap.sh,
// tripcord.yml, and each hook entry to what dir now holds, the way the
// init that wrote it would have.
func rerecord(t *testing.T, dir string) {
	t.Helper()
	read := func(rel string) []byte {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	manifest := string(read(embedded.ManifestPath))
	var m skewManifest
	if err := json.Unmarshal([]byte(manifest), &m); err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		if f.Step == "" {
			manifest = strings.ReplaceAll(manifest, f.SHA256, sha256Hex(read(f.Path)))
		}
	}
	for _, h := range m.Hooks {
		var doc struct {
			Hooks map[string][]json.RawMessage `json:"hooks"`
		}
		if err := json.Unmarshal(read(h.Path), &doc); err != nil {
			t.Fatal(err)
		}
		for _, entry := range doc.Hooks[h.Event] {
			if strings.Contains(string(entry), embedded.BootstrapPath) {
				d, err := embedded.HookEntryDigest(h.Event, entry)
				if err != nil {
					t.Fatal(err)
				}
				manifest = strings.ReplaceAll(manifest, h.SHA256, d)
			}
		}
	}
	writeTestFile(t, dir, embedded.ManifestPath, manifest)
}
