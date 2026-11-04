package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanStagedManifestOnlyActivatesConventionFiles reproduces N2: a
// Claude plugin's hooks.json, skill, agent, or command file is read "by
// convention" once its plugin root is known from a .claude-plugin
// manifest. Committing the convention file alone does nothing (no
// manifest, no known root), and committing the manifest alone, with the
// convention file already committed, must newly report the finding that
// file reaches: the manifest's SourcePaths and the convention file's
// SourcePaths must each name the other.
//
// Each case is one of the six the hunt found: the convention file is
// committed first (unrecognized, no finding), then only the manifest is
// staged and scanned with no path arguments.
func TestScanStagedManifestOnlyActivatesConventionFiles(t *testing.T) {
	bin := buildStagedBinary(t)
	root := filepath.Dir(rulesTree(t))
	cases := []struct {
		name     string
		fixture  string
		manifest string
		wantRule string
		wantPath string
	}{
		{
			name:     "006_claude-plugin-hooks-json",
			fixture:  "rules/TC-CFG-006.test/positivos/claude-plugin-hooks-json",
			manifest: "tools/acme-plugin/.claude-plugin/plugin.json",
			wantRule: "TC-CFG-006",
			wantPath: "tools/acme-plugin/hooks/hooks.json",
		},
		{
			name:     "007_claude-plugin-skill",
			fixture:  "rules/TC-CFG-007.test/positivos/claude-plugin-skill",
			manifest: "tools/acme/.claude-plugin/plugin.json",
			wantRule: "TC-CFG-007",
			wantPath: "tools/acme/skills/review/SKILL.md",
		},
		{
			name:     "012_claude-nested-plugin-skill",
			fixture:  "rules/TC-CFG-012.test/positivos/claude-nested-plugin-skill",
			manifest: "plugins/x/.claude-plugin/plugin.json",
			wantRule: "TC-CFG-012",
			wantPath: "plugins/x/skills/k/SKILL.md",
		},
		{
			name:     "012_claude-plugin-root-agent",
			fixture:  "rules/TC-CFG-012.test/positivos/claude-plugin-root-agent",
			manifest: ".claude-plugin/plugin.json",
			wantRule: "TC-CFG-012",
			wantPath: "agents/review.md",
		},
		{
			name:     "012_claude-plugin-root-command",
			fixture:  "rules/TC-CFG-012.test/positivos/claude-plugin-root-command",
			manifest: ".claude-plugin/plugin.json",
			wantRule: "TC-CFG-012",
			wantPath: "commands/setup.md",
		},
		{
			name:     "012_claude-plugin-root-skill",
			fixture:  "rules/TC-CFG-012.test/positivos/claude-plugin-root-skill",
			manifest: ".claude-plugin/plugin.json",
			wantRule: "TC-CFG-012",
			wantPath: "skills/p/SKILL.md",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := stagedRepo(t)
			copyTree(t, filepath.Join(root, filepath.FromSlash(tc.fixture)), repo)
			manifestAbs := filepath.Join(repo, filepath.FromSlash(tc.manifest))
			manifestBody, err := os.ReadFile(manifestAbs)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(manifestAbs); err != nil {
				t.Fatal(err)
			}
			stagedGit(t, repo, "add", ".")
			stagedGit(t, repo, "commit", "-qm", "convention files without the manifest")

			if code, out := stagedScan(t, bin, repo); code != 0 {
				t.Fatalf("convention file alone, no manifest = %d, want 0\n%s", code, out)
			}

			if err := os.WriteFile(manifestAbs, manifestBody, 0o644); err != nil {
				t.Fatal(err)
			}
			stagedGit(t, repo, "add", tc.manifest)

			// Findings here are medium severity, which does not fail the
			// scan's default --fail-on high; the hunt cares about the
			// finding being reported at all, not the exit code.
			_, out := stagedScan(t, bin, repo)
			if !strings.Contains(out, tc.wantRule) || !strings.Contains(out, tc.wantPath) {
				t.Fatalf("manifest only, no paths: want %s at %s\n%s", tc.wantRule, tc.wantPath, out)
			}
			// Explicit paths (the manifest alone) must report it too.
			_, out = stagedScan(t, bin, repo, tc.manifest)
			if !strings.Contains(out, tc.wantRule) || !strings.Contains(out, tc.wantPath) {
				t.Fatalf("manifest only, explicit path: want %s at %s\n%s", tc.wantRule, tc.wantPath, out)
			}
		})
	}
}
