package cfg014

import "testing"

func TestDefaultClassifiersMatchAdapterPaths(t *testing.T) {
	classifiers := DefaultClassifiers()
	cases := []struct {
		path    string
		harness string
	}{
		{path: ".cursor/hooks.json", harness: "cursor"},
		{path: ".claude/settings.json", harness: "claude"},
		{path: ".claude-plugin/marketplace.json", harness: "claude"},
		{path: ".codex/config.toml", harness: "codex"},
		{path: ".github/copilot-instructions.md", harness: "copilot"},
		{path: ".gemini/settings.json", harness: "gemini"},
		{path: "opencode.json", harness: "opencode"},
		{path: ".opencode/plugins/helper/lib.ts", harness: "opencode"},
		{path: ".windsurf/hooks.json", harness: "windsurf"},
		{path: ".devin/hooks.json", harness: "windsurf"},
		{path: ".devin/blueprint.yaml", harness: "devin"},
		{path: ".devcontainer/devcontainer.json", harness: "devcontainer"},
		{path: "AGENTS.md", harness: "generic"},
		{path: ".github/skills/demo/SKILL.md", harness: "generic"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			var matched []string
			for _, classifier := range classifiers {
				if classifier.Classifies(tc.path) {
					matched = append(matched, string(classifier.Harness()))
				}
			}
			if len(matched) != 1 || matched[0] != tc.harness {
				t.Fatalf("classifiers = %v, want %s", matched, tc.harness)
			}
		})
	}
	for _, classifier := range classifiers {
		if classifier.Classifies("README") {
			t.Fatalf("%s classified README", classifier.Harness())
		}
	}
}
