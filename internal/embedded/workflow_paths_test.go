package embedded

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/devin"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/opencode"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
)

// legacyWorkflowPaths is the paths filter init --embed used to write.
// It is kept here so a regression that puts a directory list back has
// to cover every witness below, not only these prefixes.
var legacyWorkflowPaths = []string{
	".claude/**",
	".cursor/**",
	".codex/**",
	".github/**",
	".vscode/**",
	".mcp.json",
	"AGENTS.md",
	"CLAUDE.md",
	"GEMINI.md",
	".devin/**",
	".tripcord/**",
}

// workflowWitness is a repository path the generated workflow must
// trigger on. read reports whether an adapter or the embed check
// actually consumes it, so a witness that nothing reads fails the test
// instead of rotting into an unused path.
type workflowWitness struct {
	path string
	read func(string) bool
}

func adapterRead(rel string) bool {
	if claude.RepoCandidate(rel) || claude.Reads(rel, pluginRootsFor(rel)) {
		return true
	}
	return codex.RepoCandidate(rel) ||
		copilot.RepoCandidate(rel) ||
		cursor.RepoCandidate(rel) ||
		devcontainer.RepoCandidate(rel) ||
		devin.RepoCandidate(rel) ||
		gemini.RepoCandidate(rel) ||
		generic.RepoCandidate(rel) ||
		opencode.RepoCandidate(rel) ||
		windsurf.RepoCandidate(rel)
}

// pluginRootsFor treats every directory prefix of rel as a Claude
// plugin root. That is the convention classify uses once a plugin
// manifest has been found: hooks/hooks.json, skills/*/SKILL.md,
// agents/*.md, and commands/*.md directly under the root.
func pluginRootsFor(rel string) map[string]bool {
	roots := map[string]bool{"": true}
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		roots[strings.Join(parts[:i], "/")] = true
	}
	return roots
}

func embedRead(rel string) bool {
	return rel == GitattributesPath || strings.HasSuffix(rel, "/"+GitattributesPath) ||
		rel == WorkflowPath || strings.HasPrefix(rel, ".tripcord/")
}

func workflowWitnesses() []workflowWitness {
	read := func(rel string) bool { return adapterRead(rel) }
	paths := []string{
		// Nested copies of directories the old filter named only at the root.
		"pkg/.claude/settings.json",
		"pkg/.cursor/hooks.json",
		"pkg/.codex/config.toml",
		"pkg/.mcp.json",
		"pkg/.devin/blueprint.yaml",
		"services/CLAUDE.md",
		// The files the old filter did not name at all.
		".gemini/settings.json",
		"services/.gemini/settings.json",
		".agents/skills/demo/SKILL.md",
		"pkg/.agents/skills/demo/SKILL.md",
		".devcontainer/devcontainer.json",
		".devcontainer/app/devcontainer.json",
		".devcontainer.json",
		".opencode/plugins/hook.ts",
		"pkg/.opencode/plugins/hook.ts",
		"pkg/opencode.json",
		".windsurf/hooks.json",
		"pkg/.windsurf/rules/a.md",
		".cursorrules",
		"pkg/.cursorrules",
		".windsurfrules",
		".claude-plugin/plugin.json",
		"pkg/.claude-plugin/marketplace.json",
		"CLAUDE.local.md",
		"pkg/CLAUDE.local.md",
		"AGENTS.md",
		"pkg/AGENTS.md",
		"GEMINI.md",
		"pkg/GEMINI.md",
		// A Claude plugin root is wherever plugin.json lives. The files
		// beside it are not under .claude/.
		"tools/plugin/hooks/hooks.json",
		"tools/plugin/skills/demo/SKILL.md",
		"tools/plugin/agents/review.md",
		"tools/plugin/commands/ship.md",
	}
	var out []workflowWitness
	for _, p := range paths {
		out = append(out, workflowWitness{path: p, read: read})
	}
	out = append(out,
		workflowWitness{path: GitattributesPath, read: embedRead},
		workflowWitness{path: "pkg/" + GitattributesPath, read: embedRead},
		workflowWitness{path: WorkflowPath, read: embedRead},
		workflowWitness{path: ".tripcord/bootstrap.sh", read: embedRead},
	)
	return out
}

// TestWorkflowPathsCoverAdapterGlobs fails when the generated workflow's
// pull_request paths filter would skip a file an adapter reads or the
// embed check hashes. No filter covers every path. The legacy list is
// asserted to miss the same witnesses, so this test fails if that list
// comes back.
func TestWorkflowPathsCoverAdapterGlobs(t *testing.T) {
	patterns, filtered := workflowPathPatterns(t, Workflow())
	missedByLegacy := 0
	for _, w := range workflowWitnesses() {
		if !w.read(w.path) {
			t.Errorf("witness %s is not read by an adapter or the embed check", w.path)
			continue
		}
		if !githubPathsCover(patterns, filtered, w.path) {
			t.Errorf("workflow paths filter skips %s", w.path)
		}
		if !githubPathsCover(legacyWorkflowPaths, true, w.path) {
			missedByLegacy++
		}
	}
	if missedByLegacy == 0 {
		t.Fatal("legacy paths filter covers every witness; the regression check no longer bites")
	}
}

func TestLegacyWorkflowPathsMissKnownFiles(t *testing.T) {
	// These are the paths the finding names. Each one is read, and none
	// of them matched the old paths filter.
	required := []string{
		"pkg/.claude/settings.json",
		".gemini/settings.json",
		".agents/skills/demo/SKILL.md",
		".devcontainer/devcontainer.json",
		".opencode/plugins/hook.ts",
		".windsurf/hooks.json",
		".cursorrules",
		".windsurfrules",
		".claude-plugin/plugin.json",
		"CLAUDE.local.md",
		"pkg/AGENTS.md",
		".gitattributes",
	}
	for _, rel := range required {
		if !adapterRead(rel) && !embedRead(rel) {
			t.Errorf("%s is not read", rel)
		}
		if githubPathsCover(legacyWorkflowPaths, true, rel) {
			t.Errorf("legacy filter covers %s", rel)
		}
		patterns, filtered := workflowPathPatterns(t, Workflow())
		if !githubPathsCover(patterns, filtered, rel) {
			t.Errorf("generated workflow skips %s", rel)
		}
	}
}

func TestGitHubPathMatcher(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{".claude/**", ".claude/settings.json", true},
		{".claude/**", "pkg/.claude/settings.json", false},
		{"**/.claude/**", "pkg/.claude/settings.json", true},
		{"**/.claude/**", ".claude/settings.json", true},
		{"AGENTS.md", "AGENTS.md", true},
		{"AGENTS.md", "pkg/AGENTS.md", false},
		{"**/AGENTS.md", "pkg/AGENTS.md", true},
		{".mcp.json", ".mcp.json", true},
		{".mcp.json", "pkg/.mcp.json", false},
		{"**/.cursorrules", ".cursorrules", true},
		{"**/.cursorrules", "pkg/.cursorrules", true},
		{".github/**", ".github/hooks/tripcord.json", true},
		{".github/**", "pkg/.github/hooks/tripcord.json", false},
	}
	for _, tc := range cases {
		if got := githubMatch(tc.pattern, tc.path); got != tc.want {
			t.Errorf("githubMatch(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// workflowPathPatterns is the pull_request paths filter of raw.
// filtered is false when the workflow runs on every pull request.
func workflowPathPatterns(t *testing.T, raw []byte) (patterns []string, filtered bool) {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		t.Fatalf("workflow document kind %d", doc.Kind)
	}
	on := mapValue(doc.Content[0], "on")
	pr := mapValue(on, "pull_request")
	if pr == nil || pr.Tag == "!!null" || pr.Kind != yaml.MappingNode {
		return nil, false
	}
	paths := mapValue(pr, "paths")
	if paths == nil || paths.Tag == "!!null" {
		return nil, false
	}
	if paths.Kind != yaml.SequenceNode {
		t.Fatalf("paths kind %d", paths.Kind)
	}
	for _, item := range paths.Content {
		if item.Kind != yaml.ScalarNode || item.Value == "" {
			t.Fatalf("paths entry %q", item.Value)
		}
		patterns = append(patterns, item.Value)
	}
	return patterns, true
}

// githubPathsCover reports whether patterns match path. An unfiltered
// workflow (filtered false) matches every path.
func githubPathsCover(patterns []string, filtered bool, path string) bool {
	if !filtered {
		return true
	}
	for _, pattern := range patterns {
		if githubMatch(pattern, path) {
			return true
		}
	}
	return false
}

// githubMatch is the subset of GitHub Actions path filters this test
// needs: '*' matches within one path segment, '**' matches across
// segments, and every other character is literal. A pattern that uses
// '?', '+', or '[]' fails closed so a witness is not treated as covered
// by a pattern this matcher does not implement.
func githubMatch(pattern, path string) bool {
	if strings.ContainsAny(pattern, "?+[]") {
		return false
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchSegments(pat, path []string) bool {
	for {
		if len(pat) == 0 {
			return len(path) == 0
		}
		if pat[0] == "**" {
			if matchSegments(pat[1:], path) {
				return true
			}
			if len(path) == 0 {
				return false
			}
			path = path[1:]
			continue
		}
		if len(path) == 0 || !matchOneSegment(pat[0], path[0]) {
			return false
		}
		pat = pat[1:]
		path = path[1:]
	}
}

func matchOneSegment(pat, seg string) bool {
	for {
		star := strings.IndexByte(pat, '*')
		if star < 0 {
			return pat == seg
		}
		prefix := pat[:star]
		if !strings.HasPrefix(seg, prefix) {
			return false
		}
		seg = seg[len(prefix):]
		pat = pat[star+1:]
		if pat == "" {
			return true
		}
		// The next literal in pat must occur in seg. Try each position
		// so a later '*' still matches.
		next := pat
		if i := strings.IndexByte(next, '*'); i >= 0 {
			next = next[:i]
		}
		if next == "" {
			continue
		}
		idx := strings.Index(seg, next)
		if idx < 0 {
			return false
		}
		seg = seg[idx:]
	}
}
