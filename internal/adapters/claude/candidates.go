package claude

import (
	"encoding/json"
	"path"
	"strings"
)

// RepoCandidate reports whether Discover reads rel when no plugin root
// is known yet. Plugin skills and commands are covered by Reads.
func RepoCandidate(rel string) bool {
	return classify(rel, nil) != roleNone
}

// WalkCandidate reports whether the repository walk lists rel. It is wider
// than RepoCandidate: a listed file is read only when Reads accepts it.
func WalkCandidate(rel string) bool { return candidateName(rel) }

// RepoRelevant reports whether an unreadable symlink at rel can hide
// Claude configuration.
func RepoRelevant(rel string) bool { return configRelevant(rel) }

// PluginRoot returns the plugin directory of a plugin manifest path.
func PluginRoot(rel string) (string, bool) {
	if classify(rel, nil) != rolePluginManifest {
		return "", false
	}
	return pluginRootOf(rel), true
}

// IsMarketplace reports whether rel is a marketplace manifest.
func IsMarketplace(rel string) bool { return classify(rel, nil) == roleMarketplace }

// IsManifest reports whether rel is a plugin manifest.
func IsManifest(rel string) bool { return classify(rel, nil) == rolePluginManifest }

// Reads reports whether Discover reads rel once plugin roots are known.
func Reads(rel string, pluginRoots map[string]bool) bool {
	return classify(rel, pluginRoots) != roleNone
}

// RootFor returns the plugin root that makes rel Claude configuration by
// convention: hooks/hooks.json, a skills/*/SKILL.md, an agents/*.md, or
// a commands/*.md directly under it (the same conditions classify's
// plugin-root branch matches). ok is false when no root in pluginRoots
// reads rel this way, including when some other rule (for example the
// universal .claude/skills/*/SKILL.md path) already classifies it
// without a plugin root at all.
// When more than one root matches — a plugin root nested inside
// another's skills, agents, or commands directory — the longest, most
// specific root wins, deterministically rather than by map iteration
// order, so a caller linking a convention file to its root's own
// manifest and marketplace entries always picks the same one.
func RootFor(rel string, pluginRoots map[string]bool) (root string, ok bool) {
	base := strings.ToLower(path.Base(rel))
	for candidate := range pluginRoots {
		prefix := candidate
		if prefix != "" {
			prefix += "/"
		}
		rest, cut := strings.CutPrefix(rel, prefix)
		if !cut {
			continue
		}
		switch {
		case rest == "hooks/hooks.json",
			strings.HasPrefix(rest, "skills/") && base == "skill.md",
			strings.HasPrefix(rest, "agents/") && strings.HasSuffix(base, ".md"),
			strings.HasPrefix(rest, "commands/") && strings.HasSuffix(base, ".md"):
		default:
			continue
		}
		if !ok || len(candidate) > len(root) {
			root, ok = candidate, true
		}
	}
	return root, ok
}

// JoinUnder resolves ref relative to base the way a plugin manifest does.
// Absolute, URL, and escaping references are not followed.
func JoinUnder(base, ref string) (string, bool) {
	if strings.Contains(ref, "://") {
		return "", false
	}
	ref = strings.ReplaceAll(ref, `\`, "/")
	if path.IsAbs(ref) || hasDriveLetter(ref) {
		return "", false
	}
	for _, segment := range strings.Split(ref, "/") {
		if segment == ".." {
			return "", false
		}
	}
	joined := path.Join(base, ref)
	if joined == "." {
		return "", true
	}
	return joined, true
}

// MarketplaceRoots returns plugin directories named by a marketplace file.
func MarketplaceRoots(raw []byte, rel string) []string {
	var doc struct {
		Metadata struct {
			PluginRoot string `json:"pluginRoot"`
		} `json:"metadata"`
		Plugins []struct {
			Source string `json:"source"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	base := pluginRootOf(rel)
	if doc.Metadata.PluginRoot != "" {
		joined, ok := JoinUnder(base, doc.Metadata.PluginRoot)
		if !ok {
			return nil
		}
		base = joined
	}
	var roots []string
	for _, plugin := range doc.Plugins {
		if plugin.Source == "" {
			continue
		}
		if root, ok := JoinUnder(base, plugin.Source); ok {
			roots = append(roots, root)
		}
	}
	return roots
}

// ManifestRefs returns hook and MCP files a plugin manifest names by path.
func ManifestRefs(raw []byte, rel string) []string {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	root := pluginRootOf(rel)
	var refs []string
	collect := func(value any) {
		switch v := value.(type) {
		case string:
			if p, ok := JoinUnder(root, v); ok && p != "" {
				refs = append(refs, p)
			}
		case []any:
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					continue
				}
				if p, ok := JoinUnder(root, s); ok && p != "" {
					refs = append(refs, p)
				}
			}
		}
	}
	collect(doc["hooks"])
	collect(doc["mcpServers"])
	return refs
}
