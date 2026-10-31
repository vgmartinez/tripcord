package codex

import (
	"os"
	"path/filepath"
	"testing"
)

// A trust key with ".." after a symlink names the directory next to the
// symlink's target, as the OS resolves it, not the lexical Clean result.
func TestProjectTrustResolvesSymlinkBeforeDotDot(t *testing.T) {
	t.Parallel()
	base := canonical(t.TempDir())
	elsewhere := canonical(t.TempDir())
	for _, dir := range []string{filepath.Join(elsewhere, "inner"), filepath.Join(elsewhere, "other"), filepath.Join(base, "other")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(elsewhere, "inner"), filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	tree := map[string]any{"projects": map[string]any{
		base + "/link/../other": map[string]any{"trust_level": "trusted"},
	}}
	if got := projectTrust(tree, filepath.Join(elsewhere, "other")); got != trustTrusted {
		t.Errorf("symlink target's sibling: trust = %s, want %s", got, trustTrusted)
	}
	if got := projectTrust(tree, filepath.Join(base, "other")); got != trustUnset {
		t.Errorf("lexical sibling: trust = %s, want %s", got, trustUnset)
	}
}

func TestProjectTrustRootEntryCoversEverything(t *testing.T) {
	t.Parallel()
	repo := canonical(t.TempDir())
	tree := map[string]any{"projects": map[string]any{
		"/": map[string]any{"trust_level": "trusted"},
	}}
	if got := projectTrust(tree, repo); got != trustTrusted {
		t.Errorf("trust = %s, want %s from the / entry", got, trustTrusted)
	}
	tree["projects"].(map[string]any)[repo] = map[string]any{"trust_level": "untrusted"}
	if got := projectTrust(tree, repo); got != trustUntrusted {
		t.Errorf("trust = %s, want the more specific %s", got, trustUntrusted)
	}
}

func TestProjectTrustFoldsCaseOnWindows(t *testing.T) {
	t.Parallel()
	tree := map[string]any{"projects": map[string]any{
		"/Users/Dev/Repo": map[string]any{"trust_level": "trusted"},
	}}
	if got := projectTrustFold(tree, "/users/dev/repo/sub", true); got != trustTrusted {
		t.Errorf("case-insensitive: trust = %s, want %s", got, trustTrusted)
	}
	if got := projectTrustFold(tree, "/users/dev/repo/sub", false); got != trustUnset {
		t.Errorf("case-sensitive: trust = %s, want %s", got, trustUnset)
	}
	if isSelfOrDescendant("/Users/Dev/Repository", "/users/dev/repo", true) {
		t.Errorf("case folding matched a sibling with a shared prefix")
	}
}
