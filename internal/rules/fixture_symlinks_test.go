package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vgmartinez/tripcord/internal/txtar"
)

const coreRulesDir = "../../rules"

// fixtureSymlink is a symlink inside a raw fixture of the core pack.
// The repository tracks no symlinks: GitHub's action download fails on
// them, including in-repo and dangling ones, which breaks every
// consumer of the composite action. corePackWithSymlinks creates these
// in a copy of the pack instead.
type fixtureSymlink struct {
	fixture string // <ID>.test/<kind>/<name>, relative to the pack
	link    string // relative to the fixture
	target  string // link text
}

var fixtureSymlinks = []fixtureSymlink{
	{"TC-CFG-003.test/positivos/bash-script-symlink-outside", "scripts/run.sh", "/etc/passwd"},
	{"TC-CFG-006.test/negativos/claude-symlink-inside", "scripts/x.sh", "real.sh"},
	{"TC-CFG-009.test/negativos/devin-assignment-dot-path-keeps-checksum", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/negativos/devin-cp-dot-keeps-checksum", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/negativos/devin-dot-slash-keeps-checksum", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/negativos/devin-find-dot-keeps-checksum", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/negativos/devin-git-dash-c-dot-keeps-checksum", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/negativos/devin-ls-dot-keeps-checksum", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/negativos/devin-make-dash-c-dot-keeps-checksum", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/negativos/devin-shell-state-echo-control", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/checksum-casefold-target-symlink-outside", "T.SH", "inside-link-target"},
	{"TC-CFG-009.test/positivos/checksum-casefold-target-symlink-to-sums", "T.SH", "t.sh.sha256"},
	{"TC-CFG-009.test/positivos/checksum-fetched-target-symlink-outside", "t.sh", "inside-link-target"},
	{"TC-CFG-009.test/positivos/checksum-fetched-target-symlink-to-sums", "t.sh", "t.sh.sha256"},
	// The fetched t.sh is not in the tree, so these links dangle.
	{"TC-CFG-009.test/positivos/checksum-sums-symlink-to-fetched-direct", "t.sh.sha256", "t.sh"},
	{"TC-CFG-009.test/positivos/checksum-sums-symlink-to-fetched-dot", "t.sh.sha256", "./t.sh"},
	{"TC-CFG-009.test/positivos/checksum-sums-symlink-to-fetched-nested", "sub/x", "../t.sh"},
	{"TC-CFG-009.test/positivos/checksum-sums-symlink-to-fetched-nested", "t.sh.sha256", "sub/x"},
	{"TC-CFG-009.test/positivos/devin-cd-carries-into-maintenance", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-cd-carries-within-maintenance", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-nested-blueprint-case-alias-symlink", "packages/a/T.sh", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-nested-blueprint-root-sums", "packages/a/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-assign-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-brace-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-builtin-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-builtin-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-case-multiline-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-case-one-line-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-case-paren-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-command-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-command-option-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-do-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-double-quoted-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-env-option-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-escaped-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-eval-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-for-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-function-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-if-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-if-then-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-redirection-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-single-quoted-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-source", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-sudo-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-time-cd", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-time-dot", "sub/t.sh.sha256", "inside-link-target"},
	{"TC-CFG-009.test/positivos/devin-shell-state-time-option-dot", "sub/t.sh.sha256", "inside-link-target"},
}

// corePackWithSymlinks copies the core pack into t.TempDir, unpacking
// each raw fixture archive <name>.txtar into its directory <name>, and
// creates fixtureSymlinks there with os.Symlink. Tests that run core
// fixtures use the copy, so each symlink case stays covered without a
// symlink in git.
func corePackWithSymlinks(t *testing.T) string {
	t.Helper()
	dst := txtar.ExpandTree(t, coreRulesDir)
	for _, l := range fixtureSymlinks {
		fixture := filepath.Join(dst, filepath.FromSlash(l.fixture))
		if info, err := os.Stat(fixture); err != nil || !info.IsDir() {
			t.Fatalf("fixtureSymlinks: %s is not a fixture directory", l.fixture)
		}
		link := filepath.Join(fixture, filepath.FromSlash(l.link))
		if _, err := os.Lstat(link); err == nil {
			t.Fatalf("fixtureSymlinks: %s/%s already exists in the pack", l.fixture, l.link)
		}
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.FromSlash(l.target), link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	return dst
}
