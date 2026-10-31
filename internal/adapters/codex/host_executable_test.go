package codex

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/vgmartinez/tripcord/internal/adapters/kit/kittest"
	"github.com/vgmartinez/tripcord/internal/model"
)

func TestRulesFileHostExecutableValidation(t *testing.T) {
	t.Parallel()
	invalid := map[string]string{
		"path in name":       `host_executable(name = "bin/git", paths = ["/usr/bin/git"])`,
		"dot-dot in name":    `host_executable(name = "..git", paths = ["/usr/bin/git"])`,
		"separator in name":  `host_executable(name = "git;rm", paths = ["/usr/bin/git"])`,
		"backslash in name":  `host_executable(name = "bin\\git", paths = ["/usr/bin/git"])`,
		"empty paths":        `host_executable(name = "git", paths = [])`,
		"relative path":      `host_executable(name = "git", paths = ["/usr/bin/git", "bin/git"])`,
		"empty path":         `host_executable(name = "git", paths = [""])`,
		"root as path":       `host_executable(name = "git", paths = ["/"])`,
		"drive without root": `host_executable(name = "git", paths = ["C:git.exe"])`,
	}
	for name, src := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"), src+"\n")
			a := New(Options{})
			got := kittest.Discover(t, a, root)
			if len(got.Find(".codex/rules/default.rules", model.ConfigKindPermissions)) != 1 {
				t.Fatalf("items = %+v, want the host-executable item still reported", got.Items)
			}
			if !kittest.Blocking(t, a, root, "host_executable") {
				t.Fatalf("diagnostics = %v, want a host_executable warning", got.Diagnostics)
			}
		})
	}
	for i, paths := range []string{
		`["/usr/bin/git", "/opt/homebrew/bin/git"]`,
		`["C:\\Program Files\\Git\\bin\\git.exe"]`,
		`["C:/Git/bin/git.exe", "\\\\server\\share\\git.exe"]`,
	} {
		root := t.TempDir()
		kittest.WriteFile(t, filepath.Join(root, ".codex", "rules", "default.rules"), fmt.Sprintf("host_executable(name = \"git\", paths = %s)\n", paths))
		if got := kittest.Discover(t, New(Options{}), root); len(got.Diagnostics) != 0 {
			t.Errorf("case %d %s: diagnostics = %v, want none", i, paths, got.Diagnostics)
		}
	}
}
