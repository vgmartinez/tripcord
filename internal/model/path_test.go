package model

import (
	"errors"
	"testing"
)

func TestNormalizeScopedPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		scope Scope
		path  string
		want  string
	}{
		{"repo relative", ScopeRepo, ".vscode/tasks.json", ".vscode/tasks.json"},
		{"empty scope defaults to repo", "", ".vscode/tasks.json", ".vscode/tasks.json"},
		{"repo trims and collapses slashes", ScopeRepo, " .vscode//tasks.json/ ", ".vscode/tasks.json"},
		{"repo backslashes", ScopeRepo, `.vscode\tasks.json`, ".vscode/tasks.json"},
		{"user home", ScopeUser, "~/.claude/settings.json", "~/.claude/settings.json"},
		{"user bare tilde", ScopeUser, "~", "~"},
		{"managed absolute", ScopeManaged, "/etc/cursor/hooks.json", "/etc/cursor/hooks.json"},
		{"managed windows drive", ScopeManaged, `C:\ProgramData\cursor\hooks.json`, "C:/programdata/cursor/hooks.json"},
		{"managed windows drive lowercase", ScopeManaged, "c:/programdata/cursor/hooks.json", "C:/programdata/cursor/hooks.json"},
		{"root stays root", ScopeManaged, "/", "/"},
		{"repo strips a leading dot slash", ScopeRepo, "./.vscode/tasks.json", ".vscode/tasks.json"},
		{"repo strips repeated leading dot slash", ScopeRepo, "././.vscode/tasks.json", ".vscode/tasks.json"},
		{"repo cleans a dot segment", ScopeRepo, "a/./b", "a/b"},
		{"repo nfc", ScopeRepo, "dir/cafe\u0301", "dir/caf\u00e9"},
		{"repo colon is not a drive", ScopeRepo, "a:b.json", "a:b.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeScopedPath(tc.scope, tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("normalizeScopedPath(%q, %q) = %q, want %q", tc.scope, tc.path, got, tc.want)
			}
		})
	}
}

func TestNormalizeScopedPathRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		scope Scope
		path  string
		want  error
	}{
		{"empty path", ScopeRepo, "", errPathEmpty},
		{"whitespace only path", ScopeRepo, "   ", errPathEmpty},
		{"repo unix absolute", ScopeRepo, "/home/runner/work/vgmartinez/vgmartinez/x", errPathNotRelative},
		{"repo windows drive backslash", ScopeRepo, `C:\Users\runner\x`, errPathNotRelative},
		{"repo windows drive forward slash", ScopeRepo, "C:/Users/runner/x", errPathNotRelative},
		{"repo windows drive lowercase", ScopeRepo, "c:/users/runner/x", errPathNotRelative},
		{"repo home relative", ScopeRepo, "~/x", errPathNotRelative},
		{"repo raw dotdot", ScopeRepo, "a/../b", errPathDotDot},
		{"user raw dotdot", ScopeUser, "a/../b", errPathDotDot},
		{"managed raw dotdot", ScopeManaged, "a/../b", errPathDotDot},
		{"repo trailing dotdot", ScopeRepo, "x/..", errPathDotDot},
		{"user trailing dotdot", ScopeUser, "x/..", errPathDotDot},
		{"managed trailing dotdot", ScopeManaged, "x/..", errPathDotDot},
		{"user dotdot inside home", ScopeUser, "~/.claude/../settings.json", errPathDotDot},
		{"repo leading dotdot", ScopeRepo, "../etc/passwd", errPathDotDot},
		{"repo dotdot after dot-slash strip", ScopeRepo, "./../etc/passwd", errPathDotDot},
		{"repo unresolved dotdot", ScopeRepo, "foo/../../etc/passwd", errPathDotDot},
		{"user dotdot escapes home", ScopeUser, "~/../../x", errPathDotDot},
		{"managed relative dotdot", ScopeManaged, "../etc/cursor/hooks.json", errPathDotDot},
		{"managed absolute dotdot remains", ScopeManaged, "foo/../../etc/passwd", errPathDotDot},
		{"repo UNC", ScopeRepo, `\\server\share\hooks.json`, errPathNotRelative},
		{"user absolute", ScopeUser, "/home/dev/x", errPathNotUserHome},
		{"user repo relative", ScopeUser, "x/y", errPathNotUserHome},
		{"managed repo relative", ScopeManaged, "cursor/hooks.json", errPathNotAbsolute},
		{"managed home relative", ScopeManaged, "~/cursor/hooks.json", errPathNotAbsolute},
		{"unknown scope", Scope("global"), "x", errPathScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := normalizeScopedPath(tc.scope, tc.path)
			if !errors.Is(err, tc.want) {
				t.Fatalf("normalizeScopedPath(%q, %q) err = %v, want %v", tc.scope, tc.path, err, tc.want)
			}
		})
	}
}
