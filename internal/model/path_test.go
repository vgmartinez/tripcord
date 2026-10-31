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
		{"managed relative", ScopeManaged, "cursor/hooks.json", "cursor/hooks.json"},
		{"root stays root", ScopeManaged, "/", "/"},
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
		{"repo unix absolute", ScopeRepo, "/home/runner/work/acme/acme/x", errPathNotRelative},
		{"repo windows drive backslash", ScopeRepo, `C:\Users\runner\x`, errPathNotRelative},
		{"repo windows drive forward slash", ScopeRepo, "C:/Users/runner/x", errPathNotRelative},
		{"repo home relative", ScopeRepo, "~/x", errPathNotRelative},
		{"user absolute", ScopeUser, "/home/dev/x", errPathNotUserHome},
		{"user repo relative", ScopeUser, "x/y", errPathNotUserHome},
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
