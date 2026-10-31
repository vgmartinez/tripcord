package claude

import "testing"

// S6: tildePath must clean home the same way filepath.Join already
// cleans p, or a home with a trailing "." or ".." segment (as
// os.UserHomeDir can return on some systems, or a caller-supplied
// HomeDir) would never match the already-cleaned paths built from it.
func TestTildePathCleansHome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		home string
		p    string
		want string
	}{
		{name: "trailing dot segment", home: "/x/victor/.", p: "/x/victor/.claude/settings.json", want: "~/.claude/settings.json"},
		{name: "trailing slash", home: "/x/victor/", p: "/x/victor/.claude/settings.json", want: "~/.claude/settings.json"},
		{name: "already clean", home: "/x/victor", p: "/x/victor/.claude/settings.json", want: "~/.claude/settings.json"},
		{name: "bare home", home: "/x/victor/.", p: "/x/victor", want: "~"},
		{name: "backslash home", home: `C:\Users\victor\.`, p: "C:/Users/victor/.claude/settings.json", want: "~/.claude/settings.json"},
		{name: "empty home", home: "", p: "/x/victor/.claude/settings.json", want: "/x/victor/.claude/settings.json"},
		{name: "home cleans to dot", home: ".", p: "./settings.json", want: "./settings.json"},
		{name: "no match", home: "/x/victor/.", p: "/etc/passwd", want: "/etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tildePath(tc.home, tc.p); got != tc.want {
				t.Fatalf("tildePath(%q, %q) = %q, want %q", tc.home, tc.p, got, tc.want)
			}
		})
	}
}
