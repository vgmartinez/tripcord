package pathx

import "testing"

func TestTildeHome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		home string
		in   string
		want string
	}{
		{name: "empty home", home: "", in: "/home/vic/x", want: "/home/vic/x"},
		{name: "root", home: "/", in: "/home/vic/x", want: "/home/vic/x"},
		{name: "windows drive root backslash", home: `C:\`, in: `C:\Users\vic`, want: `C:\Users\vic`},
		{name: "windows drive root forward slash", home: "C:/", in: "C:/Users/vic", want: "C:/Users/vic"},
		{name: "prefix of another user, no left issue", home: "/home/vic", in: "/home/victor", want: "/home/victor"},
		{name: "directory under home", home: "/home/vic", in: "/home/vic/x", want: "~/x"},
		{name: "bare home", home: "/home/vic", in: "/home/vic", want: "~"},
		{name: "non-path boundary on the right", home: "/home/vic", in: "/home/vic: denied", want: "~: denied"},
		{name: "trailing separator in home still matches", home: "/home/vic/", in: "/home/vic/x", want: "~/x"},
		{
			name: "home embedded mid-path is not a left boundary",
			home: "/home/victor",
			in:   "/mnt/x/home/victor/y",
			want: "/mnt/x/home/victor/y",
		},
		{
			name: "home at a real left boundary after a separator",
			home: "/home/victor",
			in:   "/mnt/x/ /home/victor/y",
			want: "/mnt/x/ ~/y",
		},
		{
			name: "multiple occurrences all rewritten",
			home: "/home/vic",
			in:   "/home/vic/a then /home/vic/b",
			want: "~/a then ~/b",
		},
		{
			name: "one real match and one embedded non-match",
			home: "/home/vic",
			in:   "/home/vic/a and /x/home/vic2/b",
			want: "~/a and /x/home/vic2/b",
		},
		{name: "quoted path", home: "/home/vic", in: `"/home/vic/x"`, want: `"~/x"`},
		{name: "no occurrence", home: "/home/vic", in: "/etc/passwd", want: "/etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := TildeHome(tc.home, tc.in); got != tc.want {
				t.Fatalf("TildeHome(%q, %q) = %q, want %q", tc.home, tc.in, got, tc.want)
			}
		})
	}
}

// S5: on Windows, a path's drive letter and directory names are
// case-insensitive, and both "/" and "\\" are valid separators (an error
// message built with filepath.Join uses "\\", while config content or a
// user-typed path often uses "/"). TildeHome itself picks Windows
// matching from runtime.GOOS, so these cases call the internal
// tildeHome directly with windowsMatching forced to true, to test it
// deterministically regardless of the OS this test suite runs on (CI's
// "go test -race" step runs only on ubuntu-latest).
func TestTildeHomeWindowsMatching(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		home string
		in   string
		want string
	}{
		{
			name: "case-insensitive directory name",
			home: `C:\Users\Alice`,
			in:   "c:/users/alice/foo",
			want: "~/foo",
		},
		{
			name: "mixed separators in home and text",
			home: `C:\Users\Alice\Projects`,
			in:   `C:/Users/Alice\Projects/app`,
			want: "~/app",
		},
		{
			// Only the matched home segment becomes "~"; a separator
			// outside that match is left exactly as written, the same
			// way the exact-match mode never rewrites text outside its
			// own match.
			name: "forward-slash home matches backslash text",
			home: "C:/Users/Alice",
			in:   `C:\Users\Alice\foo`,
			want: `~\foo`,
		},
		{
			name: "non-path boundary on the right",
			home: `C:\Users\Alice`,
			in:   "c:/users/alice: denied",
			want: "~: denied",
		},
		{
			name: "prefix of another user is not a left boundary match",
			home: `C:\Users\Alice`,
			in:   "c:/users/alicent/foo",
			want: "c:/users/alicent/foo",
		},
		{
			name: "multiple occurrences all rewritten",
			home: `C:\Users\Alice`,
			in:   `C:/Users/Alice/a then c:\users\ALICE\b`,
			want: `~/a then ~\b`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tildeHome(tc.home, tc.in, true); got != tc.want {
				t.Fatalf("tildeHome(%q, %q, true) = %q, want %q", tc.home, tc.in, got, tc.want)
			}
		})
	}
}

// TestTildeHomeNonWindowsMatchingStaysCaseSensitive checks that the
// Windows-mode behavior above is opt-in: with windowsMatching false
// (every other OS), case and separator differences must NOT match, the
// same as TildeHome's existing exact-match behavior.
func TestTildeHomeNonWindowsMatchingStaysCaseSensitive(t *testing.T) {
	t.Parallel()
	home := "/home/vic"
	for _, in := range []string{"/HOME/VIC/x", `\home\vic\x`} {
		if got := tildeHome(home, in, false); got != in {
			t.Fatalf("tildeHome(%q, %q, false) = %q, want unchanged", home, in, got)
		}
	}
}
