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
