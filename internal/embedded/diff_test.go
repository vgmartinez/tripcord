package embedded

import "testing"

func TestUnifiedDiff(t *testing.T) {
	for name, tc := range map[string]struct {
		change Change
		want   string
	}{
		"unchanged": {Change{Path: "a", Old: []byte("x\n"), New: []byte("x\n")}, ""},
		"new file":  {Change{Path: "a", New: []byte("x\ny\n")}, "--- /dev/null\n+++ b/a\n@@ -0,0 +1,2 @@\n+x\n+y\n"},
		"middle edit": {
			Change{Path: "f", Old: []byte("1\n2\n3\n4\n5\n6\n7\n8\n9\n"), New: []byte("1\n2\n3\n4\nfive\n6\n7\n8\n9\n")},
			"--- a/f\n+++ b/f\n@@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n",
		},
		"two hunks": {
			Change{Path: "f", Old: []byte("a\n1\n2\n3\n4\n5\n6\n7\nb\n"), New: []byte("A\n1\n2\n3\n4\n5\n6\n7\nB\n")},
			"--- a/f\n+++ b/f\n@@ -1,4 +1,4 @@\n-a\n+A\n 1\n 2\n 3\n@@ -6,4 +6,4 @@\n 5\n 6\n 7\n-b\n+B\n",
		},
		"no trailing newline": {
			Change{Path: "f", Old: []byte("a"), New: []byte("a\nb\n")},
			"--- a/f\n+++ b/f\n@@ -1 +1,2 @@\n-a\n\\ No newline at end of file\n+a\n+b\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := UnifiedDiff(tc.change); got != tc.want {
				t.Fatalf("got:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}
