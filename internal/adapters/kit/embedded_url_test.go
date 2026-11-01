package kit

import (
	"strings"
	"testing"
)

func TestStripEmbeddedURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want, removed string }{
		{"https://e.com/x?a=)&sig=S1", "https://e.com/x", "a=)&sig=S1"},
		{"https://b.s3.amazonaws.com/k?a=)&X-Amz-Signature=S2", "https://b.s3.amazonaws.com/k", "a=)&X-Amz-Signature=S2"},
		{"https://e.com/(x)?sig=S3", "https://e.com/(x)", "sig=S3"},
		{"https://e.com/x?a=`&sig=S4", "https://e.com/x", "a=`&sig=S4"},
		{"https://e.com/wiki/Foo_(bar)?sig=S5", "https://e.com/wiki/Foo_(bar)", "sig=S5"},
		{"https://e.com/x#a)S6", "https://e.com/x", "a)S6"},
		{"https://u:S7@e.com/x)", "https://e.com/x)", "u:S7"},
		{"https://e.com/x?sig=S8)", "https://e.com/x)", "sig=S8)"},
		{"https://e.com/x?sig=S9`", "https://e.com/x`", "sig=S9`"},
		{"https://e.com/x?q=1#f", "https://e.com/x", "q=1\x00f"},
		{"https://e.com/x?", "https://e.com/x", ""},
		{"https://e.com/x)", "https://e.com/x)", ""},
		{"https://e.com/a%20b", "https://e.com/a%20b", ""},
	} {
		got, removed, ok := StripEmbeddedURL(tc.in)
		if !ok || got != tc.want || removed != tc.removed {
			t.Errorf("StripEmbeddedURL(%q) = %q, %q, %v; want %q, %q", tc.in, got, removed, ok, tc.want, tc.removed)
		}
		for _, s := range []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9"} {
			if strings.Contains(got, s) {
				t.Errorf("StripEmbeddedURL(%q) = %q keeps %s", tc.in, got, s)
			}
		}
	}
	for _, in := range []string{"file:///etc/x?s=1", "https://:80/x", "https:///x"} {
		if _, _, ok := StripEmbeddedURL(in); ok {
			t.Errorf("StripEmbeddedURL(%q) ok, want no host", in)
		}
	}
}
