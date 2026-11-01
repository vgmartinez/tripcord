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

		// A shell character ends the query and is kept with what follows.
		{`https://e.com/?x\`, `https://e.com/\`, "x"},
		{`https://e.com/x#\`, `https://e.com/x\`, ""},
		{"https://e.com/?x;npx", "https://e.com/;npx", "x"},
		{"https://c.com/z?sig=S1|sh", "https://c.com/z|sh", "sig=S1"},
		{"https://e.com/?a=1&&curl", "https://e.com/&&curl", "a=1"},
		{"https://e.com/?a=1&", "https://e.com/&", "a=1"},
		{"https://e.com/?a|b?sig=S2", "https://e.com/|b", "a\x00sig=S2"},
		{"https://e.com/?a|https://u:S3@h/x?s=S4", "https://e.com/|https://h/x", "a\x00s=S4\x00u:S3"},

		// The opening quote is part of an embedded match. Its matching
		// closing quote bounds the URL, so old-style query separators stay
		// inside the stripped part. The closing quote itself is outside the
		// match and is left in the enclosing command.
		{`"https://e.com/x?a=1;sig=S1`, `"https://e.com/x`, "a=1;sig=S1"},
		{`'https://e.com/x?a=1|sig=S2`, `'https://e.com/x`, "a=1|sig=S2"},
		{`"https://e.com/x?a=1&&sig=S3`, `"https://e.com/x`, "a=1&&sig=S3"},
		{`"https://e.com/x#a=1;sig=S4`, `"https://e.com/x`, "a=1;sig=S4"},
		{`'https://e.com/x#a=1|sig=S5`, `'https://e.com/x`, "a=1|sig=S5"},
		{`"https://e.com/x#a=1&&sig=S6`, `"https://e.com/x`, "a=1&&sig=S6"},

		// No host: the query and fragment still go.
		{"https://:8443/x?sig=S5", "https://:8443/x", "sig=S5"},
		{"https:///x?sig=S6#S7", "https:///x", "sig=S6\x00S7"},
		{"file:///etc/x?s=S8", "file:///etc/x", "s=S8"},
	} {
		got, removed := StripEmbeddedURL(tc.in)
		if got != tc.want || removed != tc.removed {
			t.Errorf("StripEmbeddedURL(%q) = %q, %q; want %q, %q", tc.in, got, removed, tc.want, tc.removed)
		}
		for _, s := range []string{"S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9"} {
			if strings.Contains(got, s) {
				t.Errorf("StripEmbeddedURL(%q) = %q keeps %s", tc.in, got, s)
			}
		}
	}
}

// FuzzStripEmbeddedURL checks that what StripEmbeddedURL keeps of a
// match never has query or fragment text, nor userinfo, left in it,
// whether or not the URL has a host.
func FuzzStripEmbeddedURL(f *testing.F) {
	for _, seed := range []string{
		"https://e.com/x?a=)&sig=S", "https://u:p@e.com/(x)?s#f)", "https://e.com/x?a=`&s`", "http://h/#a)b",
		"https://:8443/x?sig=S", "https:///x?s#f", `https://e.com/?x\`, "https://e.com/?a|https://u:p@h/?s",
		`"https://e.com/x?a=1;sig=S`, `'https://e.com/x?a=1|sig=S`, `"https://e.com/x#a=1&&sig=S`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, m := range embeddedURL.FindAllString(s, -1) {
			quoted := len(m) > 0 && (m[0] == '\'' || m[0] == '"')
			got, _ := StripEmbeddedURL(m)
			rest := got[strings.Index(got, "://")+3:]
			if strings.ContainsAny(rest, "?#") {
				t.Fatalf("StripEmbeddedURL(%q) = %q keeps query or fragment text", m, got)
			}
			if end := strings.IndexAny(m, "?#"); quoted && end >= 0 && !strings.Contains(m[:end], "@") && got != m[:end] {
				t.Fatalf("StripEmbeddedURL(%q) = %q keeps quoted query or fragment content; want %q", m, got, m[:end])
			}
			for r := got; ; {
				i := strings.Index(r, "://")
				if i < 0 {
					break
				}
				r = r[i+3:]
				end := strings.IndexAny(r, "/?#;|&\\")
				if end < 0 {
					end = len(r)
				}
				if strings.Contains(r[:end], "@") {
					t.Fatalf("StripEmbeddedURL(%q) = %q keeps userinfo", m, got)
				}
			}
		}
	})
}
