package txtar

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add([]byte("hello\n"))
	f.Add([]byte("-- foo --\ncontent"))
	f.Add([]byte("hi\n-- a --\n1\n-- b --\n2\n"))
	f.Add([]byte("--  foo bar  --\r\nx\r\n-- b --\n"))
	f.Add([]byte("-- not\n--  --\n-- ok --\n"))
	f.Add([]byte("-- 0 --\r"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// A parsed comment can gain a newline that turns a CR-terminated
		// marker into a real one, so the first Format is not always an
		// identity. Formatting the result of that parse is.
		a := Parse(data)
		b := Parse(Format(a))
		c := Parse(Format(b))
		if !sameArchive(b, c) {
			t.Fatalf("format did not stabilize\n%#v\n%#v", b, c)
		}
		for _, file := range b.Files {
			if strings.Contains(file.Name, "\n") {
				t.Fatalf("name contains a newline: %q", file.Name)
			}
		}
	})
}

func sameArchive(a, b *Archive) bool {
	if !bytes.Equal(a.Comment, b.Comment) || len(a.Files) != len(b.Files) {
		return false
	}
	for i := range a.Files {
		if a.Files[i].Name != b.Files[i].Name || !bytes.Equal(a.Files[i].Data, b.Files[i].Data) {
			return false
		}
	}
	return true
}
