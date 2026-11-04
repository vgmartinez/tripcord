package txtar

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		comment string
		files   []File
	}{
		{name: "empty", in: "", comment: "", files: nil},
		{name: "comment", in: "hello\n", comment: "hello\n"},
		{name: "comment gains newline", in: "hello", comment: "hello\n"},
		{
			name: "one file",
			in:   "-- foo --\ncontent\n",
			files: []File{
				{Name: "foo", Data: []byte("content\n")},
			},
		},
		{
			name: "missing final newline",
			in:   "-- foo --\ncontent",
			files: []File{
				{Name: "foo", Data: []byte("content\n")},
			},
		},
		{
			name:    "comment and files",
			in:      "hi\n-- a --\n1\n-- b --\n2\n",
			comment: "hi\n",
			files: []File{
				{Name: "a", Data: []byte("1\n")},
				{Name: "b", Data: []byte("2\n")},
			},
		},
		{
			name: "crlf marker",
			in:   "-- foo --\r\nbar\r\n",
			files: []File{
				{Name: "foo", Data: []byte("bar\r\n")},
			},
		},
		{
			name: "trimmed name",
			in:   "--  foo bar  --\nx\n",
			files: []File{
				{Name: "foo bar", Data: []byte("x\n")},
			},
		},
		{
			name:    "not a marker",
			in:      "-- foo\nstill comment\n",
			comment: "-- foo\nstill comment\n",
		},
		{
			name:    "marker not at line start",
			in:      "x -- foo --\n",
			comment: "x -- foo --\n",
		},
		{
			name:    "empty marker is comment",
			in:      "--  --\nbody\n",
			comment: "--  --\nbody\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Parse([]byte(tc.in))
			if string(got.Comment) != tc.comment {
				t.Fatalf("comment %q, want %q", got.Comment, tc.comment)
			}
			if len(got.Files) != len(tc.files) {
				t.Fatalf("files %#v, want %#v", got.Files, tc.files)
			}
			for i, f := range tc.files {
				if got.Files[i].Name != f.Name || !bytes.Equal(got.Files[i].Data, f.Data) {
					t.Fatalf("file %d %#v, want %#v", i, got.Files[i], f)
				}
			}
			again := Parse(Format(got))
			if !bytes.Equal(again.Comment, got.Comment) || len(again.Files) != len(got.Files) {
				t.Fatalf("Format round trip %#v", again)
			}
			for i := range got.Files {
				if again.Files[i].Name != got.Files[i].Name || !bytes.Equal(again.Files[i].Data, got.Files[i].Data) {
					t.Fatalf("round trip file %d %#v", i, again.Files[i])
				}
			}
		})
	}
}

func TestCRWithoutNewlineIsNotAMarker(t *testing.T) {
	t.Parallel()
	// A trailing CR is not a newline, so the line is not a marker yet.
	// Adding the missing newline, which Format does, makes it one.
	got := Parse([]byte("-- 0 --\r"))
	if string(got.Comment) != "-- 0 --\r\n" || len(got.Files) != 0 {
		t.Fatalf("parse %#v", got)
	}
	again := Parse(Format(got))
	if len(again.Comment) != 0 || len(again.Files) != 1 || again.Files[0].Name != "0" {
		t.Fatalf("after format %#v", again)
	}
	if !sameArchive(again, Parse(Format(again))) {
		t.Fatalf("format did not stabilize")
	}
}

func TestRelRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want error
	}{
		{name: "empty", in: "", want: ErrEmpty},
		{name: "blank", in: "  ", want: ErrEmpty},
		{name: "dot", in: ".", want: ErrEmpty},
		{name: "trailing slash", in: "foo/", want: ErrEmpty},
		{name: "nul", in: "a\x00b", want: ErrNUL},
		{name: "backslash", in: `foo\bar`, want: ErrBackslash},
		{name: "absolute", in: "/etc/passwd", want: ErrAbsolute},
		{name: "drive", in: "C:/Windows/x", want: ErrAbsolute},
		{name: "dotdot", in: "..", want: ErrDotDot},
		{name: "nested dotdot", in: "foo/../../etc/passwd", want: ErrDotDot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Rel(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Rel(%q) = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

func TestUnpackStaysInsideTemp(t *testing.T) {
	t.Parallel()
	dir := Unpack(t, &Archive{
		Comment: []byte("note\n"),
		Files: []File{
			{Name: "a.txt", Data: []byte("one")},
			{Name: "sub/b.txt", Data: []byte("two\n")},
			{Name: "sub/./c.txt", Data: []byte("three")},
		},
	})
	for _, rel := range []string{"a.txt", "sub/b.txt", "sub/c.txt"} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		got, err := filepath.Rel(dir, p)
		if err != nil || got == ".." || strings.HasPrefix(got, "../") {
			t.Fatalf("%s escaped %s", p, dir)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Fatalf("mode %o is executable", info.Mode().Perm())
	}
}

func TestWriteRejectsEscape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	err := Write(dir, &Archive{Files: []File{{Name: "link/secret", Data: []byte("no")}}})
	if !errors.Is(err, ErrOutside) {
		t.Fatalf("symlink write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "secret")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrote outside the temp dir: %v", err)
	}
	err = Write(dir, &Archive{Files: []File{
		{Name: "a.txt", Data: []byte("x")},
		{Name: "sub/../a.txt", Data: []byte("y")},
	}})
	if !errors.Is(err, ErrDotDot) {
		t.Fatalf("dotdot: %v", err)
	}
	err = Write(dir, &Archive{Files: []File{
		{Name: "a.txt", Data: []byte("x")},
		{Name: "a.txt", Data: []byte("y")},
	}})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected archive still wrote a file")
	}
}
