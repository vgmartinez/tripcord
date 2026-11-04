// Package txtar reads and writes the text archive format used for corpus
// fixtures: a comment, then files marked by lines of the form "-- name --".
//
// The marker line starts with "-- " and ends with " --". Extra space
// around the name is stripped. A marker is recognized only at the start
// of a line. There are no syntax errors. A missing newline on the last
// line is treated as present. "\r\n" on a marker line is a newline.
package txtar

import (
	"bytes"
	"strings"
)

// Archive is a comment followed by zero or more files.
type Archive struct {
	Comment []byte
	Files   []File
}

// File is one named member. Name is slash-separated and has no marker
// syntax of its own; Data is the bytes up to the next marker.
type File struct {
	Name string
	Data []byte
}

// Format serializes a. Comment and file bodies gain a trailing newline
// when they are non-empty and lack one, matching Parse.
func Format(a *Archive) []byte {
	var buf bytes.Buffer
	buf.Write(fixNL(a.Comment))
	for _, f := range a.Files {
		buf.WriteString("-- ")
		buf.WriteString(f.Name)
		buf.WriteString(" --\n")
		buf.Write(fixNL(f.Data))
	}
	return buf.Bytes()
}

// Parse splits data into an archive. The returned slices alias data,
// except a trailing newline added when the last section omitted one.
func Parse(data []byte) *Archive {
	a := new(Archive)
	var name string
	a.Comment, name, data = findFileMarker(data)
	for name != "" {
		f := File{Name: name}
		f.Data, name, data = findFileMarker(data)
		a.Files = append(a.Files, f)
	}
	return a
}

var (
	newlineMarker = []byte("\n-- ")
	marker        = []byte("-- ")
	markerEnd     = []byte(" --")
)

// findFileMarker returns the bytes before the next marker, the marker's
// name, and the bytes after that marker line. With no further marker the
// name is empty and before is data with a trailing newline ensured.
func findFileMarker(data []byte) (before []byte, name string, after []byte) {
	var i int
	for {
		if name, after = isMarker(data[i:]); name != "" {
			return data[:i], name, after
		}
		j := bytes.Index(data[i:], newlineMarker)
		if j < 0 {
			return fixNL(data), "", nil
		}
		i += j + 1 // the newline stays with the preceding section
	}
}

// isMarker reports the name when data begins with a marker line.
// An empty name is not a marker.
func isMarker(data []byte) (name string, after []byte) {
	if !bytes.HasPrefix(data, marker) {
		return "", nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		data, after = data[:i], data[i+1:]
		if data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	if len(data) < len(marker)+len(markerEnd) || !bytes.HasSuffix(data, markerEnd) {
		return "", nil
	}
	name = strings.TrimSpace(string(data[len(marker) : len(data)-len(markerEnd)]))
	if name == "" {
		return "", nil
	}
	return name, after
}

// fixNL returns data unchanged when it is empty or already ends in '\n'.
func fixNL(data []byte) []byte {
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return data
	}
	out := make([]byte, len(data)+1)
	copy(out, data)
	out[len(data)] = '\n'
	return out
}
