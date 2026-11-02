package prcontext

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
)

// maxToolsPerNote bounds the attacker-controlled tool ids retained from one
// git-ai note.
const maxToolsPerNote = 16

// toolsFromNote returns the git-ai agent tool names recorded in a
// refs/notes/ai authorship log (spec authorship/3.0.0). Sessions and
// legacy prompt records both count. A log that names only humans returns
// no tools and no error. An unreadable note returns an error so the
// caller can warn and continue.
func toolsFromNote(note string) ([]string, error) {
	tools, _, err := toolsFromNoteReader(strings.NewReader(note))
	return tools, err
}

// toolsFromNoteReader parses an authorship note without retaining its text.
// Only the small tool ids that Detection needs escape this function.
func toolsFromNoteReader(r io.Reader) ([]string, bool, error) {
	meta, err := noteMetadataReader(bufio.NewReader(r))
	if err != nil {
		return nil, false, err
	}
	var doc struct {
		Sessions map[string]noteRecord `json:"sessions"`
		Prompts  map[string]noteRecord `json:"prompts"`
	}
	dec := json.NewDecoder(meta)
	if err := dec.Decode(&doc); err != nil {
		return nil, false, errNotAuthorshipLog
	}
	// Trailing non-whitespace means this was not the metadata object.
	var extra any
	if err := dec.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return nil, false, errNotAuthorshipLog
	}
	seen := map[string]bool{}
	var tools []string
	limited := false
	add := func(records map[string]noteRecord) {
		keys := make([]string, 0, len(records))
		for key := range records {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			tool := strings.TrimSpace(records[key].AgentID.Tool)
			if !validTool(tool) || seen[strings.ToLower(tool)] {
				continue
			}
			seen[strings.ToLower(tool)] = true
			if len(tools) == maxToolsPerNote {
				limited = true
				continue
			}
			tools = append(tools, tool)
		}
	}
	add(doc.Sessions)
	add(doc.Prompts)
	slices.SortFunc(tools, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return tools, limited, nil
}

type noteRecord struct {
	AgentID struct {
		Tool string `json:"tool"`
	} `json:"agent_id"`
}

// errNotAuthorshipLog is an unreadable refs/notes/ai note. It is not a
// failure of pr-context: the note is skipped and a warning is reported.
var errNotAuthorshipLog = errNote("authorship note was not a git-ai authorship log")

type errNote string

func (e errNote) Error() string { return string(e) }

// noteMetadataReader returns a reader positioned at the JSON section of a
// git-ai log. The prefix is read one bounded line at a time: notes may be
// attacker-controlled, so an unterminated prefix line cannot allocate
// arbitrarily while we look for the "---" divider.
func noteMetadataReader(r *bufio.Reader) (io.Reader, error) {
	for {
		line, tooLong, err := readNoteLine(r, 64<<10)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if len(bytes.TrimSpace(line)) > 0 {
			trimmed := bytes.TrimSpace(line)
			if trimmed[0] == '{' {
				return io.MultiReader(bytes.NewReader(line), r), nil
			}
		}
		if !tooLong && string(bytes.TrimRight(line, "\r\n")) == "---" {
			return r, nil
		}
		if err != nil {
			return nil, errNotAuthorshipLog
		}
	}
}

// readNoteLine returns at most keep bytes of one line while still consuming
// that whole line. It reports a line that exceeded keep separately.
func readNoteLine(r *bufio.Reader, keep int) ([]byte, bool, error) {
	var line bytes.Buffer
	tooLong := false
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return line.Bytes(), tooLong, io.EOF
			}
			return nil, false, err
		}
		if line.Len() < keep {
			line.WriteByte(b)
		} else {
			tooLong = true
		}
		if b == '\n' {
			return line.Bytes(), tooLong, nil
		}
	}
}

func validTool(tool string) bool {
	if tool == "" || len(tool) > 64 {
		return false
	}
	for i, r := range tool {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case i > 0 && (r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '+'):
		default:
			return false
		}
	}
	return true
}

// oneLine collapses whitespace so a signal value stays on one text line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\x00", "")), " ")
}
