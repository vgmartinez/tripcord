package prcontext

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
)

// toolsFromNote returns the git-ai agent tool names recorded in a
// refs/notes/ai authorship log (spec authorship/3.0.0). Sessions and
// legacy prompt records both count. A log that names only humans returns
// no tools and no error. An unreadable note returns an error so the
// caller can warn and continue.
func toolsFromNote(note string) ([]string, error) {
	meta := noteMetadata(note)
	if strings.TrimSpace(meta) == "" {
		return nil, errNotAuthorshipLog
	}
	var doc struct {
		Sessions map[string]noteRecord `json:"sessions"`
		Prompts  map[string]noteRecord `json:"prompts"`
	}
	dec := json.NewDecoder(strings.NewReader(meta))
	if err := dec.Decode(&doc); err != nil {
		return nil, errNotAuthorshipLog
	}
	// Trailing non-whitespace means this was not the metadata object.
	var extra any
	if err := dec.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return nil, errNotAuthorshipLog
	}
	seen := map[string]bool{}
	var tools []string
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
			tools = append(tools, tool)
		}
	}
	add(doc.Sessions)
	add(doc.Prompts)
	slices.SortFunc(tools, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return tools, nil
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

// noteMetadata returns the JSON section of a git-ai log. The log is an
// attestation section, a line that is exactly "---", then JSON. A note
// that is only JSON (no divider) is accepted whole.
func noteMetadata(note string) string {
	lines := strings.Split(strings.ReplaceAll(note, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if line == "---" {
			return strings.Join(lines[i+1:], "\n")
		}
	}
	trimmed := strings.TrimSpace(note)
	if strings.HasPrefix(trimmed, "{") {
		return trimmed
	}
	return ""
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
