// Package jsonc turns VS Code JSONC into strict JSON.
//
// Adapters that accept comments and trailing commas (devcontainer,
// Windsurf, Gemini, VS Code tasks, and the rest of the kit) share
// Strip. The bytes keep their offsets: a comment or a trailing comma
// becomes spaces, and a newline inside a block comment stays a newline.
package jsonc

import (
	"bytes"
	"errors"
)

// Strip blanks // and /* */ comments and trailing commas outside
// strings, so the result is strict JSON with the same meaning. An
// unterminated block comment is an error. A leading byte order mark is
// left in place; callers that accept JSONC remove it first.
func Strip(raw []byte) ([]byte, error) {
	out := bytes.Clone(raw)
	inString := false
	lastComma := -1
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inString {
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			lastComma = -1
		case c == '/' && i+1 < len(out) && out[i+1] == '/':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			end := bytes.Index(out[i+2:], []byte("*/"))
			if end < 0 {
				return nil, errors.New("unterminated block comment")
			}
			for j := i; j < i+2+end+2; j++ {
				if out[j] != '\n' {
					out[j] = ' '
				}
			}
			i += 2 + end + 1
		case c == ',':
			lastComma = i
		case c == '}' || c == ']':
			if lastComma >= 0 {
				out[lastComma] = ' '
			}
			lastComma = -1
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			lastComma = -1
		}
	}
	return out, nil
}
