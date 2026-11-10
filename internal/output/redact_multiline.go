package output

import "strings"

// A "key: value" credential in YAML can carry its value past the end of
// the line it starts on: a quoted scalar that closes on a later line, a
// plain scalar or a quoted one followed by a more-indented line, and a
// key that sits in a comment whose header comment is followed by the
// value. colonValue reads only one line, so these helpers find the rest.

// keyStartsLine reports whether the key at start has nothing before it on
// its line but blanks and "- " list markers, as a YAML mapping key does.
// A key inside a shell command ("echo token: x") has other text first.
func keyStartsLine(value string, start int) bool {
	for i := start - 1; i >= 0; i-- {
		switch value[i] {
		case ' ', '\t', '-':
		case '\n':
			return true
		default:
			return false
		}
	}
	return true
}

// inCommentLine reports whether the first non-blank byte of the line that
// holds start is "#" and lies before start: the head is commented out.
func inCommentLine(value string, start int) bool {
	i := strings.LastIndexByte(value[:start], '\n') + 1
	for i < start && (value[i] == ' ' || value[i] == '\t') {
		i++
	}
	return i < start && value[i] == '#'
}

// opensQuote reports whether the value at valStart starts with a quote.
func opensQuote(value string, valStart int) bool {
	return valStart < len(value) && (value[valStart] == '"' || value[valStart] == '\'')
}

// multilineQuotedEnd returns the offset just past the quote that closes
// the quoted scalar opening at valStart, or -1 when none closes. A
// double-quoted scalar skips backslash escapes; a single-quoted one
// reads ” as an escaped quote, as YAML does.
func multilineQuotedEnd(value string, valStart int) int {
	quote := value[valStart]
	for i := valStart + 1; i < len(value); i++ {
		switch {
		case quote == '"' && value[i] == '\\':
			i++
		case value[i] == quote && quote == '\'' && i+1 < len(value) && value[i+1] == '\'':
			i++
		case value[i] == quote:
			return i + 1
		}
	}
	return -1
}

// multilineQuotedValue is the quoted value of a YAML key, read with
// YAML's quoting rules: through the closing quote, which may be on a
// later line, or, when none closes, the rest of the line.
func multilineQuotedValue(value string, valStart int) string {
	if end := multilineQuotedEnd(value, valStart); end >= 0 {
		return value[valStart:end]
	}
	return strings.TrimRight(value[valStart:lineEndAt(value, valStart)], " \t\r")
}

// lineEndAt returns the offset of the '\n' ending the line that holds
// pos, or len(value).
func lineEndAt(value string, pos int) int {
	if i := strings.IndexByte(value[pos:], '\n'); i >= 0 {
		return pos + i
	}
	return len(value)
}

// restIsBlankOrComment reports whether value[pos:] holds only blanks and
// an optional "#" comment up to the end of its line.
func restIsBlankOrComment(value string, pos int) bool {
	for pos < len(value) && (value[pos] == ' ' || value[pos] == '\t') {
		pos++
	}
	return pos >= len(value) || value[pos] == '#' || value[pos] == '\n' || value[pos] == '\r'
}

// valueContinuation returns the offsets of the more-indented lines that
// continue the value of the key h, whose first line's value ends at
// bodyEnd: next is the start of the line after that one and end is the
// offset past the last non-blank continuation line. ok is false when the
// key is not a line-leading YAML key, text other than a comment follows
// the value, or no more-indented line follows. keyIndent is the key's
// column, read from lines.
func valueContinuation(value string, h assignmentHead, bodyEnd int, lines *lineIndex) (next, end int, ok bool) {
	if !restIsBlankOrComment(value, bodyEnd) {
		return 0, 0, false
	}
	next = lineEndAt(value, bodyEnd) + 1
	if next >= len(value) {
		return 0, 0, false
	}
	end = blockBodyEnd(value, next, lines.column(h.start))
	for end > next && isBlankLineEnd(value, next, end) {
		end = previousLineStart(value, next, end)
	}
	if end <= next || !keyStartsLine(value, h.start) {
		return 0, 0, false
	}
	return next, end, true
}

// isBlankLineEnd reports whether the last line of value[from:to] is blank.
func isBlankLineEnd(value string, from, to int) bool {
	start := previousLineStart(value, from, to)
	return strings.TrimSpace(value[start:to]) == ""
}

// previousLineStart returns the start of the last line of value[from:to],
// where a trailing newline belongs to the line it ends.
func previousLineStart(value string, from, to int) int {
	i := to
	if i > from && value[i-1] == '\n' {
		i--
	}
	if j := strings.LastIndexByte(value[from:i], '\n'); j >= 0 {
		return from + j + 1
	}
	return from
}

// commentHeadBodyEnd is blockBodyEnd for a key that is itself inside a
// comment ("# token: # c" followed by the value): the commented-out key's
// real indentation is unknown, so the value is the first content line
// after the comments and the lines indented deeper than it.
func commentHeadBodyEnd(value string, bodyStart int) int {
	indent := 0
	for bodyStart+indent < len(value) && (value[bodyStart+indent] == ' ' || value[bodyStart+indent] == '\t') {
		indent++
	}
	first := lineEndAt(value, bodyStart)
	if first >= len(value) {
		return len(value)
	}
	return blockBodyEnd(value, first+1, indent)
}
