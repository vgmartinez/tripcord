package output

import (
	"sort"
	"strings"
)

// escapedQuoteSpans are the shell-escaped quoted values in a string: a
// \" through the next \", not crossing a newline. echo "token: \"X\""
// holds the secret inside one of these. quotedValue starts at a real
// quote, so it stops at the " of \" and the bytes after it stay. The
// spans are found in one forward pass and looked up by the value's
// start, which keeps a line of candidates linear. A regexp alternative
// that rescans each miss to the end of the line does not.
type escapedQuoteSpans [][2]int

func indexEscapedQuotes(value string) escapedQuoteSpans {
	if !strings.Contains(value, `\"`) {
		return nil
	}
	var spans escapedQuoteSpans
	i := 0
	for i+1 < len(value) {
		if value[i] != '\\' || value[i+1] != '"' {
			i++
			continue
		}
		start := i
		j := i + 2
		closed := false
		for j+1 < len(value) && value[j] != '\n' {
			if value[j] == '\\' && value[j+1] == '"' {
				spans = append(spans, [2]int{start, j + 2})
				i = j + 2
				closed = true
				break
			}
			j++
		}
		if closed {
			continue
		}
		// No closer before the newline. Skip the rest of this line so
		// the opener is not tried again.
		if j < len(value) && value[j] == '\n' {
			i = j
			continue
		}
		i = len(value)
	}
	return spans
}

// at reports the escaped-quoted value that starts at pos.
func (s escapedQuoteSpans) at(value string, pos int) (string, bool) {
	i := sort.Search(len(s), func(i int) bool { return s[i][0] >= pos })
	if i >= len(s) || s[i][0] != pos {
		return "", false
	}
	return value[pos:s[i][1]], true
}

// unescapeShellQuotes strips one \"...\" wrapper. ok is false when body
// is not that wrapper.
func unescapeShellQuotes(body string) (string, bool) {
	if len(body) >= 4 && strings.HasPrefix(body, `\"`) && strings.HasSuffix(body, `\"`) {
		return body[2 : len(body)-2], true
	}
	return "", false
}
