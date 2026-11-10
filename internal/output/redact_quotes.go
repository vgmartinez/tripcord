package output

import (
	"sort"
	"strings"
)

// escapedQuoteSpans are the shell-escaped quoted values in a string: an
// escaped quote through the next escaped quote, not crossing a newline.
// A quote is escaped only when an odd number of backslashes precedes it,
// so \" and \\\" open a value and \\" does not (the backslashes escape
// each other and the quote is real). The span starts at the first
// backslash of that odd run, which is where the value itself starts.
// echo "token: \"X\"" and echo "token: \\\"X\\\"" both hold the secret
// inside one of these. quotedValue starts at a real quote, so it stops
// at the " of \" and the bytes after it stay. The spans are found in one
// forward pass and looked up by the value's start, which keeps a line of
// candidates linear. A regexp alternative that rescans each miss to the
// end of the line does not.
type escapedQuoteSpans [][2]int

func indexEscapedQuotes(value string) escapedQuoteSpans {
	if !strings.Contains(value, `\"`) {
		return nil
	}
	var spans escapedQuoteSpans
	for i := 0; i < len(value); {
		if value[i] != '"' {
			i++
			continue
		}
		n := backslashRun(value, i)
		if n%2 == 0 {
			i++
			continue
		}
		start := i - n
		j := i + 1
		closed := false
		for j < len(value) && value[j] != '\n' {
			if value[j] == '"' && backslashRun(value, j)%2 == 1 {
				spans = append(spans, [2]int{start, j + 1})
				i = j + 1
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

// backslashRun counts the backslashes immediately before quote.
func backslashRun(value string, quote int) int {
	n := 0
	for j := quote - 1; j >= 0 && value[j] == '\\'; j-- {
		n++
	}
	return n
}

// at reports the escaped-quoted value that starts at pos.
func (s escapedQuoteSpans) at(value string, pos int) (string, bool) {
	i := sort.Search(len(s), func(i int) bool { return s[i][0] >= pos })
	if i >= len(s) || s[i][0] != pos {
		return "", false
	}
	return value[pos:s[i][1]], true
}

// escapedQuoteBounds reports the odd backslash runs around an escaped
// quoted value: \"X\" is 1 and 1, \\\"X\\\" is 3 and 3. ok is false when
// body is not that wrapper.
func escapedQuoteBounds(body string) (lead, trail int, ok bool) {
	if len(body) < 4 || body[0] != '\\' || body[len(body)-1] != '"' {
		return 0, 0, false
	}
	lead = backslashRun(body, strings.IndexByte(body, '"'))
	if lead%2 == 0 || lead >= len(body) || body[lead] != '"' {
		return 0, 0, false
	}
	trail = backslashRun(body, len(body)-1)
	if trail%2 == 0 || len(body)-1-trail <= lead {
		return 0, 0, false
	}
	return lead, trail, true
}

// unescapeShellQuotes strips one escaped-quote wrapper. ok is false when
// body is not that wrapper.
func unescapeShellQuotes(body string) (string, bool) {
	lead, trail, ok := escapedQuoteBounds(body)
	if !ok {
		return "", false
	}
	return body[lead+1 : len(body)-1-trail], true
}
