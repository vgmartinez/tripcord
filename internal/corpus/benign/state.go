package benign

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Cursor is the next code-search page for one harness.
type Cursor struct {
	Harness string
	Try     int
	Order   string
	Page    int
	Done    bool
}

// stateHeader is the only comment crawl.state may have.
const stateHeader = "# benign crawl cursor. Columns: harness, try, order, page, done.\n"

// FormatState renders the crawl cursor. Harnesses follow Harnesses order.
func FormatState(cursors []Cursor) ([]byte, error) {
	by := map[string]Cursor{}
	for _, c := range cursors {
		if !knownHarness(c.Harness) {
			return nil, fmt.Errorf("unknown harness %q", c.Harness)
		}
		if c.Order != "asc" && c.Order != "desc" {
			return nil, fmt.Errorf("%s: bad order %q", c.Harness, c.Order)
		}
		if c.Try < 0 || c.Page < 1 {
			return nil, fmt.Errorf("%s: bad cursor", c.Harness)
		}
		by[c.Harness] = c
	}
	var b strings.Builder
	b.WriteString(stateHeader)
	for _, h := range Harnesses {
		c, ok := by[h]
		if !ok {
			c = Cursor{Harness: h, Order: "desc", Page: 1}
		}
		done := "no"
		if c.Done {
			done = "yes"
		}
		fmt.Fprintf(&b, "%s\t%d\t%s\t%d\t%s\n", h, c.Try, c.Order, c.Page, done)
	}
	return []byte(b.String()), nil
}

// ParseState reads a crawl cursor. The header must be stateHeader.
func ParseState(data []byte) ([]Cursor, error) {
	if len(data) == 0 {
		return nil, nil
	}
	for i, line := range strings.Split(string(data), "\n") {
		if len(line) > maxLineBytes {
			return nil, fmt.Errorf("crawl.state:%d: line is %d bytes, limit %d", i+1, len(line), maxLineBytes)
		}
	}
	if bytes.Contains(data, []byte{'\r'}) {
		return nil, fmt.Errorf("crawl.state: carriage return")
	}
	if !bytes.HasPrefix(data, []byte(stateHeader)) {
		return nil, fmt.Errorf("crawl.state: header is not the generated header")
	}
	rest := string(data[len(stateHeader):])
	if rest == "" {
		return nil, fmt.Errorf("crawl.state: no rows")
	}
	lines := strings.Split(rest, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != len(Harnesses) {
		return nil, fmt.Errorf("crawl.state: %d rows, want %d", len(lines), len(Harnesses))
	}
	out := make([]Cursor, 0, len(lines))
	for i, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			return nil, fmt.Errorf("crawl.state:%d: comment or blank line outside the header", i+1)
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			return nil, fmt.Errorf("crawl.state:%d: %d columns, want 5", i+1, len(fields))
		}
		if fields[0] != Harnesses[i] {
			return nil, fmt.Errorf("crawl.state:%d: harness %s, want %s", i+1, fields[0], Harnesses[i])
		}
		tryN, err := strconv.Atoi(fields[1])
		if err != nil || tryN < 0 {
			return nil, fmt.Errorf("crawl.state:%d: bad try", i+1)
		}
		if fields[2] != "asc" && fields[2] != "desc" {
			return nil, fmt.Errorf("crawl.state:%d: bad order", i+1)
		}
		page, err := strconv.Atoi(fields[3])
		if err != nil || page < 1 {
			return nil, fmt.Errorf("crawl.state:%d: bad page", i+1)
		}
		var done bool
		switch fields[4] {
		case "yes":
			done = true
		case "no":
			done = false
		default:
			return nil, fmt.Errorf("crawl.state:%d: bad done", i+1)
		}
		out = append(out, Cursor{Harness: fields[0], Try: tryN, Order: fields[2], Page: page, Done: done})
	}
	return out, nil
}
