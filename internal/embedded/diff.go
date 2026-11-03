package embedded

import (
	"fmt"
	"strings"
)

// diffContext is the number of unchanged lines around each hunk.
const diffContext = 3

// maxDiffCells bounds the line-matching table; larger inputs diff as one
// hunk that replaces the whole file.
const maxDiffCells = 4 << 20

// UnifiedDiff renders c as a unified diff, or "" when it is unchanged.
func UnifiedDiff(c Change) string {
	if c.Unchanged() {
		return ""
	}
	from := "a/" + c.Path
	if c.Old == nil {
		from = "/dev/null"
	}
	a, b := splitLines(string(c.Old)), splitLines(string(c.New))
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ b/%s\n", from, c.Path)
	for _, h := range hunks(diffOps(a, b)) {
		fmt.Fprintf(&out, "@@ -%s +%s @@\n", hunkRange(h.aStart, h.aLen), hunkRange(h.bStart, h.bLen))
		for _, op := range h.ops {
			out.WriteString(string(op.kind) + op.line)
			if !strings.HasSuffix(op.line, "\n") {
				out.WriteString("\n\\ No newline at end of file\n")
			}
		}
	}
	return out.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

type diffOp struct {
	kind byte // ' ', '-', or '+'
	line string
}

// diffOps is a longest-common-subsequence edit script from a to b.
func diffOps(a, b []string) []diffOp {
	if len(a)*len(b) > maxDiffCells {
		ops := make([]diffOp, 0, len(a)+len(b))
		for _, l := range a {
			ops = append(ops, diffOp{'-', l})
		}
		for _, l := range b {
			ops = append(ops, diffOp{'+', l})
		}
		return ops
	}
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', b[j]})
	}
	return ops
}

type hunk struct {
	aStart, aLen, bStart, bLen int
	ops                        []diffOp
}

// hunks groups ops into hunks with diffContext lines of context.
func hunks(ops []diffOp) []hunk {
	var out []hunk
	aLine, bLine := 1, 1
	pos := make([][2]int, len(ops))
	for i, op := range ops {
		pos[i] = [2]int{aLine, bLine}
		if op.kind != '+' {
			aLine++
		}
		if op.kind != '-' {
			bLine++
		}
	}
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := max(0, i-diffContext)
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*diffContext {
				end = min(len(ops), end+diffContext)
				break
			}
			end = run
		}
		h := hunk{aStart: pos[start][0], bStart: pos[start][1], ops: ops[start:end]}
		for _, op := range h.ops {
			if op.kind != '+' {
				h.aLen++
			}
			if op.kind != '-' {
				h.bLen++
			}
		}
		if h.aLen == 0 {
			h.aStart--
		}
		if h.bLen == 0 {
			h.bStart--
		}
		out = append(out, h)
		i = end
	}
	return out
}

func hunkRange(start, n int) string {
	if n == 1 {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d,%d", start, n)
}
