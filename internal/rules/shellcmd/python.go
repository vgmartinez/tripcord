package shellcmd

import "strings"

// pythonShellCall is a function a python -c payload uses to run a command.
// shell is set when a string argument is always a shell command
// (os.system, os.popen, getoutput). The others run a string through a
// shell only with shell=True, and run a list of strings as an argv.
type pythonShellCall struct {
	name  string
	shell bool
}

// Longer names come first so os.system is not also read as system, and
// subprocess.check_call is not also read as call.
var pythonShellCalls = []pythonShellCall{
	{"subprocess.getstatusoutput", true},
	{"subprocess.getoutput", true},
	{"commands.getstatusoutput", true},
	{"commands.getoutput", true},
	{"subprocess.check_output", false},
	{"subprocess.check_call", false},
	{"os.system", true},
	{"os.popen", true},
	{"subprocess.Popen", false},
	{"subprocess.run", false},
	{"subprocess.call", false},
	{"getstatusoutput", true},
	{"check_output", false},
	{"check_call", false},
	{"getoutput", true},
	{"system", true},
	{"popen", true},
	{"Popen", false},
	{"run", false},
	{"call", false},
}

// pythonShellPayloads returns the shell command lines and argv vectors
// that code hands to a runner. A string inside print, or a subprocess
// string without shell=True, is not one: it is not executed as a shell
// command. An f-string that interpolates is not static and is skipped.
func pythonShellPayloads(code string) (lines []string, argvs [][]string) {
	for i := 0; i < len(code); {
		if next, ok := skipPyString(code, i); ok {
			i = next
			continue
		}
		if code[i] == '#' {
			i = skipPyComment(code, i)
			continue
		}
		call, open, ok := pyCallAt(code, i)
		if !ok {
			i++
			continue
		}
		end := pyMatchingParen(code, open)
		if end < 0 {
			i = open + 1
			continue
		}
		span := code[open+1 : end]
		line, argv := pyFirstCommand(span)
		shell := call.shell || pyShellTrue(span)
		switch {
		case shell && line != "":
			lines = append(lines, line)
		case shell && argv != nil:
			lines = append(lines, strings.Join(argv, " "))
		case shell:
			if extra := firstPyString(span); extra != "" {
				lines = append(lines, extra)
			}
		case argv != nil:
			argvs = append(argvs, argv)
		}
		i = end + 1
	}
	return lines, argvs
}

func pyCallAt(code string, i int) (pythonShellCall, int, bool) {
	if i > 0 && isPyIdent(code[i-1]) {
		return pythonShellCall{}, 0, false
	}
	best := -1
	var chosen pythonShellCall
	for _, call := range pythonShellCalls {
		if len(call.name) <= best || !strings.HasPrefix(code[i:], call.name) {
			continue
		}
		end := i + len(call.name)
		if end < len(code) && isPyIdent(code[end]) {
			continue
		}
		best = len(call.name)
		chosen = call
	}
	if best < 0 {
		return pythonShellCall{}, 0, false
	}
	j := i + best
	for j < len(code) && (code[j] == ' ' || code[j] == '\t' || code[j] == '\n' || code[j] == '\r') {
		j++
	}
	if j >= len(code) || code[j] != '(' {
		return pythonShellCall{}, 0, false
	}
	return chosen, j, true
}

func pyMatchingParen(code string, open int) int {
	depth := 0
	for i := open; i < len(code); {
		if next, ok := skipPyString(code, i); ok {
			i = next
			continue
		}
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

// pyFirstCommand reads the first argument of a call span (the text
// between the parentheses). A string is a shell line. A list of strings
// is an argv. Anything else is not static.
func pyFirstCommand(span string) (line string, argv []string) {
	i := skipPySpace(span, 0)
	if i >= len(span) {
		return "", nil
	}
	if value, _, ok := pyString(span, i); ok {
		if pyFormatted(span, i) {
			return "", nil
		}
		return value, nil
	}
	if span[i] != '[' {
		return "", nil
	}
	list, _, ok := pyStringList(span, i)
	if !ok {
		return "", nil
	}
	return "", list
}

func firstPyString(span string) string {
	for i := 0; i < len(span); {
		if value, next, ok := pyString(span, i); ok {
			if pyFormatted(span, i) {
				i = next
				continue
			}
			return value
		}
		i++
	}
	return ""
}

// pyShellTrue reports shell=True or shell=1 in a call span, outside a
// string. Python treats both as true.
func pyShellTrue(span string) bool {
	for i := 0; i < len(span); {
		if next, ok := skipPyString(span, i); ok {
			i = next
			continue
		}
		if span[i] == '#' {
			i = skipPyComment(span, i)
			continue
		}
		if (i > 0 && isPyIdent(span[i-1])) || !strings.HasPrefix(span[i:], "shell") {
			i++
			continue
		}
		j := i + len("shell")
		if j < len(span) && isPyIdent(span[j]) {
			i++
			continue
		}
		j = skipPySpace(span, j)
		if j >= len(span) || span[j] != '=' {
			i++
			continue
		}
		j = skipPySpace(span, j+1)
		switch {
		case strings.HasPrefix(span[j:], "True") && (j+len("True") == len(span) || !isPyIdent(span[j+len("True")])):
			return true
		case strings.HasPrefix(span[j:], "1") && (j+1 == len(span) || !isPyIdent(span[j+1])):
			return true
		}
		i++
	}
	return false
}

func pyStringList(code string, i int) ([]string, int, bool) {
	if i >= len(code) || code[i] != '[' {
		return nil, i, false
	}
	var out []string
	j := skipPySpace(code, i+1)
	if j < len(code) && code[j] == ']' {
		return []string{}, j + 1, true
	}
	for j < len(code) {
		value, next, ok := pyString(code, j)
		if !ok || pyFormatted(code, j) {
			return nil, i, false
		}
		out = append(out, value)
		j = skipPySpace(code, next)
		if j < len(code) && code[j] == ',' {
			j = skipPySpace(code, j+1)
			if j < len(code) && code[j] == ']' {
				return out, j + 1, true
			}
			continue
		}
		if j < len(code) && code[j] == ']' {
			return out, j + 1, true
		}
		return nil, i, false
	}
	return nil, i, false
}

// skipPyString advances past a string that starts at i, including a
// one-to-three letter prefix (r, f, b, u, and combinations).
func skipPyString(code string, i int) (int, bool) {
	_, next, ok := pyString(code, i)
	return next, ok
}

// pyFormatted reports an f-string prefix at i. An f-string that
// interpolates is not a static command.
func pyFormatted(code string, i int) bool {
	prefix, _ := pyStringPrefix(code, i)
	return strings.ContainsAny(prefix, "fF")
}

func pyString(code string, i int) (string, int, bool) {
	prefix, start := pyStringPrefix(code, i)
	if start < 0 || start >= len(code) {
		return "", i, false
	}
	quote := code[start]
	if quote != '\'' && quote != '"' {
		return "", i, false
	}
	triple := start+2 < len(code) && code[start+1] == quote && code[start+2] == quote
	raw := strings.ContainsAny(prefix, "rR")
	var b strings.Builder
	j := start + 1
	if triple {
		j = start + 3
	}
	for j < len(code) {
		if !raw && code[j] == '\\' && j+1 < len(code) {
			b.WriteString(pyEscape(code[j+1]))
			j += 2
			continue
		}
		if triple && j+2 < len(code) && code[j] == quote && code[j+1] == quote && code[j+2] == quote {
			return b.String(), j + 3, true
		}
		if !triple && code[j] == quote {
			return b.String(), j + 1, true
		}
		b.WriteByte(code[j])
		j++
	}
	return "", i, false
}

// pyStringPrefix returns the prefix and the index of the opening quote
// when a string starts at i. The quote itself has an empty prefix.
func pyStringPrefix(code string, i int) (string, int) {
	if i > 0 && isPyIdent(code[i-1]) {
		return "", -1
	}
	j := i
	for n := 0; n < 3 && j < len(code) && strings.ContainsRune("rRfFbBuU", rune(code[j])); n++ {
		j++
	}
	if j < len(code) && (code[j] == '\'' || code[j] == '"') && (j == i || pyPrefixOK(code[i:j])) {
		return code[i:j], j
	}
	if i < len(code) && (code[i] == '\'' || code[i] == '"') {
		return "", i
	}
	return "", -1
}

func pyPrefixOK(prefix string) bool {
	seen := map[byte]bool{}
	for k := 0; k < len(prefix); k++ {
		c := prefix[k] | 0x20
		if c != 'r' && c != 'f' && c != 'b' && c != 'u' {
			return false
		}
		if seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

func pyEscape(c byte) string {
	switch c {
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case '\\', '\'', '"':
		return string(c)
	default:
		return string(c)
	}
}

func skipPyComment(code string, i int) int {
	for i < len(code) && code[i] != '\n' {
		i++
	}
	return i
}

func skipPySpace(code string, i int) int {
	for i < len(code) && (code[i] == ' ' || code[i] == '\t' || code[i] == '\n' || code[i] == '\r') {
		i++
	}
	return i
}

func isPyIdent(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
