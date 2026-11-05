package shellcmd

import "strings"

// MCP is the command line TC-CFG-003 judges. A POSIX shell -c or cmd
// /c, /k, or /r (a path or .exe, a flag cluster such as -lc, and cmd
// /s /c) whose payload is one simple command is replaced by that
// command. The replacement is read again, up to maxDepth, so bash -c
// 'bash -c "npx pkg"' becomes npx. env, sudo, exec, command, and
// assignments are dropped first, the same way unwrap drops them for
// shell.risks.
//
// A simple command is one program and its arguments, or cd <dir> &&
// that command. The program token has to be a literal bare word or
// path. The payload is not unwrapped when it contains $, %, a
// backtick, or ^, or, for cmd, when &, |, <, or > remains after quote
// characters are removed. A pipe, redirection, $(...), <(...),
// semicolon, ||, background &, more than one &&, an && that is not cd,
// or a downloader is not simple either: the wrapper is left in place,
// so the shell still matches. A shell whose first operand is a script
// file (bash script.sh, with no -c) is not rewritten.
func MCP(argv []string) string {
	return mcpReduce(argv, 0)
}

func mcpReduce(argv []string, depth int) string {
	joined := strings.Join(argv, " ")
	if depth > maxDepth || len(argv) == 0 || argvHasOpaque(argv) {
		return joined
	}
	// A command stored as one string ("sh -c 'npx pkg'") is the same
	// wrapper as an argv. Only a line with no operators is split, and
	// only when it is a shell, so a pipe in the command string is left
	// for shell.risks.
	if len(argv) == 1 {
		if words, ok := shellWords(argv[0]); ok {
			return mcpReduce(words, depth)
		}
	}
	w := unwrap(argv)
	if len(w) == 0 {
		return joined
	}
	name, args := progName(w[0]), w[1:]
	var payload string
	var ok bool
	switch {
	case posixShells[name]:
		var rest int
		payload, rest, ok = shellPayloadAt(name, args)
		ok = ok && rest == 0
	case name == "cmd":
		payload, ok = cmdPayload(args)
	default:
		return joined
	}
	// A shell we did not reduce stays visible after env, sudo, and exec
	// are dropped, so `env bash -c "curl | sh"` still starts with bash.
	// A program that is not a shell was returned above, unchanged, so
	// `sudo node -e` is still `sudo node -e`.
	if !ok || !unwrapPayload(payload, name == "cmd") {
		return strings.Join(w, " ")
	}
	inner, simple := simpleInner(payload)
	if !simple || !literalProgram(inner[0]) {
		return strings.Join(w, " ")
	}
	return mcpReduce(inner, depth+1)
}

// MCPWork is the byte charge for judging argv. The line may be read once
// per nesting level MCP follows.
func MCPWork(argv []string) int {
	n := 0
	for _, a := range argv {
		n += len(a) + 1
	}
	return n * (maxDepth + 1)
}

// shellWords splits a one-string command into words when those words are
// a shell wrapper and the line has no pipe, separator, or substitution.
func shellWords(line string) ([]string, bool) {
	toks, subs := lex(line, false)
	if len(subs) > 0 || len(toks) < 2 {
		return nil, false
	}
	words := make([]string, 0, len(toks))
	for _, t := range toks {
		if t.op != "" || strings.Contains(t.word, subst) {
			return nil, false
		}
		words = append(words, t.word)
	}
	w := unwrap(words)
	if len(w) == 0 {
		return nil, false
	}
	name := progName(w[0])
	if !posixShells[name] && name != "cmd" {
		return nil, false
	}
	return words, true
}

// unwrapPayload reports whether payload can be unwrapped. $, %, a
// backtick, or ^ stays wrapped: ANSI-C quotes, variables, and cmd's ^
// escape are not read as literal text. cmd also stays wrapped when
// &, |, <, or > remains after quotes are removed, quoted or not.
func unwrapPayload(payload string, cmd bool) bool {
	if strings.Contains(payload, "$") || strings.Contains(payload, "%") || strings.Contains(payload, "`") || strings.Contains(payload, "^") {
		return false
	}
	if cmd && strings.ContainsAny(stripQuotes(payload), "&|<>") {
		return false
	}
	return true
}

// stripQuotes drops quote characters and leaves everything they
// enclosed, so a quoted operator is still visible.
func stripQuotes(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\'' {
			return -1
		}
		return r
	}, s)
}

// literalProgram reports whether word is a bare command name or a path
// with no expansion. Letters, digits, and . _ + - : / \ are literal.
func literalProgram(word string) bool {
	if word == "" || word == "." || word == ".." || word[0] == '-' {
		return false
	}
	for i := 0; i < len(word); i++ {
		c := word[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '+' || c == '-' || c == ':' || c == '/' || c == '\\':
		default:
			return false
		}
	}
	return true
}

func argvHasOpaque(argv []string) bool {
	for _, a := range argv {
		if strings.Contains(a, "\x00") {
			return true
		}
	}
	return false
}

// simpleInner returns the words of payload when it is one simple
// command, including a leading cd <dir> &&. ok is false when the
// payload must stay wrapped.
func simpleInner(payload string) ([]string, bool) {
	if strings.TrimSpace(payload) == "" {
		return nil, false
	}
	toks, subs := lex(payload, false)
	if len(subs) > 0 {
		return nil, false
	}
	ands := 0
	for _, t := range toks {
		if strings.Contains(t.word, subst) {
			return nil, false
		}
		switch t.op {
		case "":
		case "&&":
			ands++
		default:
			return nil, false
		}
	}
	if ands > 1 {
		return nil, false
	}
	cmds := split(toks)
	for _, c := range cmds {
		if c.pipeIn || c.depth != 0 {
			return nil, false
		}
	}
	var words []string
	switch len(cmds) {
	case 1:
		if ands != 0 {
			return nil, false
		}
		words = cmds[0].words
	case 2:
		if ands != 1 || cmds[0].sep != "&&" || !isCD(cmds[0].words) {
			return nil, false
		}
		words = cmds[1].words
	default:
		return nil, false
	}
	words = unwrap(words)
	if len(words) == 0 || isMCPDownload(words[0]) {
		return nil, false
	}
	for _, w := range words {
		if strings.Contains(w, subst) {
			return nil, false
		}
	}
	switch progName(words[0]) {
	case "eval", "source", ".", "iex", "invoke-expression":
		return nil, false
	}
	return words, true
}

func isCD(words []string) bool {
	w := unwrap(words)
	if len(w) != 2 || progName(w[0]) != "cd" {
		return false
	}
	dir := w[1]
	return dir != "" && !strings.HasPrefix(dir, "-") && !strings.Contains(dir, subst)
}

func isMCPDownload(program string) bool {
	name := progName(program)
	return downloaderNames[name] || name == "nc" || name == "ncat"
}
