package shellcmd

import "strings"

// subst stands in a word for a command substitution, so $(echo cur)l
// is never read as curl.
const subst = "\x00"

// token is one word, with quotes removed, or one operator.
type token struct {
	word string
	op   string
}

// Operators. opRedirect means the next word is a redirection target.
const (
	opPipe     = "|"
	opSep      = ";"
	opOpen     = "("
	opRedirect = "<"
)

// lex splits src into words and operators the way a POSIX shell does,
// which is also how cmd.exe and PowerShell split | && || ; & and ( ).
// It returns the text of every $( ), backtick, and <( ) substitution
// separately: each is a command line of its own.
//
// A backslash escapes only a character the shell treats specially, so
// C:\Tools\curl.exe keeps its path separators. With ps set the text is
// PowerShell, where a backtick escapes the next character instead of
// starting a substitution: I`E`X is IEX.
func lex(src string, ps bool) (toks []token, subs []string) {
	toks = make([]token, 0, 8+len(src)/4)
	var b strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			toks = append(toks, token{word: b.String()})
			b.Reset()
			inWord = false
		}
	}
	op := func(o string) {
		flush()
		toks = append(toks, token{op: o})
	}
	for i := 0; i < len(src); {
		c := src[i]
		next := byte(0)
		if i+1 < len(src) {
			next = src[i+1]
		}
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			flush()
			i++
		case c == '\n':
			op(opSep)
			i++
		case c == '#' && !inWord:
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '\'':
			inWord = true
			end := strings.IndexByte(src[i+1:], '\'')
			if end < 0 {
				b.WriteString(src[i+1:])
				i = len(src)
			} else {
				b.WriteString(src[i+1 : i+1+end])
				i += end + 2
			}
		case c == '"':
			inWord = true
			i = lexDouble(src, i+1, ps, &b, &subs)
		case c == '`' && ps:
			inWord = true
			i = psEscape(src, i, &b)
		case c == '\\':
			inWord = true
			switch {
			case next == '\n':
				i += 2
			case next != 0 && strings.IndexByte(" \t'\"\\$`|&;<>()#*?[]{}~!", next) >= 0:
				b.WriteByte(next)
				i += 2
			default:
				b.WriteByte(c)
				i++
			}
		case c == '$' && next == '(':
			inWord = true
			end := closeParen(src, i+2)
			subs = append(subs, src[i+2:end])
			b.WriteString(subst)
			i = end + 1
		case c == '$' && next == '{':
			inWord = true
			end := strings.IndexByte(src[i:], '}')
			if end < 0 {
				end = len(src) - i - 1
			}
			b.WriteString(src[i : i+end+1])
			i += end + 1
		case c == '`':
			inWord = true
			end := strings.IndexByte(src[i+1:], '`')
			if end < 0 {
				b.WriteByte(c)
				i++
			} else {
				subs = append(subs, src[i+1:i+1+end])
				b.WriteString(subst)
				i += end + 2
			}
		case (c == '<' || c == '>') && next == '(':
			inWord = true
			end := closeParen(src, i+2)
			subs = append(subs, src[i+2:end])
			b.WriteString(subst)
			i = end + 1
		case c == '<' || c == '>' || (c == '&' && next == '>'):
			// An fd number written against the operator belongs to it (2>&1).
			if inWord && allDigits(b.String()) {
				b.Reset()
				inWord = false
			}
			flush()
			i++
			for i < len(src) && (src[i] == '<' || src[i] == '>') {
				i++
			}
			if i < len(src) && src[i] == '&' {
				i++
				for i < len(src) && (isDigit(src[i]) || src[i] == '-') {
					i++
				}
				continue
			}
			toks = append(toks, token{op: opRedirect})
		case c == '|':
			if next == '|' {
				op("||")
				i += 2
			} else {
				op(opPipe)
				i++
				if next == '&' {
					i++
				}
			}
		case c == '&':
			if next == '&' {
				op("&&")
				i += 2
			} else {
				op("&")
				i++
			}
		case c == ';':
			op(opSep)
			i++
		case c == '(':
			op(opOpen)
			i++
		case c == ')':
			op(")")
			i++
		default:
			j := i + 1
			for j < len(src) && !special(src[j]) {
				j++
			}
			// A word with no quoting is a slice of src, which keeps a
			// long unquoted command from being copied byte by byte.
			if !inWord && (j == len(src) || endsWord(src[j])) {
				toks = append(toks, token{word: src[i:j]})
			} else {
				inWord = true
				b.WriteString(src[i:j])
			}
			i = j
		}
	}
	flush()
	return toks, subs
}

// special reports whether lex handles c other than as a word byte.
func special(c byte) bool {
	return strings.IndexByte(" \t\r\n'\"\\$`<>|&;()", c) >= 0
}

// endsWord reports whether c ends a word without joining a redirect to
// it, so an fd number such as the 2 in 2>&1 is not emitted as a word.
func endsWord(c byte) bool {
	return strings.IndexByte(" \t\r\n|&;()", c) >= 0
}

// lexDouble reads a double-quoted string starting at i, just past the
// opening quote, and returns the index past the closing one.
func lexDouble(src string, i int, ps bool, b *strings.Builder, subs *[]string) int {
	for i < len(src) {
		c := src[i]
		switch {
		case c == '"':
			return i + 1
		case c == '\\' && i+1 < len(src) && strings.IndexByte("\"\\$`\n", src[i+1]) >= 0:
			if src[i+1] != '\n' {
				b.WriteByte(src[i+1])
			}
			i += 2
		case c == '$' && i+1 < len(src) && src[i+1] == '(':
			end := closeParen(src, i+2)
			*subs = append(*subs, src[i+2:end])
			b.WriteString(subst)
			i = end + 1
		case c == '`' && ps:
			i = psEscape(src, i, b)
		case c == '`':
			end := strings.IndexByte(src[i+1:], '`')
			if end < 0 {
				b.WriteByte(c)
				i++
				continue
			}
			*subs = append(*subs, src[i+1:i+1+end])
			b.WriteString(subst)
			i += end + 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return i
}

// psEscape writes the character a PowerShell backtick at i escapes and
// returns the index past it. A backtick before a newline continues the
// line.
func psEscape(src string, i int, b *strings.Builder) int {
	switch {
	case i+1 >= len(src):
		b.WriteByte('`')
		return i + 1
	case src[i+1] != '\n':
		b.WriteByte(src[i+1])
	}
	return i + 2
}

// closeParen returns the index of the ')' that closes a '(' just before
// i, skipping quoted text, or len(src) when there is none.
func closeParen(src string, i int) int {
	depth := 1
	for i < len(src) {
		switch src[i] {
		case '\\':
			i += 2
			continue
		case '\'':
			end := strings.IndexByte(src[i+1:], '\'')
			if end < 0 {
				return len(src)
			}
			i += end + 2
			continue
		case '"':
			i++
			for i < len(src) && src[i] != '"' {
				if src[i] == '\\' {
					i++
				}
				i++
			}
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
	return len(src)
}

// command is one simple command. pipeIn is set when its standard input
// is the previous command's output. stmt numbers the statement it is in:
// a statement runs to ;, &&, ||, &, or a newline, so the commands of
// curl x | sh and of iex (iwr x) share one.
type command struct {
	words  []string
	pipeIn bool
	stmt   int
}

// split groups tokens into simple commands and drops redirection
// targets.
func split(toks []token) []command {
	var cmds []command
	// Every command's words are a window of one array.
	all := make([]string, 0, len(toks))
	start := 0
	var cur command
	dropNext := false
	stmt := 0
	end := func(pipeIn bool) {
		if len(all) > start {
			cur.words = all[start:len(all):len(all)]
			cmds = append(cmds, cur)
		}
		start = len(all)
		cur = command{pipeIn: pipeIn, stmt: stmt}
	}
	for _, t := range toks {
		switch t.op {
		case "":
			if dropNext {
				dropNext = false
				continue
			}
			all = append(all, t.word)
		case opRedirect:
			dropNext = true
		case opPipe:
			end(true)
		case opOpen:
			// curl ... | (sh) still pipes into sh.
			end(cur.pipeIn && len(all) == start)
		case ")":
			end(false)
		default:
			stmt++
			end(false)
		}
	}
	end(false)
	return cmds
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
