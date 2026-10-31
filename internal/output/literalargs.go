package output

import (
	"sort"
	"strings"
)

// literalTextFlags are, per tool, the flags whose argument is literal
// text (a commit message, a search pattern, an issue title) rather than
// a command line or a config line: a credential-looking key or flag
// inside it, as in git commit -m 'fix token: handling' or
// grep -e --token file, is that text, not a secret. This is the only
// exception to redacting a credential-named "key: value" anywhere, and
// it is per tool: echo -e 'token: X' is redacted.
var literalTextFlags = map[string][]string{
	"git":  {"-m", "--message", "--grep"},
	"grep": {"-e"},
	"rg":   {"-e"},
	"sed":  {"-e"},
	"awk":  {"-e", "-F"},
	"gh":   {"--title", "--body"},
}

// literalSpans are the byte ranges of value that are the argument of a
// literalTextFlags flag, sorted and disjoint.
type literalSpans [][2]int

// findLiteralSpans splits value into quote-aware shell words, one pass:
// a quoted run ('...' or "..." with \ escapes) belongs to its word even
// across whitespace, and ;, |, &, and newline outside quotes end a
// command segment. In a segment, a word naming a literalTextFlags tool
// (normalizeToolWord, so /usr/bin/git, sudo git, and git.exe count)
// activates its flags for the words after it; the argument of one is the
// next word ("-m 'msg'"), the text after "=" ("--message=msg"), or the
// text glued to a two-byte short flag ("-mmsg").
func findLiteralSpans(value string) literalSpans {
	if !mentionsLiteralTool(value) {
		return nil
	}
	var spans literalSpans
	tool, prev := "", ""
	commandWord := true
	pending := false
	for i := 0; i < len(value); {
		c := value[i]
		switch {
		case c == ';' || c == '|' || c == '&' || c == '\n':
			tool, prev, pending = "", "", false
			commandWord = true
			i++
			continue
		case isCommandSpace(c):
			i++
			continue
		}
		start := i
		i = shellWordEnd(value, i)
		text := value[start:i]
		switch {
		case pending:
			// Shell substitutions execute a new command; they are not
			// literal message or pattern text and must still be scanned.
			if !strings.ContainsAny(text, "`") && !strings.Contains(text, "$(") && !strings.Contains(text, "${") {
				spans = append(spans, [2]int{start, i})
			}
			pending = false
		case tool != "":
			pending = literalFlagArgument(&spans, tool, text, start, i)
		}
		if commandWord {
			name := toolWordName(prev, text)
			switch name {
			case "sudo", "env", "command":
				// These wrappers leave the next executable in command
				// position. env assignments do too.
			case "git", "grep", "rg", "sed", "awk":
				tool = name
				commandWord = false
			case "gh":
				tool = "gh-subcommand"
				commandWord = false
			default:
				commandWord = false
			}
		} else if tool == "gh-subcommand" {
			switch strings.Trim(text, `"'`) {
			case "pr", "issue", "release":
				tool = "gh"
			default:
				tool = ""
			}
		}
		prev = text
	}
	return spans
}

// mentionsLiteralTool reports whether value contains a literalTextFlags
// tool name in any case, which every word naming one must.
func mentionsLiteralTool(value string) bool {
	lower := strings.ToLower(value)
	for tool := range literalTextFlags {
		if strings.Contains(lower, tool) {
			return true
		}
	}
	return false
}

// literalFlagArgument records the argument glued to text when text is a
// literalTextFlags flag of tool with its argument attached, and reports
// whether text is such a flag on its own, so the next word is the
// argument.
func literalFlagArgument(spans *literalSpans, tool, text string, start, end int) bool {
	for _, flag := range literalTextFlags[tool] {
		switch {
		case text == flag:
			return true
		case strings.HasPrefix(text, flag+"="):
			*spans = append(*spans, [2]int{start + len(flag) + 1, end})
			return false
		case len(flag) == 2 && strings.HasPrefix(text, flag):
			*spans = append(*spans, [2]int{start + len(flag), end})
			return false
		}
	}
	return false
}

// shellWordEnd returns the end of the shell word starting at i: it runs
// to unquoted whitespace or one of ;|&, and a quote that never closes
// runs to the end of value.
func shellWordEnd(value string, i int) int {
	for i < len(value) {
		switch c := value[i]; {
		case c == '\'':
			j := strings.IndexByte(value[i+1:], '\'')
			if j < 0 {
				return len(value)
			}
			i += j + 2
		case c == '"':
			i++
			for i < len(value) && value[i] != '"' {
				if value[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(value) {
				return len(value)
			}
			i++
		case isCommandSpace(c) || c == ';' || c == '|' || c == '&':
			return i
		default:
			i++
		}
	}
	return i
}

// contains reports whether offset falls inside one of the spans.
func (s literalSpans) contains(offset int) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i][1] > offset })
	return i < len(s) && s[i][0] <= offset
}
