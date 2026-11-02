package shellcmd

import "strings"

// Words returns the words of the first simple command in line, with
// quotes removed and no expansions applied. ok is false when line is
// empty or a command substitution ($(...), backticks, or <(...)) would
// have to be expanded to know the words. An operator ends the command,
// so the words of a pipeline stop at the pipe.
func Words(line string) ([]string, bool) {
	toks, _ := lex(line, false)
	var words []string
	for _, t := range toks {
		if t.op != "" {
			break
		}
		if strings.Contains(t.word, subst) {
			return nil, false
		}
		words = append(words, t.word)
	}
	if len(words) == 0 {
		return nil, false
	}
	return words, true
}
