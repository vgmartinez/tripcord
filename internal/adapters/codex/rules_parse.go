package codex

// parseRulesFile parses a .rules file: a small Starlark subset Codex uses
// for its command exec policy (see
// https://developers.openai.com/codex/rules and
// https://github.com/openai/codex/blob/main/codex-rs/execpolicy/README.md).
// It never evaluates the file; it only recognizes a fixed grammar of
// top-level prefix_rule(...) and host_executable(...) calls built from
// string and list literals, and reports ok=false the moment it sees
// anything else, so the caller can fall back to treating the file as
// opaque instead of silently dropping or misinterpreting a construct
// this parser does not model (another call, a variable, string
// concatenation, a triple-quoted string, an unsupported escape, a
// decision other than "allow", "prompt", or "forbidden", ...).
//
// Grammar recognized (EBNF-ish):
//
//	file       = { call } ;
//	call       = ident "(" [ kwarg { "," kwarg } [ "," ] ] ")" ;
//	kwarg      = ident "=" value ;
//	value      = string | list ;
//	list       = "[" [ value { "," value } [ "," ] ] "]" ;
//
// "#" starts a line comment. The only calls are "prefix_rule" and
// "host_executable"; any other top-level call name, or any kwarg name
// the call does not define, makes the file opaque. maxRulesPerFile
// counts both kinds of call.
const (
	maxRulesTokens        = 200_000
	maxRulesNestingDepth  = 16
	maxRulesPerFile       = 512
	maxRulesTopLevelCalls = 1024
)

// rawPrefixRule is one parsed prefix_rule(...) call, before sanitization.
type rawPrefixRule struct {
	pattern       []any
	decision      string
	justification string
	match         []any
	notMatch      []any
}

// rawHostExecutable is one parsed host_executable(...) call: the
// absolute paths a basename rule for name may resolve through.
type rawHostExecutable struct {
	name  string
	paths []any
}

// parsedRules is a .rules file parsed by parseRulesFile.
type parsedRules struct {
	prefixRules     []rawPrefixRule
	hostExecutables []rawHostExecutable
}

var prefixRuleArgs = map[string]bool{
	"pattern": true, "decision": true, "justification": true,
	"match": true, "not_match": true,
}

// rulesDecisions are the decision values Codex documents. Any other
// spelling ("ALLOW", "deny") makes the file opaque rather than being
// normalized to a guess.
var rulesDecisions = map[string]bool{"allow": true, "prompt": true, "forbidden": true}

func parseRulesFile(raw []byte) (parsedRules, bool) {
	var out parsedRules
	toks, ok := lexRules(raw)
	if !ok || len(toks) > maxRulesTokens {
		return out, false
	}
	p := &rulesParser{toks: toks}
	calls := 0
	for !p.at(rtEOF) {
		calls++
		if calls > maxRulesTopLevelCalls {
			return out, false
		}
		if !p.at(rtIdent) {
			return out, false
		}
		name := p.cur().text
		p.pos++
		if !p.consume(rtLParen) {
			return out, false
		}
		args, ok := p.parseKwArgs()
		if !ok {
			return out, false
		}
		if !p.consume(rtRParen) {
			return out, false
		}
		switch name {
		case "prefix_rule":
			rule, ok := buildPrefixRule(args)
			if !ok {
				return out, false
			}
			out.prefixRules = append(out.prefixRules, rule)
		case "host_executable":
			host, ok := buildHostExecutable(args)
			if !ok {
				return out, false
			}
			out.hostExecutables = append(out.hostExecutables, host)
		default:
			return out, false
		}
		if len(out.prefixRules)+len(out.hostExecutables) > maxRulesPerFile {
			return out, false
		}
	}
	return out, true
}

// buildHostExecutable requires exactly a non-empty name string and a
// paths list of strings.
func buildHostExecutable(args map[string]any) (rawHostExecutable, bool) {
	if len(args) != 2 {
		return rawHostExecutable{}, false
	}
	name, ok := args["name"].(string)
	if !ok || name == "" {
		return rawHostExecutable{}, false
	}
	paths, ok := args["paths"].([]any)
	if !ok {
		return rawHostExecutable{}, false
	}
	for _, p := range paths {
		if _, ok := p.(string); !ok {
			return rawHostExecutable{}, false
		}
	}
	return rawHostExecutable{name: name, paths: paths}, true
}

func buildPrefixRule(args map[string]any) (rawPrefixRule, bool) {
	for name := range args {
		if !prefixRuleArgs[name] {
			return rawPrefixRule{}, false
		}
	}
	pattern, ok := args["pattern"].([]any)
	if !ok || len(pattern) == 0 {
		return rawPrefixRule{}, false
	}
	rule := rawPrefixRule{pattern: pattern, decision: "allow"}
	if v, present := args["decision"]; present {
		s, ok := v.(string)
		if !ok || !rulesDecisions[s] {
			return rawPrefixRule{}, false
		}
		rule.decision = s
	}
	if v, present := args["justification"]; present {
		s, ok := v.(string)
		if !ok {
			return rawPrefixRule{}, false
		}
		rule.justification = s
	}
	if v, present := args["match"]; present {
		list, ok := v.([]any)
		if !ok {
			return rawPrefixRule{}, false
		}
		rule.match = list
	}
	if v, present := args["not_match"]; present {
		list, ok := v.([]any)
		if !ok {
			return rawPrefixRule{}, false
		}
		rule.notMatch = list
	}
	return rule, true
}

// rulesParser walks a token stream produced by lexRules.
type rulesParser struct {
	toks []rulesToken
	pos  int
}

func (p *rulesParser) cur() rulesToken { return p.toks[p.pos] }

func (p *rulesParser) at(kind rulesTokenKind) bool { return p.cur().kind == kind }

func (p *rulesParser) consume(kind rulesTokenKind) bool {
	if !p.at(kind) {
		return false
	}
	p.pos++
	return true
}

// parseKwArgs parses a comma-separated "name = value" list up to (not
// consuming) the closing ")". A duplicate keyword, or anything other
// than "ident = value", fails.
func (p *rulesParser) parseKwArgs() (map[string]any, bool) {
	args := map[string]any{}
	for !p.at(rtRParen) {
		if !p.at(rtIdent) {
			return nil, false
		}
		name := p.cur().text
		p.pos++
		if !p.consume(rtEquals) {
			return nil, false
		}
		value, ok := p.parseValue(0)
		if !ok {
			return nil, false
		}
		if _, dup := args[name]; dup {
			return nil, false
		}
		args[name] = value
		if p.consume(rtComma) {
			continue
		}
		break
	}
	return args, true
}

// parseValue parses a string literal or a list literal, to depth levels
// of list nesting, which this grammar's only two value forms produce.
func (p *rulesParser) parseValue(depth int) (any, bool) {
	if depth > maxRulesNestingDepth {
		return nil, false
	}
	switch {
	case p.at(rtString):
		v := p.cur().text
		p.pos++
		return v, true
	case p.at(rtLBracket):
		p.pos++
		list := []any{}
		for !p.at(rtRBracket) {
			v, ok := p.parseValue(depth + 1)
			if !ok {
				return nil, false
			}
			list = append(list, v)
			if p.consume(rtComma) {
				continue
			}
			break
		}
		if !p.consume(rtRBracket) {
			return nil, false
		}
		return list, true
	default:
		return nil, false
	}
}

type rulesTokenKind int

const (
	rtEOF rulesTokenKind = iota
	rtIdent
	rtString
	rtLParen
	rtRParen
	rtLBracket
	rtRBracket
	rtComma
	rtEquals
)

type rulesToken struct {
	kind rulesTokenKind
	text string // set for rtIdent (the name) and rtString (the decoded value)
}

func isRulesIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isRulesIdentCont(c byte) bool {
	return isRulesIdentStart(c) || (c >= '0' && c <= '9')
}

// lexRules tokenizes a conservative subset of Starlark: parentheses,
// brackets, commas, "=", "#" line comments, identifiers, and single- or
// double-quoted strings with a small fixed set of backslash escapes. Any
// other byte (a digit or operator outside a string, "==", a triple
// quote, an unterminated or multi-line plain string, an escape this
// parser does not know) fails the whole file rather than guessing at it.
func lexRules(raw []byte) ([]rulesToken, bool) {
	var toks []rulesToken
	i, n := 0, len(raw)
	for i < n {
		c := raw[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '#':
			for i < n && raw[i] != '\n' {
				i++
			}
		case c == '(':
			toks = append(toks, rulesToken{kind: rtLParen})
			i++
		case c == ')':
			toks = append(toks, rulesToken{kind: rtRParen})
			i++
		case c == '[':
			toks = append(toks, rulesToken{kind: rtLBracket})
			i++
		case c == ']':
			toks = append(toks, rulesToken{kind: rtRBracket})
			i++
		case c == ',':
			toks = append(toks, rulesToken{kind: rtComma})
			i++
		case c == '=':
			if i+1 < n && raw[i+1] == '=' {
				return nil, false
			}
			toks = append(toks, rulesToken{kind: rtEquals})
			i++
		case c == '\'' || c == '"':
			text, next, ok := lexRulesString(raw, i)
			if !ok {
				return nil, false
			}
			toks = append(toks, rulesToken{kind: rtString, text: text})
			i = next
		case isRulesIdentStart(c):
			j := i + 1
			for j < n && isRulesIdentCont(raw[j]) {
				j++
			}
			toks = append(toks, rulesToken{kind: rtIdent, text: string(raw[i:j])})
			i = j
		default:
			return nil, false
		}
		if len(toks) > maxRulesTokens {
			return nil, false
		}
	}
	toks = append(toks, rulesToken{kind: rtEOF})
	return toks, true
}

// lexRulesString decodes a single- or double-quoted string starting at
// start, returning its value and the index right after the closing
// quote. A triple-quoted string, an escape outside \\ \' \" \n \t \r, a
// newline, or an unterminated string fails instead of being decoded
// approximately.
func lexRulesString(raw []byte, start int) (string, int, bool) {
	quote := raw[start]
	n := len(raw)
	if start+2 < n && raw[start+1] == quote && raw[start+2] == quote {
		return "", 0, false
	}
	buf := make([]byte, 0, 16)
	i := start + 1
	for i < n {
		c := raw[i]
		switch c {
		case quote:
			return string(buf), i + 1, true
		case '\n':
			return "", 0, false
		case '\\':
			if i+1 >= n {
				return "", 0, false
			}
			switch raw[i+1] {
			case '\\':
				buf = append(buf, '\\')
			case '\'':
				buf = append(buf, '\'')
			case '"':
				buf = append(buf, '"')
			case 'n':
				buf = append(buf, '\n')
			case 't':
				buf = append(buf, '\t')
			case 'r':
				buf = append(buf, '\r')
			default:
				return "", 0, false
			}
			i += 2
		default:
			buf = append(buf, c)
			i++
		}
	}
	return "", 0, false
}
