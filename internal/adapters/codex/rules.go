package codex

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// rulesFile normalizes one .rules file: Codex's Starlark-based exec
// policy, read from .codex/rules/*.rules (project, gated by project
// trust) and ~/.codex/rules/*.rules (user, always active). It is parsed
// conservatively, never executed: parseRulesFile recognizes only
// prefix_rule(pattern=[...], decision=..., justification=..., match=...,
// not_match=...) and host_executable(name=..., paths=[...]) calls built
// from string and list literals. Anything else in the file (another
// call, a variable, a loop, string concatenation, an unsupported escape
// or quoting form, an undocumented decision, ...) makes the whole file
// opaque: one item is emitted for it instead of guessing at its meaning,
// with a blocking diagnostic, since the unparsed part may hold an allow
// rule no finding can then cite.
func (f *file) rulesFile(raw []byte) {
	parsed, ok := parseRulesFile(raw)
	if !ok {
		f.Warn("rules file uses Starlark the scanner does not parse conservatively; reporting its content, not its rules")
		f.Add(model.ConfigKindPermissions, []string{"rules-file"}, map[string]any{
			"role":    "rules-file",
			"parsed":  false,
			"content": f.SafeString(f.sanitizeRulesLiterals(raw)),
		})
		return
	}
	for _, host := range parsed.hostExecutables {
		for _, problem := range hostExecutableProblems(host) {
			f.Warn("host_executable %q: %s", f.SafeString(host.name), problem)
		}
		f.Add(model.ConfigKindPermissions, []string{"host-executable", host.name}, map[string]any{
			"role":  "host-executable",
			"name":  f.SafeString(host.name),
			"paths": f.SafeValue("", host.paths),
		})
	}
	for _, rule := range parsed.prefixRules {
		pattern := f.SafeValue("", f.SafeToolArgv(rule.pattern))
		payload := map[string]any{
			"role":     "rule",
			"decision": rule.decision,
			"pattern":  pattern,
		}
		if rule.justification != "" {
			payload["justification"] = f.SafeString(rule.justification)
		}
		if rule.match != nil {
			payload["match"] = f.SafeValue("", f.safeExamples(rule.match))
		}
		if rule.notMatch != nil {
			payload["not_match"] = f.SafeValue("", f.safeExamples(rule.notMatch))
		}
		patternJSON, _ := json.Marshal(pattern)
		f.Add(model.ConfigKindPermissions, []string{"rule", rule.decision, string(patternJSON)}, payload)
	}
}

// safeExamples applies SafeToolArgv to each argv-list example of a
// match or not_match list; a string example is a whole command line,
// which SafeValue's RedactToolFlags pass already covers.
func (f *file) safeExamples(examples []any) []any {
	out := make([]any, len(examples))
	for i, example := range examples {
		if argv, ok := example.([]any); ok {
			out[i] = f.SafeToolArgv(argv)
		} else {
			out[i] = example
		}
	}
	return out
}

// rulesLiteral is one string literal found in a rules file the parser
// could not model: its byte span, quote, decoded text, and group, the
// outermost "[...]" or "(...)" enclosing it (a literal outside any has
// a group of its own).
type rulesLiteral struct {
	start, end int
	quote      string
	text       string
	group      int
}

// sanitizeRulesLiterals returns raw with every string literal sanitized
// through kit.Source.SafeValue, each list or tuple of literals as one
// argv-like list. A secret flag and its value are separate literals in a
// pattern (["aws", "--secret-access-key", "X"]), which a whole-file
// SafeString cannot pair up; SafeValue's array rule can, and records
// what it removes for the key discriminator. SafeToolArgv runs first, so
// a tool-specific flag (["redis-cli", "--pass", "X"], ["mysql", "-pX"])
// is redacted too. A tool word activates its flags only within its own
// list, so ["make", "-a", "all"] after ["redis-cli", "info"] keeps
// "all". Literals are found leniently: an escape the parser rejects is
// kept as written.
func (f *file) sanitizeRulesLiterals(raw []byte) string {
	literals := scanRulesLiterals(raw)
	sanitized := make([]string, len(literals))
	var order []int
	members := map[int][]int{}
	for i, lit := range literals {
		if members[lit.group] == nil {
			order = append(order, lit.group)
		}
		members[lit.group] = append(members[lit.group], i)
	}
	for _, group := range order {
		values := make([]any, len(members[group]))
		for j, i := range members[group] {
			values[j] = literals[i].text
		}
		out, _ := f.SafeValue("", f.SafeToolArgv(values)).([]any)
		for j, i := range members[group] {
			sanitized[i], _ = out[j].(string)
		}
	}
	// Syntax the opaque scanner cannot resolve (an argv concatenation or
	// a variable standing for a tool) gets the conservative pre-e8a570c
	// treatment within that expression. Ordinary adjacent lists retain
	// their independent argv groups above.
	for _, group := range conservativeRulesGroups(raw, literals) {
		values := make([]any, 0, len(group.prefix)+len(group.members))
		for _, value := range group.prefix {
			values = append(values, value)
		}
		for _, i := range group.members {
			values = append(values, literals[i].text)
		}
		out, _ := f.SafeValue("", f.SafeToolArgv(values)).([]any)
		for j, i := range group.members {
			sanitized[i], _ = out[len(group.prefix)+j].(string)
		}
	}
	var b strings.Builder
	pos := 0
	for i, lit := range literals {
		text := sanitized[i]
		if text == lit.text {
			continue
		}
		b.Write(raw[pos:lit.start])
		b.WriteString(lit.quote + encodeRulesString(text, lit.quote) + lit.quote)
		pos = lit.end
	}
	b.Write(raw[pos:])
	return b.String()
}

type rulesConservativeGroup struct {
	members []int
	prefix  []string
}

// conservativeRulesGroups recognizes the two opaque constructs where an
// argv can cross a list boundary: A + B and a variable previously assigned
// a literal tool name. It deliberately confines fallback to that source
// line, preserving the per-list isolation for unrelated rules.
func conservativeRulesGroups(raw []byte, literals []rulesLiteral) []rulesConservativeGroup {
	var out []rulesConservativeGroup
	tools := map[string]string{}
	lineStart := 0
	for lineStart <= len(raw) {
		lineEnd := bytes.IndexByte(raw[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(raw)
		} else {
			lineEnd += lineStart
		}
		var members []int
		for i, lit := range literals {
			if lit.start >= lineStart && lit.end <= lineEnd {
				members = append(members, i)
			}
		}
		line := string(raw[lineStart:lineEnd])
		if len(members) == 1 {
			prefix := strings.TrimSpace(line[:literals[members[0]].start-lineStart])
			if name, ok := strings.CutSuffix(strings.TrimSpace(prefix), "="); ok && name != "" {
				tools[strings.TrimSpace(name)] = literals[members[0]].text
			}
		}
		if len(members) > 0 && strings.Contains(line, "+") {
			out = append(out, rulesConservativeGroup{members: members})
		} else if len(members) > 0 {
			for name, tool := range tools {
				if strings.Contains(line, "["+name) || strings.Contains(line, ", "+name) {
					out = append(out, rulesConservativeGroup{members: members, prefix: []string{tool}})
					break
				}
			}
		}
		if lineEnd == len(raw) {
			break
		}
		lineStart = lineEnd + 1
	}
	return out
}

func scanRulesLiterals(raw []byte) []rulesLiteral {
	var out []rulesLiteral
	var open []int
	groups := 0
	for i := 0; i < len(raw); {
		switch raw[i] {
		case '#':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
		case '[', '(':
			groups++
			open = append(open, groups)
			i++
		case ']', ')':
			if len(open) > 0 {
				open = open[:len(open)-1]
			}
			i++
		case '\'', '"':
			lit, ok := scanRulesLiteral(raw, i)
			if !ok {
				i++
				continue
			}
			if len(open) > 0 {
				lit.group = open[0]
			} else {
				groups++
				lit.group = groups
			}
			out = append(out, lit)
			i = lit.end
		default:
			i++
		}
	}
	return out
}

func scanRulesLiteral(raw []byte, start int) (rulesLiteral, bool) {
	quote := string(raw[start])
	if triple := strings.Repeat(quote, 3); strings.HasPrefix(string(raw[start:]), triple) {
		end := strings.Index(string(raw[start+3:]), triple)
		if end < 0 {
			return rulesLiteral{}, false
		}
		return rulesLiteral{start: start + 3, end: start + 3 + end, quote: "", text: string(raw[start+3 : start+3+end])}, true
	}
	var b strings.Builder
	for i := start + 1; i < len(raw); i++ {
		switch c := raw[i]; c {
		case quote[0]:
			return rulesLiteral{start: start, end: i + 1, quote: quote, text: b.String()}, true
		case '\n':
			return rulesLiteral{}, false
		case '\\':
			if i+1 >= len(raw) {
				return rulesLiteral{}, false
			}
			i++
			switch e := raw[i]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '\'', '"':
				b.WriteByte(e)
			default:
				b.WriteByte('\\')
				b.WriteByte(e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return rulesLiteral{}, false
}

// encodeRulesString escapes text for a literal quoted with quote ("" for
// the inside of a triple-quoted string, which is kept as written).
func encodeRulesString(text, quote string) string {
	if quote == "" {
		return text
	}
	return strings.NewReplacer(`\`, `\\`, quote, `\`+quote, "\n", `\n`, "\r", `\r`).Replace(text)
}

// hostExecutableProblems reports why a host_executable entry may not
// mean what it appears to: name must be a bare program name (the
// basename a prefix_rule matches), and paths a non-empty list of
// non-empty absolute paths. The entry is still reported; the diagnostic
// says a finding citing it may not match what Codex resolves.
func hostExecutableProblems(host rawHostExecutable) []string {
	var problems []string
	if host.name == "" || strings.ContainsAny(host.name, `/\;`) || strings.Contains(host.name, "..") {
		problems = append(problems, `name is not a bare program name (empty, or contains "/", "\", "..", or ";")`)
	}
	if len(host.paths) == 0 {
		problems = append(problems, "paths is empty")
	}
	for _, p := range host.paths {
		if s, _ := p.(string); !absoluteRulesPath(s) {
			problems = append(problems, "paths has an empty or relative entry")
			break
		}
	}
	return problems
}

// absoluteRulesPath reports whether p is absolute on any OS Codex runs
// on, independent of the OS the scanner runs on: "/usr/bin/git",
// `C:\Git\bin\git.exe`, "C:/Git/bin/git.exe", or a UNC `\\host\share\x`.
func absoluteRulesPath(p string) bool {
	switch {
	case strings.HasPrefix(p, "/"), strings.HasPrefix(p, `\\`):
		return len(p) > 1
	case len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
		c := p[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return false
}
