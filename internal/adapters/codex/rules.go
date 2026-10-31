package codex

import (
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
		pattern := f.SafeValue("", rule.pattern)
		payload := map[string]any{
			"role":     "rule",
			"decision": rule.decision,
			"pattern":  pattern,
		}
		if rule.justification != "" {
			payload["justification"] = f.SafeString(rule.justification)
		}
		if rule.match != nil {
			payload["match"] = f.SafeValue("", rule.match)
		}
		if rule.notMatch != nil {
			payload["not_match"] = f.SafeValue("", rule.notMatch)
		}
		patternJSON, _ := json.Marshal(pattern)
		f.Add(model.ConfigKindPermissions, []string{"rule", rule.decision, string(patternJSON)}, payload)
	}
}

// rulesLiteral is one string literal found in a rules file the parser
// could not model: its byte span, quote, and decoded text.
type rulesLiteral struct {
	start, end int
	quote      string
	text       string
}

// sanitizeRulesLiterals returns raw with every string literal sanitized
// as one element of an argv-like list, in file order, through
// kit.Source.SafeValue. A secret flag and its value are separate
// literals in a pattern (["aws", "--secret-access-key", "X"]), which a
// whole-file SafeString cannot pair up; SafeValue's array rule can, and
// records what it removes for the key discriminator. Literals are found
// leniently: an escape the parser rejects is kept as written.
func (f *file) sanitizeRulesLiterals(raw []byte) string {
	literals := scanRulesLiterals(raw)
	values := make([]any, len(literals))
	for i, lit := range literals {
		values[i] = lit.text
	}
	sanitized, _ := f.SafeValue("", values).([]any)
	var b strings.Builder
	pos := 0
	for i, lit := range literals {
		text, _ := sanitized[i].(string)
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

func scanRulesLiterals(raw []byte) []rulesLiteral {
	var out []rulesLiteral
	for i := 0; i < len(raw); {
		switch c := raw[i]; {
		case c == '#':
			for i < len(raw) && raw[i] != '\n' {
				i++
			}
		case c == '\'' || c == '"':
			lit, ok := scanRulesLiteral(raw, i)
			if !ok {
				i++
				continue
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
