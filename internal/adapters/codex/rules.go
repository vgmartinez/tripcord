package codex

import (
	"encoding/json"

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
			"content": f.SafeString(string(raw)),
		})
		return
	}
	for _, host := range parsed.hostExecutables {
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
