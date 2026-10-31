package output

import (
	"regexp"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Redactor replaces secret values in a string. Sinks apply it to every
// string of a finding. It must be deterministic and must not return its
// input's secret in any form.
type Redactor func(string) string

const redactedMarker = "[REDACTED]"

// secretPatterns are well-known credential shapes. The model layer redacts
// first; this list is a second line of defense, not a secret scanner.
// Distinctive prefixes match without a word boundary, because "_" is a word
// character and ids such as "evt_AKIA..." would otherwise slip through.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)aws_?secret_?access_?key["'\s]*[:=]\s*["']?[A-Za-z0-9/+=]{40}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,255}`),
	regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`(?:\b|_)sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`[sr]k_live_[0-9A-Za-z]{20,}`),
	regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`xapp-[0-9]+-[A-Za-z0-9-]{8,}`),
	regexp.MustCompile(`npm_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`ya29\.[A-Za-z0-9._-]{20,}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*`),
	regexp.MustCompile(`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+`),
	regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),
}

// assignmentPattern matches a credential key and its value. The key may
// carry a prefix, as in GITHUB_TOKEN or OPENAI_API_KEY. A quoted value runs
// to its closing quote. An unquoted value stops at the first whitespace or
// any of ;&|"' so a trailing shell command (e.g. "TOKEN=x curl evil|sh")
// stays visible as evidence instead of being swallowed into the redaction.
// Only the value is replaced.
var assignmentPattern = regexp.MustCompile(`(?i)((?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]*[_-])*(?:password|passwd|api[_-]?key|token|secret)\b["']?\s*[=:]\s*)("[^"\n]*"|'[^'\n]*'|[^\s;&|"'\n]*)`)

// authorizationPattern matches an Authorization header or JSON field with a
// Bearer, Basic, or token scheme, in both header ("Authorization: Bearer x")
// and quoted/JSON ("Authorization":"Bearer x") spellings. The value is not
// length-limited, and a closing quote is never consumed.
var authorizationPattern = regexp.MustCompile(`(?i)(authorization["']?\s*:\s*["']?(?:bearer|basic|token)\s+)([^\s;&|"']+)`)

// curlUserPattern matches curl's "-u user:pass" / "--user user:pass" inline
// credential flag. Quotes around the value, if present, are preserved.
var curlUserPattern = regexp.MustCompile(`(?i)((?:^|\s)(?:-u|--user)\s+)(['"]?)([^\s'";&|]+:[^\s'";&|]*)(['"]?)`)

// DefaultRedactor replaces well-known credential shapes with [REDACTED].
// Already-redacted text, such as "sk-***REDACTED***abcd", is unchanged.
func DefaultRedactor(value string) string {
	value = authorizationPattern.ReplaceAllString(value, "${1}"+redactedMarker)
	value = curlUserPattern.ReplaceAllString(value, "${1}${2}"+redactedMarker+"${4}")
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, redactedMarker)
	}
	return assignmentPattern.ReplaceAllStringFunc(value, redactAssignment)
}

func redactAssignment(match string) string {
	parts := assignmentPattern.FindStringSubmatch(match)
	if len(parts) != 3 || placeholderSecret(parts[2]) {
		return match
	}
	value := parts[2]
	if len(value) >= 2 {
		quote := value[0]
		if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
			return parts[1] + string(quote) + redactedMarker + string(quote)
		}
	}
	return parts[1] + redactedMarker
}

func placeholderSecret(value string) bool {
	inner := strings.Trim(strings.TrimSpace(value), `"'`)
	if inner == "" || strings.HasPrefix(inner, "$") || strings.HasPrefix(inner, "<") || strings.HasPrefix(strings.ToLower(inner), "your-") {
		return true
	}
	switch strings.ToLower(inner) {
	case "changeme", "example", "placeholder", "todo", "xxx", "redacted", "[redacted]":
		return true
	default:
		return false
	}
}

// redactFinding returns a deep copy of finding with redact applied to every
// string except the closed vocabularies and the validated fingerprint.
func redactFinding(finding model.Finding, redact Redactor) model.Finding {
	out := finding
	out.Rule = redact(finding.Rule)
	out.Title = redact(finding.Title)
	out.Fix = redact(finding.Fix)
	out.Location.Session = redact(finding.Location.Session)
	out.Location.Path = redact(finding.Location.Path)
	if finding.Location.Line != nil {
		line := *finding.Location.Line
		out.Location.Line = &line
	}
	if finding.Evidence != nil {
		out.Evidence = make([]model.Evidence, len(finding.Evidence))
		for i, evidence := range finding.Evidence {
			out.Evidence[i] = model.Evidence{
				Event:   redact(evidence.Event),
				Excerpt: redact(evidence.Excerpt),
			}
			if evidence.Config != nil {
				out.Evidence[i].Config = &model.ConfigRef{ID: redact(evidence.Config.ID), Key: redact(evidence.Config.Key)}
			}
		}
	}
	if finding.Refs != nil {
		out.Refs = make([]string, len(finding.Refs))
		for i, ref := range finding.Refs {
			out.Refs[i] = redact(ref)
		}
	}
	return out
}
