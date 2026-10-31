package output

import (
	"regexp"

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
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*`),
	regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),
}

// DefaultRedactor replaces well-known credential shapes with [REDACTED].
// Already-redacted text, such as "sk-***REDACTED***abcd", is unchanged.
func DefaultRedactor(value string) string {
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, redactedMarker)
	}
	return value
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
