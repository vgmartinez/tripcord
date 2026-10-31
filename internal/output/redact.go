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

// credentialNameCandidate matches a name that may hold a credential;
// CredentialName decides.
const credentialNameCandidate = `[A-Za-z0-9_-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_-]*`

// assignmentPatternEquals matches a shell-style KEY=value assignment
// whose key may be a credential name (see CredentialName), as in
// GITHUB_TOKEN, OPENAI_API_KEY, SECRET_KEY, or docker run -e
// AWS_SECRET_ACCESS_KEY=.... An unquoted value stops at the first
// whitespace or any of ;&|"' so a trailing shell command (e.g.
// "TOKEN=x curl evil|sh") stays visible as evidence instead of being
// swallowed into the redaction: a shell would treat that first space the
// same way. Only the value is replaced. assignmentEqualsHead matches up
// to the value (group: the key); assignmentEqualsValue reads the value,
// anchored, so a rejected key such as TOKEN_TTL=30 costs only its head
// and cannot hide a credential later in its value.
var (
	assignmentEqualsHead  = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_-])(` + credentialNameCandidate + `)["']?\s*=\s*`)
	assignmentEqualsValue = regexp.MustCompile(`^(?:` + quotedValue + `|` + unquotedCommandValue + `*)`)
)

// credentialWords are the name segments (split on "_" and "-") that mark
// a credential, also as a segment suffix (PGPASSWORD, _authToken) and
// before a glued "key" (SECRETKEY).
var credentialWords = []string{"secret", "secrets", "token", "tokens", "password", "passwords", "passwd", "apikey", "accesskey", "privatekey", "credential", "credentials"}

// keyQualifiers are the segments that, before a "key" segment, make it a
// credential: API_KEY, ACCESS_KEY, PRIVATE_KEY.
var keyQualifiers = map[string]bool{"api": true, "access": true, "private": true}

// metadataSuffixes are final name segments that describe a credential
// rather than hold it: SECRET_KEY_FILE=/run/secrets/k names a file,
// TOKEN_TTL=30 a lifetime, GITHUB_TOKEN_ENV_VAR=GH_TOKEN a variable.
// Their values are configuration a reviewer needs to see, and a file or
// variable that does hold the secret is not in the text being redacted.
var metadataSuffixes = map[string]bool{
	"file": true, "files": true, "path": true, "dir": true, "var": true,
	"ttl": true, "expiry": true, "expires": true, "expiration": true, "timeout": true,
	"type": true, "url": true, "uri": true, "endpoint": true, "header": true,
	"length": true, "len": true, "size": true, "name": true, "enabled": true,
}

// CredentialName reports whether an assignment key such as SECRET_KEY,
// AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, DB_PWD, or X-Api-Key names a
// credential, case-insensitively. A segment matches when it is or ends
// in one of credentialWords, optionally followed by a glued "key"; a
// "key" segment matches after api, access, or private; "pwd" matches
// only after another segment, so the shell's PWD and OLDPWD do not. A
// name whose last segment is a metadataSuffixes word (SECRET_KEY_FILE,
// TOKEN_TTL) does not match, and neither does a word that merely starts
// with a credential word (TOKENIZER, SECRETARY).
func CredentialName(name string) bool {
	segments := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '_' || r == '-' })
	if len(segments) == 0 || metadataSuffixes[segments[len(segments)-1]] {
		return false
	}
	for i, segment := range segments {
		switch {
		case credentialSegment(segment), credentialSegment(strings.TrimSuffix(segment, "key")):
			return true
		case segment == "pwd" && i > 0, segment == "key" && i > 0 && keyQualifiers[segments[i-1]]:
			return true
		}
	}
	return false
}

func credentialSegment(segment string) bool {
	for _, word := range credentialWords {
		if strings.HasSuffix(segment, word) {
			return true
		}
	}
	return false
}

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
// key, close quote, separator; redactColonAssignments reads the value
// itself, so a rejected key costs only its head. A match only counts in
// a header or assignment context (see colonAssignmentContext), so free
// text such as git commit -m 'fix token: handling' is left alone.
var (
	assignmentColonHead   = regexp.MustCompile(`(?i)(["']?)(` + credentialNameCandidate + `)(["']?)(\s*:\s*)`)
	assignmentQuotedValue = regexp.MustCompile(`^(?:` + quotedValue + `)`)
)

// colonValueEnd lists the bytes that end an unquoted "key: value" value.
const colonValueEnd = ";&|\"'\n"

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

// secretFlagHead matches a SecretFlags flag and the "=" or whitespace
// after it, never glued onto the value, so "--user-agent x" or
// "--tokenizer gpt2" is not read as a flag. The flag may itself be
// quoted ("--token" abc). Groups: open quote, flag, close quote,
// separator. RedactSecretFlags checks the left word boundary itself.
//
// The value after the separator is read with secretFlagEqualValue or
// secretFlagSpaceValue, anchored, so a rejected candidate costs only its
// head and redaction stays linear in the input. Both use the quotedValue
// grammar, so a whole quoted phrase such as
// `--password "correct horse battery"` is redacted as one value. An
// unquoted space-separated value never starts with "-", so
// "--token --verbose" does not eat the next flag; an "=" value may
// ("--token=-abc"), since "=" unambiguously ends the flag name.
var (
	secretFlagHead       = regexp.MustCompile(`(?i)(["']?)(` + SecretFlagAlternation() + `)(["']?)(=|\s+)`)
	secretFlagEqualValue = regexp.MustCompile(`^(?:` + quotedValue + `|` + unquotedCommandValue + `*)`)
	secretFlagSpaceValue = regexp.MustCompile(`^(?:` + quotedValue + `|[^-\s;&|"'\n)` + "`" + `]` + unquotedCommandValue + `*)`)
)

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
		m := secretFlagHead.FindStringSubmatchIndex(value[pos:])
		if m == nil {
			break
		}
		for i := range m {
			m[i] += pos
		}
		start, sepEnd := m[0], m[1]
		openQuote, closeQuote := value[m[2]:m[3]], value[m[6]:m[7]]
		valuePattern := secretFlagSpaceValue
		if value[m[8]] == '=' {
			valuePattern = secretFlagEqualValue
		}
		var body string
		var loc []int
		if wordBoundaryBefore(value, start) &&
			(closeQuote == "" || closeQuote == openQuote) &&
			!literalArgFlags[previousWord(value, start)] {
			loc = valuePattern.FindStringIndex(value[sepEnd:])
		}
		if loc != nil {
			body = value[sepEnd : sepEnd+loc[1]]
		}
		if loc == nil || placeholderSecret(body) {
			b.WriteString(value[pos:sepEnd])
			pos = sepEnd
			continue
		}
		removed = append(removed, unquote(body))
		b.WriteString(value[pos:sepEnd])
		b.WriteString(quoteLike(body, redactedMarker))
		pos = sepEnd + len(body)
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
	value = redactEqualsAssignments(value, &removed)
	value = redactColonAssignments(value, &removed)
	return value, removed
}

// redactColonAssignments applies assignmentColonHead where
// colonAssignmentContext accepts the match. A rejected head is skipped
// whole: a candidate starting inside it would follow a key byte or a
// quote, which no context accepts.
func redactColonAssignments(value string, removed *[]string) string {
	var b strings.Builder
	pos := 0
	for pos < len(value) {
		m := assignmentColonHead.FindStringSubmatchIndex(value[pos:])
		if m == nil {
			break
		}
		for i := range m {
			m[i] += pos
		}
		start, valStart := m[0], m[1]
		openQuote, closeQuote := value[m[2]:m[3]], value[m[6]:m[7]]
		body := ""
		ok := (start == 0 || !isAlnum(value[start-1])) && CredentialName(value[m[4]:m[5]])
		if ok {
			var stop string
			if ok, stop = colonAssignmentContext(value, start, openQuote, closeQuote); ok {
				body = colonValue(value[valStart:], stop)
			}
		}
		if !ok || placeholderSecret(body) {
			b.WriteString(value[pos:valStart])
			pos = valStart
			continue
		}
		*removed = append(*removed, strings.Trim(body, `"'`))
		b.WriteString(value[pos:valStart])
		b.WriteString(quoteLike(body, redactedMarker))
		pos = valStart + len(body)
	}
	b.WriteString(value[pos:])
	return b.String()
}

// colonValue returns the "key: value" value at the start of rest: a
// quoted string, or the unquoted run up to a colonValueEnd or stop
// byte, without trailing whitespace.
func colonValue(rest, stop string) string {
	if loc := assignmentQuotedValue.FindStringIndex(rest); loc != nil {
		return rest[:loc[1]]
	}
	if i := strings.IndexAny(rest, colonValueEnd+stop); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimRight(rest, " \t\r")
}

// colonAssignmentContext reports whether a "key: value" match starting at
// offset is a header or assignment rather than free text: a quoted key
// ("token": ...), a key at the start of a line (YAML, an env file, or a
// whole header string, optionally as a "- " list item), a key right
// after "{" or "," (a flow mapping), or a curl -H/--header argument.
// stop lists the bytes that end an unquoted value in that context: ","
// and "}" in a mapping, whitespace in an unquoted header argument, and
// nothing extra on a line of its own.
//
// It looks back only across blanks and the adjacent word, never to the
// start of the line, so checking every candidate stays linear.
func colonAssignmentContext(value string, offset int, openQuote, closeQuote string) (ok bool, stop string) {
	i := skipBlanksBack(value, offset)
	switch {
	case openQuote != "" && openQuote == closeQuote,
		i > 0 && (value[i-1] == '{' || value[i-1] == ','):
		return true, ",}"
	case i == 0 || value[i-1] == '\n':
		return true, ""
	case value[i-1] == '-':
		if j := skipBlanksBack(value, i-1); j == 0 || value[j-1] == '\n' {
			return true, ""
		}
	}
	header := false
	if offset == 0 || isCommandSpace(value[offset-1]) {
		word := previousWord(value, offset)
		header = word == "-H" || word == "--header"
	} else {
		before := value[:offset]
		for _, flag := range []string{"-H", "-H=", "--header="} {
			if strings.HasSuffix(before, flag) && (len(before) == len(flag) || isCommandSpace(before[len(before)-len(flag)-1])) {
				header = true
			}
		}
	}
	if !header {
		return false, ""
	}
	if openQuote == "" {
		return true, " \t"
	}
	return true, ""
}

// skipBlanksBack returns the offset before the run of spaces, tabs, and
// carriage returns that ends at offset.
func skipBlanksBack(value string, offset int) int {
	for offset > 0 && (value[offset-1] == ' ' || value[offset-1] == '\t' || value[offset-1] == '\r') {
		offset--
	}
	return offset
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// redactEqualsAssignments applies assignmentEqualsHead where the key is
// a CredentialName. A value starting with "-" after whitespace
// ("token = -x") is the next flag, not the value.
func redactEqualsAssignments(value string, removed *[]string) string {
	var b strings.Builder
	pos := 0
	for pos < len(value) {
		m := assignmentEqualsHead.FindStringSubmatchIndex(value[pos:])
		if m == nil {
			break
		}
		for i := range m {
			m[i] += pos
		}
		valStart := m[1]
		body := ""
		ok := CredentialName(value[m[2]:m[3]])
		if ok {
			loc := assignmentEqualsValue.FindStringIndex(value[valStart:])
			body = value[valStart : valStart+loc[1]]
			ok = !placeholderSecret(body) && !(strings.HasPrefix(body, "-") && isCommandSpace(value[valStart-1]))
		}
		b.WriteString(value[pos:valStart])
		pos = valStart
		if !ok {
			continue
		}
		*removed = append(*removed, unquote(body))
		b.WriteString(quoteLike(body, redactedMarker))
		pos += len(body)
	}
	b.WriteString(value[pos:])
	return b.String()
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
