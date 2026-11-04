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
//
// Each pattern lists literals one of which every match contains, so a
// value without any skips the regexp, which otherwise steps every byte.
// A fold pattern's literals are lowercase and compared with an
// ASCII-lowercased value; they avoid "k" and "s", the only ASCII
// letters (?i) also matches as a non-ASCII rune (the Kelvin sign, long s).
var secretPatterns = []shapePattern{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), []string{"-----BEGIN "}, false},
	{regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`), []string{"AKIA", "ASIA", "ABIA", "ACCA"}, false},
	{regexp.MustCompile(`(?i)aws_?secret_?access_?key["'\s]*[:=]\s*["']?[A-Za-z0-9/+=]{40}`), []string{"acce"}, true},
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`), []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, false},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,255}`), []string{"github_pat_"}, false},
	{regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), []string{"glpat-"}, false},
	{regexp.MustCompile(`(?:\b|_)sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`), []string{"sk-"}, false},
	{regexp.MustCompile(`[sr]k_live_[0-9A-Za-z]{20,}`), []string{"k_live_"}, false},
	{regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`), []string{"xox"}, false},
	{regexp.MustCompile(`xapp-[0-9]+-[A-Za-z0-9-]{8,}`), []string{"xapp-"}, false},
	{regexp.MustCompile(`npm_[A-Za-z0-9]{20,}`), []string{"npm_"}, false},
	{regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`), []string{"hf_"}, false},
	{regexp.MustCompile(`ya29\.[A-Za-z0-9._-]{20,}`), []string{"ya29."}, false},
	{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), []string{"AIza"}, false},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), []string{"eyJ"}, false},
	{regexp.MustCompile(`(?i)\bbearer(?:\s|` + lineContinuation + `)+[A-Za-z0-9._~+/-]{20,}=*`), []string{"bearer"}, true},
	{regexp.MustCompile(`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+`), []string{"https://hooks.slack.com/"}, false},
}

// shapePattern is a secretPatterns entry: the regexp, the literals one of
// which every match contains, and whether they compare case-folded.
type shapePattern struct {
	re    *regexp.Regexp
	anyOf []string
	fold  bool
}

// mayMatch reports whether value, or lower (its asciiLower) for a fold
// pattern, contains one of p.anyOf.
func (p shapePattern) mayMatch(value, lower string) bool {
	text := value
	if p.fold {
		text = lower
	}
	for _, literal := range p.anyOf {
		if strings.Contains(text, literal) {
			return true
		}
	}
	return false
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
// The username may be empty ("redis://:pw@h", "postgresql://:pw@db"): a
// scheme that carries only a password still carries a credential.
var urlUserinfoPattern = regexp.MustCompile(`(://)([^/\s:@]*:[^/?#\s]*)(@)`)

// urlUserinfoSlashPattern is urlUserinfoPattern for a password that
// contains "/" ("https://user:pa/ss@host"), which net/url cannot parse
// and urlUserinfoPattern stops short of. The password runs to the first
// "@". RedactURLUserinfo skips a match whose text before the first "/"
// is all digits: that is a port and a path ("https://host:8080/x@y"),
// not a password.
var urlUserinfoSlashPattern = regexp.MustCompile(`(://)([^/\s:@]*:([^\s@?#]*/[^\s@?#]*))(@)`)

// quotedOrBareValue is one assignment value: a double-quoted string that
// correctly skips an escaped quote (\"), so {"password":"a\"b"} redacts
// the whole "a\"b" instead of stopping at the \" and leaking the b that
// followed it; a single-quoted string (shell single quotes do not
// support backslash escapes, so no \-skipping is needed there); or an
// unquoted run, which the two assignmentPattern variants below bound
// differently.
const quotedValue = `"(?:[^"\\\n]|\\.)*"|'[^'\n]*'`

// lineContinuation is a shell backslash-newline. The shell deletes it,
// so in "--token \<newline>  x" the token is x, not the backslash.
const lineContinuation = `\\\r?\n`

// equalsSeparator and spaceSeparator are the separators between a flag
// and its value, either of which may continue onto the next line. A
// space separator needs one blank that is not a continuation's newline:
// "--token\<newline>x" is the shell word "--tokenx", not a flag and a
// value.
const (
	equalsSeparator = `=(?:` + lineContinuation + `)*`
	spaceSeparator  = `(?:` + lineContinuation + `)*\s(?:\s|` + lineContinuation + `)*`
)

// continuationLen returns the length of the lineContinuation at the
// start of s, or 0.
func continuationLen(s string) int {
	switch {
	case strings.HasPrefix(s, "\\\n"):
		return 2
	case strings.HasPrefix(s, "\\\r\n"):
		return 3
	default:
		return 0
	}
}

// A shell-style KEY=value assignment is redacted when its key is a
// credential name (see CredentialName), as in GITHUB_TOKEN,
// OPENAI_API_KEY, SECRET_KEY, or docker run -e AWS_SECRET_ACCESS_KEY=....
// assignmentEqualsValue reads the value, anchored after the "=": an
// unquoted value stops at the first whitespace or any of ;&|"' so a
// trailing shell command (e.g. "TOKEN=x curl evil|sh") stays visible as
// evidence instead of being swallowed into the redaction: a shell would
// treat that first space the same way. Only the value is replaced, and a
// rejected key such as TOKEN_TTL=30 cannot hide a credential later in
// its value.
var assignmentEqualsValue = regexp.MustCompile(`^(?:` + quotedValue + `|` + unquotedCommandValue + `*)`)

// assignmentHead is a candidate "name=" or "name:" found by
// nextAssignmentHead: the name holds a credential stem, may be quoted,
// and is followed by optional whitespace, the separator, and optional
// whitespace and line continuations.
type assignmentHead struct {
	start                 int // the name, or the quote right before it
	nameEnd               int
	name                  string
	openQuote, closeQuote string
	sep                   string // the separator with its whitespace
	valStart              int
}

// stemScanner finds credentialStems in an ASCII-lowercased copy of a
// value with strings.Index, remembering each stem's next occurrence, so
// a scan whose position only moves forward is linear. It replaces a
// case-insensitive name regexp, which cannot skip ahead to a literal and
// steps every byte.
type stemScanner struct {
	lower string
	next  []int // per stem: next occurrence, -1 for none left, -2 unknown
}

func newStemScanner(value string) *stemScanner {
	s := &stemScanner{lower: asciiLower(value), next: make([]int, len(credentialStems))}
	for i := range s.next {
		s.next[i] = -2
	}
	return s
}

// find returns the first stem occurrence at or after pos, or -1.
func (s *stemScanner) find(pos int) int {
	best := -1
	for i, stem := range credentialStems {
		if s.next[i] == -1 {
			continue
		}
		if s.next[i] < pos {
			j := strings.Index(s.lower[pos:], stem)
			if j < 0 {
				s.next[i] = -1
				continue
			}
			s.next[i] = pos + j
		}
		if best < 0 || s.next[i] < best {
			best = s.next[i]
		}
	}
	return best
}

func asciiLower(value string) string {
	b := []byte(value)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func isNameByte(c byte) bool { return isAlnum(c) || c == '_' || c == '-' }

// isRegexpSpace is RE2's \s.
func isRegexpSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

// nextAssignmentHead returns the first head at or after pos whose
// separator is sep ('=' or ':'). The name is the whole run of
// [A-Za-z0-9_-] around a stem, bounded below by pos, as is a quote
// before it.
func nextAssignmentHead(value string, scan *stemScanner, pos int, sep byte) (assignmentHead, bool) {
	for {
		floor := pos
		hit := scan.find(pos)
		if hit < 0 {
			return assignmentHead{}, false
		}
		nameStart, nameEnd := hit, hit
		for nameStart > floor && isNameByte(value[nameStart-1]) {
			nameStart--
		}
		for nameEnd < len(value) && isNameByte(value[nameEnd]) {
			nameEnd++
		}
		pos = nameEnd
		h := assignmentHead{start: nameStart, nameEnd: nameEnd, name: value[nameStart:nameEnd]}
		if nameStart > floor && (value[nameStart-1] == '"' || value[nameStart-1] == '\'') {
			h.start, h.openQuote = nameStart-1, value[nameStart-1:nameStart]
		}
		j := nameEnd
		if j < len(value) && (value[j] == '"' || value[j] == '\'') {
			h.closeQuote = value[j : j+1]
			j++
		}
		sepStart := j
		for j < len(value) && isRegexpSpace(value[j]) {
			j++
		}
		if j == len(value) || value[j] != sep {
			continue
		}
		j++
		for j < len(value) {
			if n := continuationLen(value[j:]); n > 0 {
				j += n
			} else if isRegexpSpace(value[j]) {
				j++
			} else {
				break
			}
		}
		h.sep, h.valStart = value[sepStart:j], j
		return h, true
	}
}

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

// booleanFlags are flags whose name contains a credential word but that
// take no value: gh auth login --with-token reads the token from stdin,
// so "--with-token=true" or the word after it is not a secret.
var booleanFlags = map[string]bool{"--with-token": true}

// CredentialName reports whether an assignment key such as SECRET_KEY,
// AWS_SECRET_ACCESS_KEY, PRIVATE_KEY, GITHUB_TOKEN, DB_PASS, DB_PWD,
// PASS, or X-Api-Key names a credential, case-insensitively. A segment
// matches when it is or ends in one of credentialWords, optionally
// followed by a glued "key"; a "key" segment matches after api, access,
// or private. "pwd" matches only as a whole segment after another one,
// so the shell's PWD and OLDPWD do not. "pass" matches as a whole
// segment after another one (DB_PASS, redis-pass) or as the entire name
// (PASS). BYPASS is not that segment, and PASS_THROUGH starts with it
// but is not only that segment, so neither matches. A name whose last
// segment is a metadataSuffixes word (SECRET_KEY_FILE, TOKEN_TTL,
// PASS_FILE) does not match, nor does a word that merely starts with a
// credential word (TOKENIZER, SECRETARY, COMPASS), nor a booleanFlags
// flag.
func CredentialName(name string) bool {
	lower := strings.ToLower(name)
	if booleanFlags[lower] {
		return false
	}
	segments := strings.FieldsFunc(lower, func(r rune) bool { return r == '_' || r == '-' })
	if len(segments) == 0 || metadataSuffixes[segments[len(segments)-1]] {
		return false
	}
	for i, segment := range segments {
		switch {
		case credentialSegment(segment), credentialSegment(strings.TrimSuffix(segment, "key")):
			return true
		case segment == "pwd" && i > 0,
			segment == "pass" && passSegment(i, len(segments)),
			segment == "key" && i > 0 && keyQualifiers[segments[i-1]]:
			return true
		}
	}
	return false
}

// passSegment reports whether a segment that is exactly "pass" names a
// credential: the whole name (PASS, i == 0 and no other segment) or a
// later segment (DB_PASS, MY_PASS_V2). A leading segment with something
// after it (PASS_THROUGH) does not.
func passSegment(i, n int) bool {
	return i > 0 || n == 1
}

// credentialStems are lowercase substrings every CredentialName name
// contains; stemScanner looks for them.
var credentialStems = []string{"secret", "token", "pass", "pwd", "key", "credential"}

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

// A "key: value" credential, as opposed to shell-style KEY=value: a
// line such as "token: abc def" is not shell syntax, so, unlike the "="
// form, there is no shell word boundary to preserve and an unquoted
// value runs to the end of the line (or to one of ;&|"', in case the
// line is itself embedded in a larger shell command); trailing
// whitespace is not part of it. A head counts anywhere except inside the
// argument of a literalTextFlags flag, so git commit -m 'fix token:
// handling' is left alone (see redactColonAssignments).
// assignmentQuotedValue reads a quoted value, anchored.
var assignmentQuotedValue = regexp.MustCompile(`^(?:` + quotedValue + `)`)

// colonValueEnd lists the bytes that end an unquoted "key: value" value.
const colonValueEnd = ";&|\"'\n)}"

// authorizationPattern matches an Authorization header or JSON field with a
// Bearer, Basic, or token scheme, in both header ("Authorization: Bearer x")
// and quoted/JSON ("Authorization":"Bearer x") spellings. The value is not
// length-limited, and a closing quote is never consumed.
var authorizationPattern = regexp.MustCompile(`(?i)(authorization["']?\s*:\s*["']?(?:bearer|basic|token)(?:\s|` + lineContinuation + `)+)([^\s;&|"']+)`)

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
// RedactSecretFlags tries secretFlagHead, anchored, only where a word
// can start with a flag: a "-" at a word boundary, or the quote right
// before it. The head's optional leading quote gives the regexp no
// literal prefix to skip to, so searching with it would step every byte.
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
	secretFlagHead       = regexp.MustCompile(`(?i)^(["']?)(` + SecretFlagAlternation() + `)(["']?)(` + equalsSeparator + `|` + spaceSeparator + `)`)
	secretFlagEqualValue = regexp.MustCompile(`^(?:` + quotedValue + `|` + unquotedCommandValue + `*)`)
	secretFlagSpaceValue = regexp.MustCompile(`^(?:` + quotedValue + `|[^-\s;&|"'\n)` + "`" + `]` + unquotedCommandValue + `*)`)
)

// RedactSecretFlags replaces the value of every SecretFlags flag in
// value ("--token X", "--token=X", "--token 'X'") with [REDACTED], kept
// in the value's own quotes, and returns the raw values it removed, with
// those quotes stripped. An empty or placeholder value ("--token=",
// "--token $TOKEN") is left alone, as is a flag name inside the argument
// of a literalTextFlags flag (grep -e --token file).
func RedactSecretFlags(value string) (string, []string) {
	var removed []string
	var b strings.Builder
	var spans literalSpans
	spansFound := false
	pos, written := 0, 0
	for pos < len(value) {
		dash := strings.IndexByte(value[pos:], '-')
		if dash < 0 {
			break
		}
		start := pos + dash
		if start > pos && (value[start-1] == '"' || value[start-1] == '\'') {
			start--
		}
		var m []int
		if wordBoundaryBefore(value, start) {
			m = secretFlagHead.FindStringSubmatchIndex(value[start:])
		}
		if m == nil {
			pos += dash + 1
			continue
		}
		for i := range m {
			m[i] += start
		}
		sepEnd := m[1]
		openQuote, closeQuote := value[m[2]:m[3]], value[m[6]:m[7]]
		valuePattern := secretFlagSpaceValue
		if value[m[8]] == '=' {
			valuePattern = secretFlagEqualValue
		}
		var body string
		var loc []int
		if !spansFound {
			spans, spansFound = findLiteralSpans(value), true
		}
		if (closeQuote == "" || closeQuote == openQuote) && !spans.contains(start) {
			loc = valuePattern.FindStringIndex(value[sepEnd:])
		}
		if loc != nil {
			body = value[sepEnd : sepEnd+loc[1]]
		}
		pos = sepEnd
		if loc == nil || placeholderSecret(body) {
			continue
		}
		removed = append(removed, unquote(body))
		b.WriteString(value[written:sepEnd])
		b.WriteString(quoteLike(body, redactedMarker))
		pos += len(body)
		written = pos
	}
	b.WriteString(value[written:])
	return b.String(), removed
}

// wordBoundaryBefore reports whether offset starts a shell word: the
// start of text or right after whitespace. Without it, the optional
// single dash of SecretFlagAlternation would match the "-password"
// inside a compound word such as "find-generic-password".
func wordBoundaryBefore(value string, offset int) bool {
	return offset == 0 || isCommandSpace(value[offset-1])
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

// userFlagPattern matches curl's -u/--user/-user flag and its value,
// anchored at the flag: "-u value", "-u=value", or glued ("-uuser:pass",
// curl's documented short form). Groups: flag, separator, value.
// RedactUserFlags tries it only at a "-" that starts the text or follows
// whitespace.
var userFlagPattern = regexp.MustCompile(`(?i)^(` + UserFlagAlternation + `)(` + equalsSeparator + `|` + spaceSeparator + `|)(` + quotedValue + `|` + unquotedCommandValue + `*)`)

// RedactUserFlags replaces the value of a curl-style -u/--user/-user flag
// with [REDACTED] when it has "user:pass" shape, and returns the raw
// values it removed. A non-credential use such as "sudo -u root" is left
// alone. The glued form is accepted only for "-u": "-userX" is read as
// "-u" plus "serX", and "--userX" (such as "--user-agent") is never a
// user flag at all. It is shared by DefaultRedactor and the Claude Code
// adapter's source-side redaction, so both phases agree.
func RedactUserFlags(value string) (string, []string) {
	var removed []string
	var b strings.Builder
	pos, written := 0, 0
	for pos < len(value) {
		dash := strings.IndexByte(value[pos:], '-')
		if dash < 0 {
			break
		}
		start := pos + dash
		var g []int
		if start == 0 || (start > pos && isRegexpSpace(value[start-1])) {
			g = userFlagPattern.FindStringSubmatchIndex(value[start:])
		}
		if g == nil {
			pos += dash + 1
			continue
		}
		end := start + g[1]
		pos = end
		flag, separator, body := value[start+g[2]:start+g[3]], value[start+g[4]:start+g[5]], value[start+g[6]:end]
		if separator == "" {
			switch strings.ToLower(flag) {
			case "-u":
			case "-user":
				body = flag[2:] + body
				flag = flag[:2]
			default:
				continue
			}
		}
		if !LooksLikeUserPass(body) || placeholderSecret(body) {
			continue
		}
		removed = append(removed, strings.Trim(body, `"'`))
		b.WriteString(value[written:start])
		b.WriteString(flag + separator + quoteLike(body, redactedMarker))
		written = end
	}
	b.WriteString(value[written:])
	return b.String(), removed
}

// DefaultRedactor replaces well-known credential shapes with [REDACTED].
// Already-redacted text, such as "sk-***REDACTED***abcd", is unchanged.
func DefaultRedactor(value string) string {
	if strings.Contains(asciiLower(value), "authorization") {
		value = authorizationPattern.ReplaceAllString(value, "${1}"+redactedMarker)
	}
	value, _ = RedactSecretFlags(value)
	value, _ = RedactUserFlags(value)
	value, _ = RedactToolFlags(value)
	value, _ = RedactURLUserinfo(value)
	lower := asciiLower(value)
	for _, pattern := range secretPatterns {
		if !pattern.mayMatch(value, lower) {
			continue
		}
		if out := pattern.re.ReplaceAllString(value, redactedMarker); out != value {
			value, lower = out, asciiLower(out)
		}
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

// redactColonAssignments redacts each credential-named "key:" head
// (nextAssignmentHead) anywhere in value, except inside the argument of
// a literalTextFlags flag (git commit -m 'fix token: handling'). Free
// text such as echo secret: foo is redacted too: over-redacting a
// scanner's output is safe, leaking a secret is not. A rejected head is
// skipped whole: a candidate starting inside it would follow a key byte.
func redactColonAssignments(value string, removed *[]string) string {
	scan := newStemScanner(value)
	var b strings.Builder
	var spans literalSpans
	spansFound := false
	imageRefs := findContainerImageSpans(value)
	lines := newLineIndex(value)
	commentGaps := newCommentGapIndex(value)
	pos := 0
	for {
		h, found := nextAssignmentHead(value, scan, pos, ':')
		if !found {
			break
		}
		ok := (h.start == 0 || !isAlnum(value[h.start-1])) && CredentialName(h.name) &&
			!imageRefs.contains(h.start)
		if ok && !spansFound {
			spans, spansFound = findLiteralSpans(value), true
		}
		ok = ok && !spans.contains(h.start)
		if ok {
			// A block scalar ("api_key: |") or a nested mapping
			// ("token:\n  pw: x") is the key's value even when the key is
			// quoted ("'api_key': |"), so both are checked before
			// colonValueStop's mapping stops apply. Each test is
			// strict before it asks lines for the key's column, so a
			// near miss ("api_key: |x") costs no line lookup.
			blockStart, isBlock := blockScalarHeader(value, h.valStart, lines)
			bodyStart := blockStart
			if !isBlock {
				blockStart, isBlock = nestedMappingStart(value, h)
				bodyStart = blockStart
			}
			if !isBlock {
				blockStart, bodyStart, isBlock = commentGapStart(value, h, lines, commentGaps)
			}
			if isBlock {
				bodyEnd := blockBodyEnd(value, bodyStart, lines.column(h.start))
				if bodyEnd > blockStart {
					b.WriteString(value[pos:blockStart])
					*removed = append(*removed, value[blockStart:bodyEnd])
					b.WriteString(redactedBlockScalarBody(value[blockStart:bodyEnd]))
					pos = bodyEnd
					continue
				}
				// An empty block scalar, or a "nested" key that is a
				// sibling at the key's own indentation ("token:\npw: x"):
				// h has no value; the loop goes on to that next key.
				end := max(blockStart, h.valStart)
				b.WriteString(value[pos:end])
				pos = end
				continue
			}
		}
		stop := ""
		if ok {
			stop = colonValueStop(value, h.start, h.openQuote, h.closeQuote, h.sep)
		}
		body := ""
		if ok {
			body = colonValue(value[h.valStart:], stop)
		}
		b.WriteString(value[pos:h.valStart])
		pos = h.valStart
		if !ok || placeholderSecret(body) {
			continue
		}
		*removed = append(*removed, strings.Trim(body, `"'`))
		b.WriteString(quoteLike(body, redactedMarker))
		pos += len(body)
	}
	b.WriteString(value[pos:])
	return b.String()
}

// blockScalarHeader recognizes a YAML block scalar header starting at
// valStart: "|" or ">", an optional chomping indicator ("-" or "+") and
// a single-digit indentation indicator, in either order, then nothing
// but blanks or a "#" comment to the end of the line ("api_key: |-",
// "api_key: >2", "api_key: |2-"). headerEnd is the offset just past the
// header's line, where the block's content starts. ok is false for
// anything else, including "|x", so the caller falls back to colonValue.
func blockScalarHeader(value string, valStart int, lines *lineIndex) (headerEnd int, ok bool) {
	if valStart >= len(value) || (value[valStart] != '|' && value[valStart] != '>') {
		return 0, false
	}
	i := valStart + 1
	for n := 0; n < 2 && i < len(value) && isBlockScalarIndicator(value[i]); n++ {
		i++
	}
	for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
		i++
	}
	if i < len(value) && value[i] == '#' {
		i = lines.lineEnd(i)
	}
	if i < len(value) && value[i] == '\r' {
		i++
	}
	if i < len(value) && value[i] != '\n' {
		return 0, false
	}
	if i < len(value) {
		i++
	}
	return i, true
}

func isBlockScalarIndicator(c byte) bool {
	return c == '-' || c == '+' || (c >= '1' && c <= '9')
}

// blockBodyEnd returns the offset past the block value starting at
// start: every following line that is blank or indented more than
// keyIndent, the key's own column. It reads each body line once and
// only the indentation of the line that ends the block, so the caller,
// which resumes after the block, stays linear.
func blockBodyEnd(value string, start, keyIndent int) int {
	i := start
	for i < len(value) {
		j := i
		for j < len(value) && (value[j] == ' ' || value[j] == '\t') {
			j++
		}
		if j < len(value) && value[j] != '\n' && value[j] != '\r' && j-i <= keyIndent {
			break
		}
		if k := strings.IndexByte(value[j:], '\n'); k >= 0 {
			i = j + k + 1
		} else {
			i = len(value)
		}
	}
	return i
}

// lineIndex answers line questions about value for positions that only
// move forward, in amortized constant time: scanning back to the start
// of the line, or ahead to its end, once per candidate would make a
// long line of candidates ("api_key: |x api_key: |x ...") quadratic.
type lineIndex struct {
	value     string
	scanned   int // value[:scanned] has been searched for line starts
	lineStart int // the start of the line holding scanned
	nextNL    int // the first '\n' at or after the last lineEnd query
}

func newLineIndex(value string) *lineIndex { return &lineIndex{value: value, nextNL: -1} }

// column returns pos's offset from the start of its line: every byte
// before it on that line, blank or not, so a key after "- " or after
// other text on its line ("x api_key: |") counts that text too. That
// is the indentation YAML compares a block's content against.
func (l *lineIndex) column(pos int) int {
	if pos < l.scanned {
		return pos - (strings.LastIndexByte(l.value[:pos], '\n') + 1)
	}
	if i := strings.LastIndexByte(l.value[l.scanned:pos], '\n'); i >= 0 {
		l.lineStart = l.scanned + i + 1
	}
	l.scanned = pos
	return pos - l.lineStart
}

// lineEnd returns the offset of the first '\n' at or after pos, or
// len(value) when there is none.
func (l *lineIndex) lineEnd(pos int) int {
	if l.nextNL < pos {
		if i := strings.IndexByte(l.value[pos:], '\n'); i >= 0 {
			l.nextNL = pos + i
		} else {
			l.nextNL = len(l.value)
		}
	}
	return l.nextNL
}

// redactedBlockScalarBody is a YAML block scalar's content, replaced by
// one [REDACTED] line at the first line's own indentation, so a secret
// split across lines by "|" or ">" is not left in the output the way a
// single-line value would catch it.
func redactedBlockScalarBody(body string) string {
	indent := 0
	for indent < len(body) && (body[indent] == ' ' || body[indent] == '\t') {
		indent++
	}
	nl := ""
	if strings.HasSuffix(body, "\n") {
		nl = "\n"
	}
	return body[:indent] + redactedMarker + nl
}

// findContainerImageSpans returns tag-shaped image arguments in the only
// container command positions that are exempt from colon assignments. It
// scans each command segment once; calling splitWords from every assignment
// candidate would turn a long path-heavy command quadratic.
func findContainerImageSpans(value string) literalSpans {
	var refs literalSpans
	for start := 0; start < len(value); {
		end := commandSegmentEnd(value, start)
		words := splitWords(value[start:end])
		if len(words) >= 3 {
			tool := normalizeToolWord(words[0].text)
			if tool == "docker" || tool == "podman" || tool == "nerdctl" {
				subcommand := strings.Trim(words[1].text, `"'`)
				for i, word := range words {
					imagePosition := (subcommand == "run" || subcommand == "pull" || subcommand == "push" || subcommand == "create") && i == 2 ||
						subcommand == "build" && i == 3 && (words[2].text == "-t" || words[2].text == "--tag") ||
						subcommand == "tag" && (i == 2 || i == 3)
					if !imagePosition {
						continue
					}
					if colon := strings.LastIndexByte(word.text, ':'); colon > 0 && !strings.Contains(word.text, "=") && imageTag(word.text[colon+1:]) {
						refs = append(refs, [2]int{start + word.start, start + word.end})
					}
				}
			}
		}
		start = end + 1
	}
	return refs
}

// commandSegmentEnd finds an unquoted shell command separator. A semicolon
// inside an argument such as echo 'x; docker run password:S y' cannot start
// a container command.
func commandSegmentEnd(value string, start int) int {
	for i := start; i < len(value); i++ {
		switch value[i] {
		case '\'':
			if end := strings.IndexByte(value[i+1:], '\''); end >= 0 {
				i += end + 1
			}
		case '"':
			i++
			for i < len(value) && value[i] != '"' {
				if value[i] == '\\' {
					i++
				}
				i++
			}
		case ';', '&', '|', '\n':
			return i
		}
	}
	return len(value)
}

func imageTag(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] == '-' {
		return false
	}
	for _, c := range value {
		if c == '_' || c == '.' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

// nestedMappingStart reports whether h, a key whose colon is followed by
// nothing but a newline, holds a nested mapping ("token:\n  pw: x",
// "token:\n  \"pw\": x", "token:\n  \"pw\":x") rather than a plain scalar
// wrapped onto the next line ("token:\n  opaque-value",
// "api_key:\n  sk:X"). start is the offset of the line holding the
// nested key, where the mapping starts. A nested key is a name,
// optionally quoted, optional blanks, and a ":". An unquoted key needs
// a space, tab, CR, LF, or the end of value after that colon, as in
// YAML: a glued "sk:X" or a URL ("https://...") is a scalar, not a key.
// A quoted key is a key even when its value is glued on ("\"pw\":X"),
// because the quotes already ended the name.
func nestedMappingStart(value string, h assignmentHead) (start int, ok bool) {
	nl := strings.LastIndexByte(h.sep, '\n')
	if nl < 0 {
		return 0, false
	}
	pos := h.valStart
	quoted := false
	if pos < len(value) && (value[pos] == '"' || value[pos] == '\'') {
		quoted = true
		quote := value[pos]
		pos++
		for pos < len(value) && value[pos] != quote && value[pos] != '\n' {
			pos++
		}
		if pos == len(value) || value[pos] != quote {
			return 0, false
		}
		pos++
	} else {
		nameStart := pos
		for pos < len(value) && isNameByte(value[pos]) {
			pos++
		}
		if pos == nameStart {
			return 0, false
		}
	}
	for pos < len(value) && (value[pos] == ' ' || value[pos] == '\t') {
		pos++
	}
	if pos == len(value) || value[pos] != ':' {
		return 0, false
	}
	if pos++; !quoted && pos < len(value) {
		switch value[pos] {
		case ' ', '\t', '\r', '\n':
		default:
			return 0, false
		}
	}
	return h.valStart - len(h.sep) + nl + 1, true
}

// commentGapStart reports whether h's value is more-indented content
// after a YAML comment, which colonValue cannot see because it stops at
// the first newline: "token: # c\n  X" and "token:\n  # c\n  X".
// redactStart is h's value start, including every header or gap comment;
// bodyStart is the first line of content whose indentation decides where
// the value ends. A "#" with nothing indented after it is the value itself
// ("token: #secret"), so this returns false and colonValue redacts it.
func commentGapStart(value string, h assignmentHead, lines *lineIndex, gaps *commentGapIndex) (redactStart, bodyStart int, ok bool) {
	i := h.valStart
	for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
		i++
	}
	if i >= len(value) || value[i] != '#' {
		return 0, 0, false
	}
	bodyStart = gaps.afterRun(i)
	if bodyStart >= len(value) {
		return 0, 0, false
	}
	keyIndent := lines.column(h.start)
	first := bodyStart
	for first < len(value) && (value[first] == ' ' || value[first] == '\t') {
		first++
	}
	if first == len(value) || first-bodyStart <= keyIndent {
		return 0, 0, false
	}
	return h.valStart, bodyStart, true
}

// commentGapIndex caches where each run of comment and blank lines ends.
// It is separate from lineIndex: a later header can occur before that
// run's cached end, so sharing a single forward line-end cache lets that
// later header mistake a later line for the end of its own line. Heads
// are scanned in source order, so a later head inside the most recent
// run reuses its endpoint. That keeps "# token: #\n" repeated N times
// linear: the first candidate scans the run and the rest look it up.
type commentGapIndex struct {
	value string
	runs  []commentGapRun
}

func newCommentGapIndex(value string) *commentGapIndex {
	return &commentGapIndex{value: value}
}

// afterRun returns the first non-comment, nonblank line after the
// comment starting at start, or len(value) when there is none.
func (c *commentGapIndex) afterRun(start int) int {
	if n := len(c.runs); n > 0 {
		last := c.runs[n-1]
		if start >= last.start && start < last.end {
			return last.end
		}
	}
	i := start
	for i < len(c.value) {
		line := i
		for i < len(c.value) && (c.value[i] == ' ' || c.value[i] == '\t') {
			i++
		}
		switch {
		case i == len(c.value):
			c.cache(start, i)
			return i
		case c.value[i] == '#':
			if end := strings.IndexByte(c.value[i:], '\n'); end >= 0 {
				i += end + 1
				continue
			}
			c.cache(start, len(c.value))
			return len(c.value)
		case c.value[i] == '\n':
			i++
		case c.value[i] == '\r' && i+1 < len(c.value) && c.value[i+1] == '\n':
			i += 2
		default:
			c.cache(start, line)
			return line
		}
	}
	c.cache(start, len(c.value))
	return len(c.value)
}

type commentGapRun struct{ start, end int }

func (c *commentGapIndex) cache(start, end int) {
	c.runs = append(c.runs, commentGapRun{start: start, end: end})
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

// colonValueStop returns the bytes that end an unquoted "key: value"
// value starting at offset, beyond colonValueEnd: "," and "}" in a
// mapping (a quoted key, or a key right after "{" or ","), whitespace in
// a glued Name:value word that does not start a line (an httpie or
// curl header), and nothing extra otherwise, so a YAML or env line, an
// echo argument, or a free-text value runs to the end of its line or
// quote. It looks back only across blanks, so checking every candidate
// stays linear.
func colonValueStop(value string, offset int, openQuote, closeQuote, sep string) string {
	i := skipBlanksBack(value, offset)
	switch {
	case openQuote != "" && openQuote == closeQuote,
		i > 0 && (value[i-1] == '{' || value[i-1] == ','):
		return ",}"
	case i == 0 || value[i-1] == '\n':
		return ""
	case sep == ":":
		return " \t"
	}
	return ""
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

// redactEqualsAssignments redacts each "KEY=" head (nextAssignmentHead)
// whose key is a CredentialName. A value starting with "-" after
// whitespace ("token = -x") is the next flag, not the value.
func redactEqualsAssignments(value string, removed *[]string) string {
	scan := newStemScanner(value)
	var b strings.Builder
	pos := 0
	for {
		h, found := nextAssignmentHead(value, scan, pos, '=')
		if !found {
			break
		}
		body := ""
		ok := CredentialName(h.name)
		if ok {
			loc := assignmentEqualsValue.FindStringIndex(value[h.valStart:])
			body = value[h.valStart : h.valStart+loc[1]]
			ok = !placeholderSecret(body) && (!strings.HasPrefix(body, "-") || !isCommandSpace(value[h.valStart-1]))
		}
		b.WriteString(value[pos:h.valStart])
		pos = h.valStart
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

// PublishFinding returns finding as a sink publishes it, for a caller
// that renders a finding itself: every string except the closed
// vocabularies and the fingerprint redacted with redact, then capped at
// MaxFieldBytes.
func PublishFinding(finding model.Finding, redact Redactor) model.Finding {
	return capFinding(redactFinding(finding, redact))
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
