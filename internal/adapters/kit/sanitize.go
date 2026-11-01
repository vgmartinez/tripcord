package kit

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/pathx"
)

// Redacted replaces secret values in payloads and evidence keys.
const Redacted = "[REDACTED]"

var (
	secretFlagName = regexp.MustCompile(`(?i)^(?:` + output.SecretFlagAlternation() + `)$`)
	bearerToken    = regexp.MustCompile(`(?i)\b(bearer)\s+([^\s'"]+)`)
	// bearerSchemeWord matches an array element ending in the word
	// "Bearer": "Bearer", "Authorization: Bearer", or
	// "--header=Authorization: Bearer", whose token is the next element.
	bearerSchemeWord = regexp.MustCompile(`(?i)(?:^|:)\s*bearer\s*$`)
	userFlagName     = regexp.MustCompile(`(?i)^(?:` + output.UserFlagAlternation + `)$`)
	// embeddedURL finds an absolute URL inside a larger string, such as a
	// curl command. It stops at whitespace and quotes so a trailing shell
	// quote or the rest of a pipeline is not swallowed. It runs on through
	// ")" and a backtick, so a query that contains one is still stripped
	// whole; StripEmbeddedURL keeps the shell text that closes there.
	embeddedURL = regexp.MustCompile(`["']?[A-Za-z][A-Za-z0-9+.-]*://[^\s'"<>]+`)
)

// Sanitized is one string after sanitization: the safe text, and the raw
// substrings removed to produce it. Removed is never stored; it only
// feeds the k1 discriminator (see discriminated).
type Sanitized struct {
	Value   string
	Removed []string
}

// Sanitize strips URL userinfo, query, and fragment from every URL inside
// value, redacts secret CLI flag values and bearer tokens, rewrites the
// home directory as "~" (user scope only), and finally redacts any
// credential shape output.DefaultRedactor recognizes. What it removes is
// also recorded for the next Add's key discriminator. The result depends
// only on value and the source's scope and home, so it is memoized per
// source: an entry's signature re-sanitizes strings that earlier entries
// or its own key already did.
func (s *Source) Sanitize(value string) Sanitized {
	if s.presanitized != nil && s.presanitized(value) {
		return Sanitized{Value: value}
	}
	r, ok := s.sanitized[value]
	if !ok {
		r = s.sanitizeUncached(value)
		if s.sanitized == nil {
			s.sanitized = map[string]Sanitized{}
		}
		s.sanitized[value] = r
	}
	s.recordRemoved(r.Removed...)
	return Sanitized{Value: r.Value, Removed: slices.Clone(r.Removed)}
}

func (s *Source) sanitizeUncached(value string) Sanitized {
	value, removed := stripEmbeddedURLSecrets(value)
	value, flags := redactCommandSecrets(value)
	removed = append(removed, flags...)
	value = s.tildeHome(value)
	if redacted := output.DefaultRedactor(value); redacted != value {
		removed = append(removed, value)
		value = redacted
	}
	return Sanitized{Value: value, Removed: removed}
}

// SafeString is Sanitize(value).Value.
func (s *Source) SafeString(value string) string { return s.Sanitize(value).Value }

// SafeKey sanitizes every part of an evidence key.
func (s *Source) SafeKey(parts []string) []string {
	out := make([]string, len(parts))
	for i, part := range parts {
		out[i] = s.SafeString(part)
	}
	return out
}

// Removal is one raw value sanitization removed while an entry was
// built, and the top-level payload field it came from. Value is never
// stored: in k1 mode it only feeds the HMAC; in s1 mode it is not used.
type Removal struct {
	Field string
	Value string
}

// Removed tags each value as removed from field.
func Removed(field string, values ...string) []Removal {
	out := make([]Removal, len(values))
	for i, v := range values {
		out[i] = Removal{Field: field, Value: v}
	}
	return out
}

const (
	// k1Domain separates the k1 HMAC from any other use of the key.
	k1Domain = "tripcord.sig.k1"
	// k1HexLen is the k1 discriminator length in hex characters.
	k1HexLen = 16
)

// discriminated returns key with a "sig:" discriminator over removed
// appended when it is non-empty, so two entries that differ only by
// redacted text keep distinct keys. Both modes also get "#" and the
// entry's ordinal among earlier entries of the same file whose key up
// to and including the mode part is identical, so identical duplicates
// are told apart the same way in k1 and s1. The mode is part of the
// text:
//
//   - k1, with a fingerprint key: "sig:k1:" and 16 hex characters of
//     HMAC-SHA256(key, removed values). The same entry with a different
//     secret gets a different key.
//   - s1, without one: "sig:s1:" and StructuralDiscriminator(view),
//     the structure of where view still shows [REDACTED]. No hash or
//     other function of a removed value is used, and the result never
//     depends on how many sanitization passes produced those markers,
//     only on the final sanitized payload, so a rotated secret, or one
//     with a different recognizable shape (a provider-prefixed token
//     versus a generic one), keeps the same key.
func (s *Source) discriminated(kind model.ConfigKind, key []string, removed []Removal, view map[string]any) []string {
	if len(removed) == 0 {
		return key
	}
	var part string
	if s.c.key.Present() {
		values := make([]string, len(removed))
		for i, r := range removed {
			values[i] = r.Value
		}
		part = "sig:k1:" + s.c.key.Sum(k1Domain, values, k1HexLen)
	} else {
		part = "sig:s1:" + StructuralDiscriminator(view)
	}
	ordinal := s.c.ordinal(s.harness, s.scope, s.path, kind, key, part)
	return append(key, part+"#"+strconv.Itoa(ordinal))
}

// StructuralDiscriminator describes, without any secret value, where
// view (the final sanitized payload, as built for the entry) still
// shows the Redacted marker: each top-level field holding at least one
// occurrence as field[n], where n counts earlier occurrences within
// that field (maps walked in sorted key order, arrays by index),
// comma-joined in field order (SortedKeys(view)). A field is skipped
// when it holds none. Field names are passed through
// output.DefaultRedactor once per field, not once per occurrence.
//
// Counting markers in the payload itself, rather than how many
// sanitization passes fired while building it, means two payloads that
// are byte-identical after sanitizing always get the same
// discriminator: a provider-shaped secret (ghp_, sk-, AKIA, a JWT, ...)
// and a generic one that redact to the same shape are indistinguishable
// here, as they must be, since neither the shape nor the count of
// detection passes that happened to match is safe to reveal.
func StructuralDiscriminator(view map[string]any) string {
	var parts []string
	for _, field := range SortedKeys(view) {
		count := countRedacted(view[field])
		if count == 0 {
			continue
		}
		name := redactedFieldName(field)
		for n := 0; n < count; n++ {
			parts = append(parts, name+"["+strconv.Itoa(n)+"]")
		}
	}
	return strings.Join(parts, ",")
}

// redactedFieldNames memoizes output.DefaultRedactor on a field name: a
// scan's payload field names (command, headers, env, url, args, and so
// on) usually come from a small, fixed set defined by the adapters
// themselves, repeated across every entry and every scan, so caching
// avoids running DefaultRedactor's whole regex pipeline again on a name
// it has already classified. It is shared across all adapters and
// sources: a field name is redacted the same way regardless of which
// one produced it.
//
// That "small, fixed set" assumption is usually true but not
// guaranteed: SafeObject keeps every key of a hook's or an MCP server's
// raw JSON object, sanitizing only its value, so a config author (or an
// attacker who can edit one) can add a field whose name the adapter
// never expected. Such a name is passed through DefaultRedactor here
// like any other string before it can reach a discriminator or other
// output, the same guarantee every other secret-shaped value in this
// package relies on. But unlike a Removal, whose Value is never
// retained once used, this cache's key is always the original,
// unredacted field name, kept for the life of the process: a field name
// that happens to be credential-shaped is, by definition, a secret
// value, so this cache is only free of secret values when every field
// name actually is one of the small fixed set adapters normally use.
var redactedFieldNames sync.Map

func redactedFieldName(field string) string {
	if cached, ok := redactedFieldNames.Load(field); ok {
		return cached.(string)
	}
	name := output.DefaultRedactor(field)
	redactedFieldNames.Store(field, name)
	return name
}

// countRedacted counts occurrences of the Redacted marker in value,
// walking a map in sorted key order and an array by index. It counts a
// substring occurrence, not just a whole-value match, so it covers both
// a value entirely replaced with [REDACTED] (a header or env map entry)
// and [REDACTED] substituted inside a larger string (a secret embedded
// in a command line); the discriminator's shape does not depend on
// which of those two forms a given field happens to take.
func countRedacted(value any) int {
	switch v := value.(type) {
	case string:
		return strings.Count(v, Redacted)
	case map[string]any:
		total := 0
		for _, key := range SortedKeys(v) {
			total += countRedacted(v[key])
		}
		return total
	case []any:
		total := 0
		for _, item := range v {
			total += countRedacted(item)
		}
		return total
	default:
		return 0
	}
}

// enterField makes name the field later removals are attributed to when
// no outer field is set, and returns the function that restores it.
func (s *Source) enterField(name string) func() {
	if s.field != "" || name == "" {
		return func() {}
	}
	s.field = name
	return func() { s.field = "" }
}

// tildeHome rewrites the home directory as "~" in user scope only.
// Repository and managed content may legitimately contain a path equal to
// the scanning machine's home; rewriting it would make a fingerprint
// depend on who ran the scan.
func (s *Source) tildeHome(value string) string {
	if s.scope != model.ScopeUser {
		return value
	}
	return pathx.TildeHome(s.c.home, value)
}

// SafeValue sanitizes a decoded value recursively. Strings are sanitized;
// in an array, the element after a bare secret flag ("--token", "X") or
// a bare "Bearer" scheme word (an MCP server's args split across two
// elements, ["Bearer", "X"], where neither element alone carries
// "Bearer X" for Sanitize's bearerToken regex to match) is redacted
// unconditionally; the element after a bare curl user flag ("-u",
// "user:pass") is redacted only when it has "user:pass" shape
// (output.LooksLikeUserPass), so ["-u", "root"] ("sudo -u root") is left
// alone; a string or number under a secret-looking key name is redacted.
func (s *Source) SafeValue(key string, value any) any {
	defer s.enterField(key)()
	if key != "" && SecretKey(key) && !namesEnvVar(key) {
		switch value.(type) {
		case string, json.Number, int64, float64:
			s.recordRemovedValue(value)
			return Redacted
		}
	}
	switch v := value.(type) {
	case string:
		return s.SafeString(v)
	case []any:
		out := make([]any, len(v))
		redactNext := false
		gateUserPass := false
		for i, item := range v {
			if redactNext {
				name, isString := item.(string)
				if gateUserPass && (!isString || !output.LooksLikeUserPass(name)) {
					out[i] = s.SafeValue("", item)
				} else {
					s.recordRemovedValue(item)
					out[i] = Redacted
				}
				redactNext, gateUserPass = false, false
				continue
			}
			out[i] = s.SafeValue("", item)
			if name, ok := item.(string); ok {
				switch {
				case isArraySecretMarker(name):
					redactNext = true
				case userFlagName.MatchString(name):
					redactNext, gateUserPass = true, true
				}
			}
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for _, name := range SortedKeys(v) {
			out[name] = s.SafeValue(name, v[name])
		}
		return out
	default:
		return value
	}
}

// SafeToolArgv applies output.RedactToolArgv to list, an argv whose
// string elements are separate words (a Codex prefix_rule pattern such
// as ["redis-cli", "--pass", "X"] or ["mysql", "-pX"]), records what it
// removed for the key discriminator, and returns a redacted copy. A
// non-string element (a nested list of alternatives) is kept as is and
// counts as an empty word. Run SafeValue on the result as usual.
func (s *Source) SafeToolArgv(list []any) []any {
	argv := make([]string, len(list))
	for i, item := range list {
		argv[i], _ = item.(string)
	}
	redacted, removed := output.RedactToolArgv(argv)
	out := append([]any(nil), list...)
	if len(removed) == 0 {
		return out
	}
	s.recordRemoved(removed...)
	for i, item := range list {
		if _, isString := item.(string); isString {
			out[i] = redacted[i]
		}
	}
	return out
}

// isArraySecretMarker reports whether name is an array element that
// marks the next element as a credential: a bare secret CLI flag
// ("--token") or the bare HTTP auth scheme word "Bearer".
func isArraySecretMarker(name string) bool {
	return secretFlagName.MatchString(name) || bearerSchemeWord.MatchString(name)
}

// SafeObject sanitizes every field of obj with SafeValue, in key order
// so what it removes is recorded in the same order on every run.
func (s *Source) SafeObject(obj map[string]any) map[string]any {
	out := make(map[string]any, len(obj))
	for _, k := range SortedKeys(obj) {
		out[k] = s.SafeValue(k, obj[k])
	}
	return out
}

// RedactValues keeps values rules need to see (URL hosts and paths,
// booleans, numbers, non-secret strings) and replaces a value with
// [REDACTED] when its name looks like a secret or output.DefaultRedactor
// recognizes it. It is used for env and header maps.
func (s *Source) RedactValues(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for _, k := range SortedKeys(m) {
		out[k] = s.redactValue(k, m[k])
	}
	return out
}

func (s *Source) redactValue(key string, value any) any {
	defer s.enterField(key)()
	if key != "" && SecretKey(key) {
		s.recordRemovedValue(value)
		return Redacted
	}
	switch v := value.(type) {
	case map[string]any:
		return s.RedactValues(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = s.redactValue("", item)
		}
		return out
	case string:
		return s.redactString(v)
	case bool, json.Number, int64, float64, nil:
		return v
	default:
		return s.redactString(fmt.Sprint(v))
	}
}

func (s *Source) redactString(value string) string {
	if stripped, removed, ok := StripURLSecrets(value); ok {
		if removed != "" {
			s.recordRemoved(removed)
		}
		value = stripped
	}
	if output.DefaultRedactor(value) != value {
		s.recordRemoved(value)
		return Redacted
	}
	return s.tildeHome(value)
}

// secretKeyFragments are case-insensitive substrings of a field name whose
// value is always redacted.
var secretKeyFragments = []string{"token", "key", "secret", "password", "authorization", "cookie"}

// SecretKey reports whether name looks like it holds a credential: it
// contains one of secretKeyFragments, or it is an env-style credential
// name such as DB_PASS or DB_PWD (output.CredentialName), the same rule
// command-string assignments use.
func SecretKey(name string) bool {
	if output.CredentialName(name) {
		return true
	}
	n := strings.ToLower(name)
	for _, fragment := range secretKeyFragments {
		if strings.Contains(n, fragment) {
			return true
		}
	}
	return false
}

// namesEnvVar reports whether a field holds the name of an environment
// variable rather than its value, such as Codex's bearer_token_env_var.
// A string there is a variable name and is sanitized, not redacted.
func namesEnvVar(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "_env_var")
}

// redactCommandSecrets redacts "Bearer <token>" and then everything
// output.RedactCommand covers, the same table the output-side
// DefaultRedactor and the Claude Code adapter use.
func redactCommandSecrets(value string) (string, []string) {
	var removed []string
	value = bearerToken.ReplaceAllStringFunc(value, func(m string) string {
		g := bearerToken.FindStringSubmatch(m)
		removed = append(removed, g[2])
		return g[1] + " " + Redacted
	})
	value, commandRemoved := output.RedactCommand(value)
	return value, append(removed, commandRemoved...)
}

func stripEmbeddedURLSecrets(value string) (string, []string) {
	var removed []string
	value = embeddedURL.ReplaceAllStringFunc(value, func(m string) string {
		stripped, raw := StripEmbeddedURL(m)
		if raw != "" {
			removed = append(removed, raw)
		}
		return stripped
	})
	return value, removed
}

// StripEmbeddedURL strips userinfo, query, and fragment from a URL found
// inside a longer string, as text: the URL is not parsed and rebuilt, so
// nothing is re-encoded, and a URL without a host (https://:8443/x) is
// stripped all the same. A query or fragment runs to the end of the
// match. When m starts with a quote, that quoted string bounds its query
// or fragment, so legitimate old-style query separators (;, |, &&) do
// not end stripping. Outside quotes, a shell character ends it: ;, |,
// \, &&, or a trailing &. That character and the text after it are kept,
// so the evidence keeps the command's shape (?sig=x|sh keeps |sh), and
// a ? or # in that text starts another removed part. ")" and a backtick
// do not end a query, and neither does a single &, its own separator; a
// run of ")" and backticks that ends the match is kept, since it closes a
// $( ) or backtick substitution around the URL. removedRaw is the
// removed text, NUL-joined, for the "sig:" discriminator only.
func StripEmbeddedURL(m string) (stripped, removedRaw string) {
	quote := byte(0)
	if len(m) > 0 && (m[0] == '\'' || m[0] == '"') {
		quote, m = m[0], m[1:]
	}
	prefix, rest := "", m
	if sep := strings.Index(m, "://"); sep >= 0 {
		prefix, rest = m[:sep+3], m[sep+3:]
	}
	authEnd := strings.IndexAny(rest, "/?#")
	if authEnd < 0 {
		authEnd = len(rest)
	}
	auth, tail := rest[:authEnd], rest[authEnd:]
	var removed []string
	if at := strings.LastIndexByte(auth, '@'); at >= 0 {
		removed = append(removed, auth[:at])
		auth = auth[at+1:]
	}
	var b strings.Builder
	if quote != 0 {
		b.WriteByte(quote)
	}
	b.WriteString(prefix)
	b.WriteString(auth)
	for len(tail) > 0 {
		q := strings.IndexAny(tail, "?#")
		if q < 0 {
			b.WriteString(tail)
			break
		}
		b.WriteString(tail[:q])
		end := q + 1 + queryEnd(tail[q+1:], quote)
		secret := tail[q:end]
		removed = append(removed, splitSecret(secret)...)
		if quote == 0 && end == len(tail) {
			closing := len(secret)
			for closing > 0 && (secret[closing-1] == ')' || secret[closing-1] == '`') {
				closing--
			}
			b.WriteString(secret[closing:])
		}
		tail = tail[end:]
	}
	out, more := stripUserinfo(b.String())
	return out, strings.Join(append(removed, more...), "\x00")
}

// stripUserinfo removes the userinfo of every scheme://user@host left in
// text, such as a second URL after a pipe.
func stripUserinfo(text string) (string, []string) {
	var removed []string
	var b strings.Builder
	for {
		i := strings.Index(text, "://")
		if i < 0 {
			break
		}
		b.WriteString(text[:i+3])
		text = text[i+3:]
		end := strings.IndexAny(text, "/?#;|&\\")
		if end < 0 {
			end = len(text)
		}
		if at := strings.LastIndexByte(text[:end], '@'); at >= 0 {
			removed = append(removed, text[:at])
			text = text[at+1:]
		}
	}
	b.WriteString(text)
	return b.String(), removed
}

// queryEnd returns the index in s of the shell character that ends a
// query or fragment, or len(s). Inside a quoted URL, the closing quote
// already ended the embeddedURL match, so the query runs to len(s).
func queryEnd(s string, quote byte) int {
	if quote != 0 {
		return len(s)
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ';', '|', '\\':
			return i
		case '&':
			if strings.Trim(s[i:], "&") == "" || strings.HasPrefix(s[i:], "&&") {
				return i
			}
		}
	}
	return len(s)
}

// splitSecret returns the query and fragment text of secret, which starts
// with ? or #: the query whenever there is a ?, even an empty one, and
// the fragment only when it is not empty.
func splitSecret(secret string) []string {
	var out []string
	if query, ok := strings.CutPrefix(secret, "?"); ok {
		frag, hasFrag := "", false
		if h := strings.IndexByte(query, '#'); h >= 0 {
			query, frag, hasFrag = query[:h], query[h+1:], true
		}
		out = append(out, query)
		if hasFrag && frag != "" {
			out = append(out, frag)
		}
		return out
	}
	if frag := secret[1:]; frag != "" {
		out = append(out, frag)
	}
	return out
}

// StripURLSecrets reports whether raw parses as an absolute URL with a
// host and, if so, returns it without userinfo, query, or fragment.
// removedRaw is the removed text, NUL-joined, for the k1 discriminator
// only.
func StripURLSecrets(raw string) (stripped, removedRaw string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	var removed []string
	if u.User != nil {
		removed = append(removed, u.User.String())
		u.User = nil
	}
	if u.RawQuery != "" || u.ForceQuery {
		removed = append(removed, u.RawQuery)
		u.RawQuery = ""
		u.ForceQuery = false
	}
	if u.Fragment != "" {
		removed = append(removed, u.Fragment)
		u.Fragment = ""
	}
	return u.String(), strings.Join(removed, "\x00"), true
}
