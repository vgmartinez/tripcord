package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

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
	// quote or the rest of a pipeline is not swallowed.
	embeddedURL = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s'"<>]+`)
)

// Sanitized is one string after sanitization: the safe text, and the raw
// substrings removed to produce it. Removed is never stored; it only
// feeds KeyDiscriminator.
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

// discriminated returns key with a "sig:" discriminator over removed
// appended when it is non-empty, so two entries that differ only by
// redacted text keep distinct keys.
func discriminated(key []string, removed []string) []string {
	if len(removed) > 0 {
		return append(key, "sig:"+KeyDiscriminator(removed))
	}
	return key
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

// KeyDiscriminator is the first 8 hex characters of SHA-256 over removed,
// NUL-joined. It is computed from the removed text, never the sanitized
// text, so it is stable across machines but differs whenever the secret
// differs.
func KeyDiscriminator(removed []string) string {
	sum := sha256.Sum256([]byte(strings.Join(removed, "\x00")))
	return hex.EncodeToString(sum[:])[:8]
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
		stripped, raw, ok := StripURLSecrets(m)
		if !ok {
			return m
		}
		if raw != "" {
			removed = append(removed, raw)
		}
		return stripped
	})
	return value, removed
}

// StripURLSecrets reports whether raw parses as an absolute URL with a
// host and, if so, returns it without userinfo, query, or fragment.
// removedRaw is the removed text, NUL-joined, for KeyDiscriminator only.
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
