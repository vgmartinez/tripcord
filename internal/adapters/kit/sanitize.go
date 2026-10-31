package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
	"github.com/vgmartinez/tripcord/internal/pathx"
)

// Redacted replaces secret values in payloads and evidence keys.
const Redacted = "[REDACTED]"

var (
	commandSecretFlag = regexp.MustCompile(`(?i)(` + output.SecretFlagAlternation() + `)(?:=|\s+)('[^']*'|"[^"]*"|\S+)`)
	secretFlagName    = regexp.MustCompile(`(?i)^(?:` + output.SecretFlagAlternation() + `)$`)
	bearerToken       = regexp.MustCompile(`(?i)\b(bearer)\s+([^\s'"]+)`)
	bearerSchemeWord  = regexp.MustCompile(`(?i)^bearer$`)
	userFlagName      = regexp.MustCompile(`(?i)^(?:` + output.UserFlagAlternation + `)$`)
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
// also recorded for the next Add's key discriminator.
func (s *Source) Sanitize(value string) Sanitized {
	value, removed := stripEmbeddedURLSecrets(value)
	value, flags := redactCommandSecrets(value)
	removed = append(removed, flags...)
	value = s.tildeHome(value)
	if redacted := output.DefaultRedactor(value); redacted != value {
		removed = append(removed, value)
		value = redacted
	}
	s.recordRemoved(removed...)
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

// SecretKey reports whether name looks like it holds a credential.
func SecretKey(name string) bool {
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

func redactCommandSecrets(value string) (string, []string) {
	var removed []string
	value = commandSecretFlag.ReplaceAllStringFunc(value, func(m string) string {
		g := commandSecretFlag.FindStringSubmatch(m)
		removed = append(removed, g[2])
		return g[1] + " " + Redacted
	})
	value = bearerToken.ReplaceAllStringFunc(value, func(m string) string {
		g := bearerToken.FindStringSubmatch(m)
		removed = append(removed, g[2])
		return g[1] + " " + Redacted
	})
	return value, removed
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
