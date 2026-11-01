// Package kit holds the normalization helpers that the Codex, Cursor,
// Copilot, and shared-surface adapters have in common: a collector for
// items and diagnostics, source-side sanitization of evidence keys and
// payloads, strict JSON, JSONC, YAML, and TOML decoders that report
// duplicate and case-variant keys, and a bounded repository walk.
//
// The rules mirror the Claude Code adapter's: evidence keys and payloads
// are sanitized before they become items (URL userinfo, query, and
// fragment removed; secret CLI flags, bearer tokens, and secret-looking
// env and header values redacted; the home directory rewritten as "~" in
// user scope only), and a key whose text lost a secret carries a "sig:"
// discriminator: an HMAC of the removed text under the fingerprint key
// (k1), or, with no key, the structure of what was removed and an
// ordinal (s1). Neither is an unkeyed hash of a secret.
package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
)

// Collector accumulates items and diagnostics for one Discover call.
type Collector struct {
	harness model.Harness
	// Product names the harness in diagnostics, e.g. "Codex".
	product string
	home    string
	items   []model.ConfigItem
	diags   []adapters.Diagnostic
	// key selects the k1 discriminator when present (see discriminated).
	key *fpkey.Key
	// ordinals counts s1 entries per file and key prefix.
	ordinals map[string]int
}

// NewCollector returns a collector whose diagnostics are attributed to
// harness. product is the human name used in diagnostic text.
func NewCollector(harness model.Harness, product string) *Collector {
	return &Collector{harness: harness, product: product}
}

// SetHome records the home directory rewritten as "~" in user-scope
// values. It is never applied to repository or managed scope.
func (c *Collector) SetHome(home string) { c.home = home }

// SetFingerprintKey selects the k1 discriminator for entries that lost a
// secret. A nil key selects s1.
func (c *Collector) SetFingerprintKey(k *fpkey.Key) { c.key = k }

// ordinal returns how many earlier entries of the same file had key and
// part as their key so far, and counts this one. The map key is a
// cheap NUL-separated join, not JSON, since it is never compared across
// processes or stored: ordinal() is called once per entry on top of the
// JSON encoding its caller already pays for key, so a second
// json.Marshal here would double that cost for no benefit.
func (c *Collector) ordinal(harness model.Harness, scope model.Scope, path string, kind model.ConfigKind, key []string, part string) int {
	if c.ordinals == nil {
		c.ordinals = map[string]int{}
	}
	var b strings.Builder
	b.WriteString(string(harness))
	b.WriteByte(0)
	b.WriteString(string(scope))
	b.WriteByte(0)
	b.WriteString(path)
	b.WriteByte(0)
	b.WriteString(string(kind))
	for _, p := range key {
		b.WriteByte(0)
		b.WriteString(p)
	}
	b.WriteByte(0)
	b.WriteString(part)
	id := b.String()
	n := c.ordinals[id]
	c.ordinals[id] = n + 1
	return n
}

// Warn records a diagnostic that makes the scan incomplete.
func (c *Collector) Warn(scope model.Scope, path, format string, args ...any) {
	c.Note(scope, path, false, format, args...)
}

// Note records a diagnostic; informational notes do not change the exit
// code.
func (c *Collector) Note(scope model.Scope, path string, informational bool, format string, args ...any) {
	c.diags = append(c.diags, adapters.Diagnostic{
		Harness:       c.harness,
		Scope:         scope,
		Path:          path,
		Message:       fmt.Sprintf(format, args...),
		Informational: informational,
	})
}

// Append adds items and diagnostics produced elsewhere, such as by the
// Claude adapter's skill normalizer.
func (c *Collector) Append(items []model.ConfigItem, diags []adapters.Diagnostic) {
	c.items = append(c.items, items...)
	c.diags = append(c.diags, diags...)
}

// Items returns the items collected so far, in insertion order.
func (c *Collector) Items() []model.ConfigItem { return c.items }

// Diagnostics returns the diagnostics collected so far.
func (c *Collector) Diagnostics() []adapters.Diagnostic { return c.diags }

// Result sorts items deterministically and returns them with a
// *adapters.DiagnosticError when any diagnostic was recorded.
func (c *Collector) Result() ([]model.ConfigItem, error) {
	sort.SliceStable(c.items, func(i, j int) bool {
		x, y := c.items[i], c.items[j]
		if x.Scope != y.Scope {
			return x.Scope < y.Scope
		}
		if x.Path != y.Path {
			return x.Path < y.Path
		}
		if x.Harness != y.Harness {
			return x.Harness < y.Harness
		}
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		return string(x.Payload) < string(y.Payload)
	})
	if len(c.diags) > 0 {
		return c.items, &adapters.DiagnosticError{Diagnostics: c.diags}
	}
	return c.items, nil
}

// Source is one file being normalized.
type Source struct {
	c       *Collector
	harness model.Harness
	scope   model.Scope
	path    string
	sha     string
	fields  map[string]any
	// removed is every raw value sanitization removed since the last
	// Add, in the order it was removed; Add discriminates on it.
	removed []Removal
	// field is the top-level payload field removals are attributed to
	// (see enterField).
	field string
	// sanitized memoizes Sanitize, keyed by its input.
	sanitized map[string]Sanitized
	// presanitized reports strings Sanitize may return as they are (see
	// TrustSanitized).
	presanitized func(string) bool
}

// recordRemoved rewrites the home directory in each value (user scope
// only, see tildeHome) so the discriminator does not depend on who ran
// the scan.
func (s *Source) recordRemoved(raw ...string) {
	for _, r := range raw {
		s.removed = append(s.removed, Removal{Field: s.field, Value: s.tildeHome(r)})
	}
}

// recordRemovedValue records a decoded value that was replaced whole.
func (s *Source) recordRemovedValue(value any) {
	if text, ok := value.(string); ok {
		s.recordRemoved(text)
		return
	}
	raw, _ := json.Marshal(value)
	s.recordRemoved(string(raw))
}

// WithField adds name=value to the payload of every item this source
// emits, for file-level facts such as a trust status. It is never part of
// the evidence key.
func (s *Source) WithField(name string, value any) *Source {
	if s.fields == nil {
		s.fields = map[string]any{}
	}
	s.fields[name] = value
	return s
}

// Source starts normalizing raw, read from the logical path in scope.
// Items are attributed to the collector's harness.
func (c *Collector) Source(scope model.Scope, path string, raw []byte) *Source {
	sum := sha256.Sum256(raw)
	return c.SourceSHA(scope, path, hex.EncodeToString(sum[:]))
}

// SourceSHA is Source for a file whose SHA-256 was computed while
// streaming it.
func (c *Collector) SourceSHA(scope model.Scope, path, sha string) *Source {
	return &Source{c: c, harness: c.harness, scope: scope, path: path, sha: sha}
}

// TrustSanitized makes Sanitize return a string f reports as already
// sanitized as it is, with nothing removed. It is for an adapter that
// runs the same string sanitization itself and signs its own output
// (see EntryKey): re-sanitizing that text protects nothing, since
// it is already in the payload as written, while kit's key and array
// rules still apply to the whole entry.
func (s *Source) TrustSanitized(f func(string) bool) *Source {
	s.presanitized = f
	return s
}

// WithHarness attributes the source's items to harness instead of the
// collector's, for a file another product owns (a VS Code surface read by
// the shared adapter). Diagnostics stay attributed to the collector.
func (s *Source) WithHarness(h model.Harness) *Source {
	s.harness = h
	return s
}

// Scope is the source's scope.
func (s *Source) Scope() model.Scope { return s.scope }

// Path is the source's logical path.
func (s *Source) Path() string { return s.path }

// Product is the human harness name for diagnostic text.
func (s *Source) Product() string { return s.c.product }

// Warn records a diagnostic against this file.
func (s *Source) Warn(format string, args ...any) { s.c.Warn(s.scope, s.path, format, args...) }

// Note records an informational diagnostic against this file: something
// a reviewer should know that does not make the scan incomplete.
func (s *Source) Note(format string, args ...any) {
	s.c.Note(s.scope, s.path, true, format, args...)
}

// WarnAll records each decoder warning against this file.
func (s *Source) WarnAll(warnings []string) {
	for _, w := range warnings {
		s.Warn("%s", w)
	}
}

// Len is how many items this source's collector holds.
func (s *Source) Len() int { return len(s.c.items) }

// MarkLine sets the 1-based source line of the item added after before
// items were present. A rejected add does not move the count, and no
// line is recorded.
func (s *Source) MarkLine(before, line int) {
	if line < 1 || len(s.c.items) <= before {
		return
	}
	s.c.items[len(s.c.items)-1].Line = line
}

// MarkHidden attaches hidden code points to the item added after before.
func (s *Source) MarkHidden(before int, hidden model.HiddenChars) {
	if len(s.c.items) <= before {
		return
	}
	s.c.items[len(s.c.items)-1].Hidden = hidden
}

// Add emits one item. key is sanitized, has a content digest of the full
// sanitized payload appended (see PayloadDigest), then a discriminator
// over every raw value sanitization removed while building the entry
// (see discriminated), and is encoded as payload["key"]: the
// content-derived evidence key, which never encodes a position in the
// file. The digest means two entries whose caller-supplied key parts
// match, but whose other fields differ (a second "uses" step with a
// different "with", a hook whose non-primary action field differs, an
// env value, an "args" element, ...), never share a key or a fingerprint;
// the discriminator means the same holds when they differ only in
// something redaction replaced with [REDACTED]. payload values must
// already be sanitized by this Source, and nothing else may be sanitized
// between building one entry and adding it.
func (s *Source) Add(kind model.ConfigKind, key []string, payload map[string]any) {
	s.add(kind, key, payload, nil, nil)
}

// AddDetect is Add with the entry as the file wrote it, for rules to
// evaluate (see model.ConfigItem.Detect). raw is the source object: each
// of its fields replaces the sanitized field of the same name in a copy
// of the final payload, except the names in keep, which keep their
// payload value: redacted maps, and fields the adapter sets itself
// (event, matcher, name), which a raw field must not override. raw is
// not sanitized, memoized, hashed, or part of the key.
func (s *Source) AddDetect(kind model.ConfigKind, key []string, payload, raw map[string]any, keep ...string) {
	s.add(kind, key, payload, raw, keep)
}

func (s *Source) add(kind model.ConfigKind, key []string, payload, rawFields map[string]any, keep []string) {
	removed := s.removed
	s.removed = nil
	defer func() { s.removed = nil }()
	// The digest is computed before s.fields are merged in: those are
	// file-level facts such as project_trust that can depend on which
	// scopes this scan read, not on the file's own content, and must
	// never affect the key (see WithField).
	fullKey := append(s.SafeKey(key), "sig:"+PayloadDigest(payload))
	fullKey = s.discriminated(kind, fullKey, removed, payload)
	for name, value := range s.fields {
		payload[name] = value
	}
	payload["key"] = EvidenceKey(fullKey)
	raw, err := json.Marshal(payload)
	if err != nil {
		s.Warn("cannot encode %s entry: %v", kind, err)
		return
	}
	item := model.ConfigItem{Harness: s.harness, Scope: s.scope, Path: s.path, SHA256: s.sha, Kind: kind, Payload: raw}
	if rawFields != nil {
		keep = append(slices.Clone(keep), "key")
		for name := range s.fields {
			keep = append(keep, name)
		}
		item.Detect = DetectView(payload, rawFields, keep)
	}
	if err := item.Validate(); err != nil {
		s.Warn("cannot represent entry: %v", err)
		return
	}
	s.c.items = append(s.c.items, item)
}

// DetectView encodes payload with each field of raw in place of the
// sanitized one, except the names in keep (see Source.AddDetect). It
// returns nil when the view cannot be encoded, so rules fall back to the
// sanitized payload.
func DetectView(payload, raw map[string]any, keep []string) model.DetectPayload {
	view := maps.Clone(payload)
	for k, v := range raw {
		if !slices.Contains(keep, k) {
			view[k] = v
		}
	}
	out, err := json.Marshal(view)
	if err != nil {
		return nil
	}
	return out
}

// EntryKey returns the evidence key parts Add would build for kind, the
// already-sanitized key, and payload, for an adapter that builds its
// items itself (the Claude adapter): key, a digest of payload as this
// Source sanitizes it, so a value the caller left raw never feeds the
// digest, then a discriminator over removed (what the caller's own
// sanitization removed, in a deterministic order) followed by what this
// Source's sanitization of payload removed.
func (s *Source) EntryKey(kind model.ConfigKind, key []string, payload map[string]any, removed []Removal) []string {
	s.removed = nil
	for _, r := range removed {
		restore := s.enterField(r.Field)
		s.recordRemoved(r.Value)
		restore()
	}
	view, _ := s.SafeValue("", payload).(map[string]any)
	all := s.removed
	s.removed = nil
	return s.discriminated(kind, append(slices.Clone(key), "sig:"+PayloadDigest(view)), all, view)
}

// EvidenceKey encodes parts as a compact JSON array, so no choice of
// separator inside a matcher or command can make two keys collide.
func EvidenceKey(parts []string) string {
	raw, _ := json.Marshal(parts)
	return string(raw)
}

// PayloadDigest is a stable content hash of payload (computed before
// payload["key"] is set): the first 16 hex characters of the SHA-256 of
// its canonical JSON encoding. encoding/json sorts object keys at every
// level of nesting, so the digest depends only on payload's content, not
// on Go's randomized map iteration order. It is appended to every
// evidence key (see Add) so two entries whose other key parts match but
// whose full sanitized content differs still get distinct keys and
// fingerprints: without it, a tool that merges findings by fingerprint
// (for example GitHub's SARIF alert de-duplication) could let a benign
// entry hide a hostile one that happened to share the same first fields.
func PayloadDigest(payload map[string]any) string {
	raw, err := json.Marshal(payload)
	if err != nil {
		// payload holds only JSON-decoded values plus strings, bools,
		// and sanitized copies of those, so Marshal cannot fail here in
		// practice; the caller's own json.Marshal(payload) call just
		// below would fail identically and is what reports the problem.
		return strings.Repeat("0", 16)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

// SortedKeys returns the keys of m in byte order.
func SortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
