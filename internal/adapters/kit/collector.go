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
// user scope only), and a key whose text lost a secret carries a short
// discriminator hashed from the removed text so two different secrets
// never share a fingerprint.
package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/vgmartinez/tripcord/internal/adapters"
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
}

// NewCollector returns a collector whose diagnostics are attributed to
// harness. product is the human name used in diagnostic text.
func NewCollector(harness model.Harness, product string) *Collector {
	return &Collector{harness: harness, product: product}
}

// SetHome records the home directory rewritten as "~" in user-scope
// values. It is never applied to repository or managed scope.
func (c *Collector) SetHome(home string) { c.home = home }

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

// Add emits one item. key is sanitized and encoded as payload["key"]: the
// content-derived evidence key, which never encodes a position in the
// file. payload values must already be sanitized.
func (s *Source) Add(kind model.ConfigKind, key []string, payload map[string]any) {
	for name, value := range s.fields {
		payload[name] = value
	}
	payload["key"] = EvidenceKey(s.SafeKey(key))
	raw, err := json.Marshal(payload)
	if err != nil {
		s.Warn("cannot encode %s entry: %v", kind, err)
		return
	}
	item := model.ConfigItem{Harness: s.harness, Scope: s.scope, Path: s.path, SHA256: s.sha, Kind: kind, Payload: raw}
	if err := item.Validate(); err != nil {
		s.Warn("cannot represent entry: %v", err)
		return
	}
	s.c.items = append(s.c.items, item)
}

// EvidenceKey encodes parts as a compact JSON array, so no choice of
// separator inside a matcher or command can make two keys collide.
func EvidenceKey(parts []string) string {
	raw, _ := json.Marshal(parts)
	return string(raw)
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
