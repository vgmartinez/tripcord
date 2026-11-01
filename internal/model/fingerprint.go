package model

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	fingerprintVersion = 1
	// fingerprintHexLen is the number of hex digits after "tcf_".
	// Encoding the first fingerprintHexLen/2 bytes of the SHA-256 sum
	// is exactly this many characters, and it matches fingerprintPattern.
	fingerprintHexLen = 16
)

var (
	errEmptyRule      = errors.New("fingerprint: empty rule")
	errEmptyHarness   = errors.New("fingerprint: empty location harness")
	errUnknownHarness = errors.New("fingerprint: unknown location harness")
	errUnknownScope   = errors.New("fingerprint: unknown location scope")
)

// Fingerprint returns the stable id for rule, loc, and evidence.
//
// The result is "tcf_" plus the first 16 lowercase hex characters of
// SHA-256 over a canonical UTF-8 JSON document. The same inputs always
// produce the same id across Tripcord versions. Golden tests lock the
// digest. The full write-up, including why line and event ids are
// excluded, is docs/fingerprint.md.
//
// Canonical document, encoding/json compact form, HTML escaping
// disabled, trailing encoder newline removed, keys in this order:
//
//	{"v":1,"rule":"<rule>","location":{...},"evidence":[...]}
//
// v is the integer 1.
//
// rule is the rule id byte for byte. It must be non-empty. There is no
// trimming and no case folding.
//
// location is an object. harness is required: trimmed with
// strings.TrimSpace, and must be a known harness or surface, with no
// case folding. session is strings.TrimSpace and omitted when empty.
// scope is always present: an empty loc.Scope defaults to repo, and any
// other value must be a known Scope or Fingerprint errors. scope is
// hashed, unlike line, because a path's scope is part of what the path
// names: before scope was validated per path shape (see
// normalizeScopedPath), a managed-scope path had no required shape and
// could collide, as plain text, with a repo- or user-scope path that
// happened to use the same characters. Hashing scope removes any
// reliance on path shape alone to tell the three apart. path is
// normalizeScopedPath(loc.Scope, loc.Path) and is omitted when
// loc.Path is empty; an absolute path for repo scope, a path not rooted
// at "~/" for user scope, or a relative path for managed scope, is an
// error. loc.Line is NOT hashed: a line number is volatile (an edit
// above the finding's line shifts it) and is not part of what a finding
// identifies. Line stays on Finding.Location for display.
//
// evidence is an array of items built from the non-empty normalized
// fields of each Evidence. excerpt is strings.Fields-joined with single
// spaces: Unicode white space collapsed, ends dropped. config, when
// Evidence.Config is set, is an object {id, key?}: id is
// strings.TrimSpace of Config.ID, key is strings.TrimSpace of
// Config.Key and is omitted when empty. An item whose excerpt, id, and
// key are all empty is dropped (this matters because Excerpt is
// optional on a config-only citation: a finding evidenced only by a
// config id with no excerpt must not vanish from the hash the way an
// all-whitespace excerpt does). Items are sorted by (id, key, excerpt)
// as raw strings for a deterministic order. Identical items are then
// dropped, so N repeats of the same normalized excerpt and config
// citation hash as one. The array is [] when nothing remains, never null.
//
// Evidence.Event is NEVER hashed. Event ids are ULIDs minted at
// ingest, so the same finding re-derived from a reimported transcript,
// or from a hook event deduped against its transcript copy, would
// otherwise mint a different fingerprint for the same occurrence.
//
// Evidence.Config IS hashed, unlike Event, because ConfigItem.ID (see
// ConfigItem.ID) is already content-stable: harness, scope, and
// normalized path, with no sha256, so editing the config file's body
// does not change it, and nothing mints a new one per run the way a
// ULID does. Leaving it out of the hash entirely let two findings that
// cite different config files collapse onto the same fingerprint
// whenever Location.Path was unset and the evidence carried no excerpt
// (reducing the preimage to just rule, harness, and an empty evidence
// list). Hashing the cited config id closes that collision without
// reopening the reimport-instability problem Event's exclusion solves.
//
// Config.Key is hashed too. It names one entry inside the file (an MCP
// server name, a task label, or matcher+command for a hook) and is
// derived from that entry's content, never from its position. Two
// matching entries in the same file therefore get distinct fingerprints,
// and listing them in a different order does not, because items are
// sorted by (id, key, excerpt) before hashing.
//
// Because occurrence-identifying fields (the event id) are excluded, a
// command that recurs across a session — the same shell command run
// twice, or a hook that fires on every matching tool call — produces
// evidence with the same normalized excerpt both times, so those
// repeated occurrences hash to the same fingerprint rather than minting
// a new one per repetition. A store can dedup on that fingerprint, both
// within one scan and across a reimport of the same transcript.
//
// Credential values, secret values, network URLs, and any other fields
// are not inputs. Excerpts must already be redacted. This function does
// not search them for secrets.
func Fingerprint(rule string, loc Location, evidence []Evidence) (string, error) {
	pre, err := fingerprintPreimage(rule, loc, evidence)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pre)
	// 16 hex digits are 8 bytes. Encoding that prefix is always exactly
	// fingerprintHexLen characters, never a shorter or longer id.
	raw := hex.EncodeToString(sum[:fingerprintHexLen/2])
	if len(raw) != fingerprintHexLen {
		return "", fmt.Errorf("fingerprint: digest length %d, want %d hex digits", len(raw), fingerprintHexLen)
	}
	return "tcf_" + raw, nil
}

type fingerprintDocument struct {
	V        int                   `json:"v"`
	Rule     string                `json:"rule"`
	Location fingerprintLocation   `json:"location"`
	Evidence []fingerprintEvidence `json:"evidence"`
}

type fingerprintLocation struct {
	Harness string `json:"harness"`
	Session string `json:"session,omitempty"`
	Scope   string `json:"scope"`
	Path    string `json:"path,omitempty"`
}

type fingerprintConfig struct {
	ID  string `json:"id"`
	Key string `json:"key,omitempty"`
}

type fingerprintEvidence struct {
	Config  *fingerprintConfig `json:"config,omitempty"`
	Excerpt string             `json:"excerpt,omitempty"`
}

func fingerprintPreimage(rule string, loc Location, evidence []Evidence) ([]byte, error) {
	if rule == "" {
		return nil, errEmptyRule
	}
	harness := strings.TrimSpace(string(loc.Harness))
	if harness == "" {
		return nil, errEmptyHarness
	}
	if !Harness(harness).Valid() {
		return nil, fmt.Errorf("%w: %q", errUnknownHarness, harness)
	}
	scope, err := canonicalFingerprintScope(loc.Scope)
	if err != nil {
		return nil, err
	}
	canonicalLoc := fingerprintLocation{Harness: harness, Scope: string(scope)}
	if session := strings.TrimSpace(loc.Session); session != "" {
		canonicalLoc.Session = session
	}
	if loc.Path != "" {
		path, err := normalizeScopedPath(loc.Scope, loc.Path)
		if err != nil {
			return nil, fmt.Errorf("fingerprint: location %w", err)
		}
		canonicalLoc.Path = path
	}

	items := make([]fingerprintEvidence, 0, len(evidence))
	for _, ev := range evidence {
		excerpt := strings.Join(strings.Fields(ev.Excerpt), " ")
		config := fingerprintConfigOf(ev.Config)
		if excerpt == "" && config == nil {
			continue
		}
		items = append(items, fingerprintEvidence{Config: config, Excerpt: excerpt})
	}
	slices.SortFunc(items, func(a, b fingerprintEvidence) int {
		if c := cmp.Compare(configID(a.Config), configID(b.Config)); c != 0 {
			return c
		}
		if c := cmp.Compare(configKey(a.Config), configKey(b.Config)); c != 0 {
			return c
		}
		return cmp.Compare(a.Excerpt, b.Excerpt)
	})
	items = slices.CompactFunc(items, func(a, b fingerprintEvidence) bool {
		return configID(a.Config) == configID(b.Config) && configKey(a.Config) == configKey(b.Config) && a.Excerpt == b.Excerpt
	})

	return canonicalJSON(fingerprintDocument{
		V:        fingerprintVersion,
		Rule:     rule,
		Location: canonicalLoc,
		Evidence: items,
	})
}

// fingerprintConfigOf returns the canonical config object for ref.
// A nil ref, or one whose id and key are both empty after trimming,
// returns nil so the field is omitted from the preimage.
func fingerprintConfigOf(ref *ConfigRef) *fingerprintConfig {
	if ref == nil {
		return nil
	}
	id := strings.TrimSpace(ref.ID)
	key := strings.TrimSpace(ref.Key)
	if id == "" && key == "" {
		return nil
	}
	return &fingerprintConfig{ID: id, Key: key}
}

func configID(c *fingerprintConfig) string {
	if c == nil {
		return ""
	}
	return c.ID
}

func configKey(c *fingerprintConfig) string {
	if c == nil {
		return ""
	}
	return c.Key
}

// canonicalFingerprintScope defaults an empty scope to repo and
// validates any other value against the closed Scope vocabulary.
func canonicalFingerprintScope(scope Scope) (Scope, error) {
	if scope == "" {
		return ScopeRepo, nil
	}
	if !scope.Valid() {
		return "", fmt.Errorf("%w: %q", errUnknownScope, scope)
	}
	return scope, nil
}

// k1Marker and s1Marker are the discriminator prefixes
// internal/adapters/kit.discriminated appends as the LAST element of a
// ConfigRef.Key's part array when an entry lost a secret to redaction
// (see docs/fingerprint.md). Key is compact JSON encoding that array
// (internal/adapters/kit.EvidenceKey); every earlier part can be
// arbitrary user-controlled text (a command, a header value, ...), so
// the marker must only ever be looked for, anchored, in the decoded
// last element, never as a substring of the whole JSON text.
const (
	k1Marker = "sig:k1:"
	s1Marker = "sig:s1:"
)

// FingerprintMode returns which "sig:" discriminator mode, if any,
// produced evidence's fingerprint: "k1" when a fingerprint key keyed it,
// "s1" when the structural discriminator did, or "" when no evidence
// config key carries either marker at all. The empty case is not an
// error: an entry that removed nothing to redact (Q2 in the researcher
// review) has no discriminator and its fingerprint does not depend on
// the mode, so it is deliberately the same in k1 and s1 runs. Renderers
// use this to annotate SARIF properties and JSON output with the mode,
// without hashing the mode itself or changing Fingerprint.
func FingerprintMode(evidence []Evidence) string {
	for _, ev := range evidence {
		if ev.Config == nil {
			continue
		}
		switch last := lastKeyPart(ev.Config.Key); {
		case strings.HasPrefix(last, k1Marker):
			return "k1"
		case strings.HasPrefix(last, s1Marker):
			return "s1"
		}
	}
	return ""
}

// lastKeyPart decodes key, a compact JSON array
// (internal/adapters/kit.EvidenceKey's output), and returns its last
// element, or "" if key is not that shape or is empty. The discriminator
// FingerprintMode looks for is always this last element in full, never a
// substring of an earlier, caller-controlled part: a hook whose command
// literally contains the text "sig:s1:x[0]" (as in `echo sig:s1:x[0]`)
// must not be mistaken for a discriminated entry, and an s1 entry whose
// payload happens to embed the text "sig:k1:" must not be mislabeled k1.
func lastKeyPart(key string) string {
	var parts []string
	if err := json.Unmarshal([]byte(key), &parts); err != nil || len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
