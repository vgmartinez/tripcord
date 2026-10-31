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
	fingerprintHexLen  = 16
)

var (
	errEmptyRule      = errors.New("fingerprint: empty rule")
	errEmptyHarness   = errors.New("fingerprint: empty location harness")
	errUnknownHarness = errors.New("fingerprint: unknown location harness")
)

// Fingerprint returns the stable id for rule, loc, and evidence.
//
// The result is "tcf_" plus the first 16 lowercase hex characters of
// SHA-256 over a canonical UTF-8 JSON document. The same inputs always
// produce the same id across Tripcord versions. Golden tests lock the
// digest. The full write-up, including why line, event ids, and config
// ids are excluded, is docs/fingerprint.md.
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
// location is an object. harness is required. It is trimmed with
// strings.TrimSpace and must be a known harness or surface. There is
// no case folding. session is strings.TrimSpace and omitted when empty.
// path is normalizeScopedPath(loc.Scope, loc.Path) (an empty scope is
// repo scope) and is omitted when loc.Path is empty; an absolute path
// for repo scope, or a path not rooted at "~/" for user scope, is an
// error. loc.Line is NOT hashed: a line number is volatile (an edit
// above the finding's line shifts it) and is not part of what a finding
// identifies. Line stays on Finding.Location for display. loc.Scope is
// also not hashed; it is already implied by the normalized path's shape
// (relative, "~/"-rooted, or managed-absolute), so including it would
// not disambiguate anything further.
//
// evidence is an array of the normalized, non-empty excerpts, sorted as
// raw strings (byte order); duplicates are kept. Each evidence excerpt
// is strings.Fields-joined with single spaces (Unicode white space
// collapsed, ends dropped); an item that normalizes to "" is dropped.
// Evidence.Event and Evidence.Config are NOT hashed. Event ids are
// ULIDs minted at ingest, so the same finding re-derived from a
// reimported transcript, or from a hook event deduped against its
// transcript copy, would otherwise get a different id for the same
// occurrence; config ids are comparatively stable (see ConfigItem.ID)
// but are left out too, for the same one-input-shape rule: a finding's
// identity is the rule, the location, and what the evidence says, not
// which record happens to cite it. The array is [] when nothing
// remains, never null.
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
	return "tcf_" + hex.EncodeToString(sum[:])[:fingerprintHexLen], nil
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
	Path    string `json:"path,omitempty"`
}

type fingerprintEvidence struct {
	Excerpt string `json:"excerpt,omitempty"`
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
	canonicalLoc := fingerprintLocation{Harness: harness}
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
		if excerpt == "" {
			continue
		}
		items = append(items, fingerprintEvidence{Excerpt: excerpt})
	}
	slices.SortFunc(items, func(a, b fingerprintEvidence) int {
		return cmp.Compare(a.Excerpt, b.Excerpt)
	})

	return canonicalJSON(fingerprintDocument{
		V:        fingerprintVersion,
		Rule:     rule,
		Location: canonicalLoc,
		Evidence: items,
	})
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
