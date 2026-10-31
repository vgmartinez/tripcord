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
	errLocationLine   = errors.New("fingerprint: location line must be >= 1")
)

// Fingerprint returns the stable id for rule, loc, and evidence.
//
// The result is "tcf_" plus the first 16 lowercase hex characters of
// SHA-256 over a canonical UTF-8 JSON document. The same inputs always
// produce the same id. Golden tests lock the digest. The full write-up
// is docs/fingerprint.md.
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
// path is omitted when empty after this normalization: trim space,
// replace "\" with "/", collapse repeated "/" into one "/", and strip
// a trailing "/" except when the path is "/". Dot segments are not
// resolved. line is included only for a non-nil pointer to an integer
// >= 1. A non-nil line below 1 is an error. No other location field
// is hashed.
//
// evidence is an array sorted by event, then excerpt, compared as raw
// strings (byte order). Each item keeps only event and excerpt. event
// is strings.TrimSpace. excerpt is strings.Fields (Unicode white space
// collapsed to one U+0020, ends dropped). Empty keys are omitted. An
// item whose event and excerpt are both empty is dropped. Duplicates
// are kept. The array is [] when nothing remains, never null.
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
	Line    *int   `json:"line,omitempty"`
}

type fingerprintEvidence struct {
	Event   string `json:"event,omitempty"`
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
	if path := normalizeFingerprintPath(loc.Path); path != "" {
		canonicalLoc.Path = path
	}
	if loc.Line != nil {
		if *loc.Line < 1 {
			return nil, fmt.Errorf("%w (%d)", errLocationLine, *loc.Line)
		}
		line := *loc.Line
		canonicalLoc.Line = &line
	}

	items := make([]fingerprintEvidence, 0, len(evidence))
	for _, ev := range evidence {
		item := fingerprintEvidence{
			Event:   strings.TrimSpace(ev.Event),
			Excerpt: strings.Join(strings.Fields(ev.Excerpt), " "),
		}
		if item.Event == "" && item.Excerpt == "" {
			continue
		}
		items = append(items, item)
	}
	slices.SortFunc(items, func(a, b fingerprintEvidence) int {
		if c := cmp.Compare(a.Event, b.Event); c != 0 {
			return c
		}
		return cmp.Compare(a.Excerpt, b.Excerpt)
	})

	return canonicalJSON(fingerprintDocument{
		V:        fingerprintVersion,
		Rule:     rule,
		Location: canonicalLoc,
		Evidence: items,
	})
}

func normalizeFingerprintPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = strings.ReplaceAll(path, `\`, "/")
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return path
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
