package benign

import (
	"math"
	"net"
	"regexp"
	"strings"

	"github.com/vgmartinez/tripcord/internal/corpus/iplit"
)

// Reason length and entropy match the corpus lint's secret-shaped token
// rule: a token of 40 or more characters whose Shannon entropy is above
// 4.5 is rejected. A reason is also too short to be a review note below
// minReasonBytes. It is printable ASCII and cannot name a URL, a host,
// or an IP address.
const (
	maxLineBytes     = 1024
	minReasonBytes   = 16
	maxReasonBytes   = 200
	reasonEntropyMin = 40
	reasonEntropyMax = 4.5
)

var (
	reasonURL       = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://`)
	reasonV6        = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b`)
	reasonBracketed = regexp.MustCompile(`\[([^\]\s]*)\]`)
)

// reasonFileExt is the closed list of suffixes a dotted word in a
// reason may end with. Any other dotted word is treated as a host,
// whatever its suffix, so no list of top-level domains is needed.
var reasonFileExt = map[string]bool{
	"md": true, "json": true, "yml": true, "yaml": true, "txt": true, "txtar": true,
	"go": true, "sh": true, "ps1": true, "toml": true, "png": true, "svg": true,
	"html": true, "htm": true, "js": true, "ts": true, "py": true, "mod": true,
	"sum": true, "xml": true, "csv": true, "gif": true, "jpg": true, "jpeg": true,
	"css": true, "lock": true, "bash": true, "zsh": true,
}

func checkReason(reason string) error {
	if reason == "" || strings.ContainsAny(reason, "\t\r\n") {
		return errReason("bad reason")
	}
	if len(reason) < minReasonBytes || len(reason) > maxReasonBytes {
		return errReason("reason length")
	}
	for i := 0; i < len(reason); i++ {
		if reason[i] < 0x20 || reason[i] > 0x7e {
			return errReason("reason must be printable ASCII")
		}
	}
	if reasonIP(reason) {
		return errReason("reason contains an IP address")
	}
	if reasonURL.MatchString(reason) || reasonHost(reason) {
		return errReason("reason contains a URL or host")
	}
	if len(reasonEntropy(reason)) > 0 {
		return errReason("reason contains a high-entropy token")
	}
	return nil
}

type reasonError string

func errReason(s string) error { return reasonError(s) }

func (e reasonError) Error() string { return string(e) }

// reasonHost reports a dotted label.label word whose suffix is not in
// reasonFileExt. "e.g." and "v1.2" count as hosts too; spell them out.
func reasonHost(s string) bool {
	for _, w := range reasonWords(s) {
		if !strings.Contains(w, ".") {
			continue
		}
		last := strings.ToLower(w[strings.LastIndexByte(w, '.')+1:])
		if !reasonFileExt[last] {
			return true
		}
	}
	return false
}

// reasonIP reports an IPv4 literal in any inet_aton form, parsed by
// iplit as the corpus fetch-argument check does, and an IPv6 address,
// bracketed or bare. An undotted decimal or octal word is an address
// only from 1.0.0.0 up, so a small count such as "2" is not one.
func reasonIP(s string) bool {
	for _, w := range reasonWords(s) {
		ip, ok := iplit.ParseIPv4(w)
		if !ok {
			continue
		}
		lower := strings.ToLower(w)
		if strings.Contains(w, ".") || strings.HasPrefix(lower, "0x") || ip[0] != 0 {
			return true
		}
	}
	for _, m := range reasonBracketed.FindAllStringSubmatch(s, -1) {
		if net.ParseIP(m[1]) != nil {
			return true
		}
	}
	for _, m := range reasonV6.FindAllString(s, -1) {
		if net.ParseIP(m) != nil {
			return true
		}
	}
	return false
}

// reasonWords splits s into runs of letters, digits, '_', '-', and '.',
// with leading and trailing dots trimmed so a full stop is not a label.
func reasonWords(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		if !reasonWordByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && reasonWordByte(s[j]) {
			j++
		}
		if w := strings.Trim(s[i:j], "."); w != "" {
			out = append(out, w)
		}
		i = j
	}
	return out
}

func reasonWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '_' || c == '-' || c == '.'
}

func reasonEntropy(s string) []string {
	var hits []string
	for i := 0; i < len(s); {
		if !reasonToken(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && reasonToken(s[j]) {
			j++
		}
		tok := s[i:j]
		if len(tok) >= reasonEntropyMin && shannon(tok) > reasonEntropyMax {
			hits = append(hits, tok)
		}
		i = j
	}
	return hits
}

func reasonToken(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
}

func shannon(s string) float64 {
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
