package benign

import (
	"math"
	"net"
	"regexp"
	"strings"
)

// Reason length and entropy match the corpus lint's secret-shaped token
// rule: a token of 40 or more characters whose Shannon entropy is above
// 4.5 is rejected. A reason is also too short to be a review note below
// minReasonBytes, and it cannot name a URL or a host.
const (
	maxLineBytes     = 1024
	minReasonBytes   = 16
	maxReasonBytes   = 200
	reasonEntropyMin = 40
	reasonEntropyMax = 4.5
)

var (
	reasonURL  = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"<>]+`)
	reasonBare = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	reasonV4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	reasonV6   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b`)
)

// reasonTLD is the public suffixes a dotted word in a reason can be.
// A filename extension is not a host. The set matches the corpus lint.
var reasonTLD = map[string]bool{}

func init() {
	for _, tld := range strings.Fields(`com net org io ai co sh dev app site xyz info gov edu cloud security tools aws me pro fun cc tv uk de fr ru cn jp br in au ca us eu nl se no fi es it pl ch at be nz za kr tw hk sg example invalid test localhost local onion`) {
		reasonTLD[tld] = true
	}
}

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

func reasonHost(s string) bool {
	for _, m := range reasonBare.FindAllString(s, -1) {
		labels := strings.Split(strings.ToLower(m), ".")
		last := labels[len(labels)-1]
		if reasonFileExt[last] || !reasonTLD[last] {
			continue
		}
		return true
	}
	if reasonV4.MatchString(s) {
		return true
	}
	for _, m := range reasonV6.FindAllString(s, -1) {
		if net.ParseIP(m) != nil {
			return true
		}
	}
	return false
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
