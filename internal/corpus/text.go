package corpus

import (
	"math"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
)

// hostAllowlist is the only non-reserved authority the corpus may name.
// Leave it empty until a fixture needs an exception, and record why.
var hostAllowlist = map[string]bool{}

// knownIOC are full-form indicator strings. A defanged spelling (a
// reserved host, or a bracketed dot) is not this substring.
var knownIOC = []string{
	"webhook.site",
	"pastebin.com",
	"ngrok.io",
	"burpcollaborator.net",
	"interact.sh",
	"oast.fun",
	"oast.me",
	"oast.pro",
	"oastify.com",
	"pipedream.net",
	"requestbin.com",
	"canarytokens.com",
	"hooks.slack.com",
}

const fakePrefix = "TRIPCORD-FAKE-"

const entropyMin = 40
const entropyMax = 4.5

var (
	urlRE  = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"<>]+`)
	bareRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	v4RE   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
	v6RE   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b`)

	secretRE = []*regexp.Regexp{
		regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`),
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
		regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
		regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`),
		regexp.MustCompile(`[sr]k_live_[0-9A-Za-z]{20,}`),
		regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
		regexp.MustCompile(`npm_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`hf_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`ya29\.[A-Za-z0-9._-]{20,}`),
		regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	}
)

var fileExt = map[string]bool{
	"md": true, "json": true, "yml": true, "yaml": true, "txt": true, "txtar": true,
	"go": true, "sh": true, "ps1": true, "toml": true, "png": true, "svg": true,
	"html": true, "htm": true, "js": true, "ts": true, "py": true, "mod": true,
	"sum": true, "xml": true, "csv": true, "gif": true, "jpg": true, "jpeg": true,
	"css": true, "lock": true, "bash": true, "zsh": true,
}

var testNets []*net.IPNet

// scanText runs the text checks. Without content, the file is a
// definition or a doc: only the secret and fetch-and-exec checks run.
// Without hosts, no host finding is reported; a fetch-and-exec line
// still counts a non-reserved host.
func scanText(root, rel, text string, content, hosts bool) []Finding {
	var out []Finding
	seenHost := map[string]bool{}
	addHost := func(host string) {
		if !content || !hosts || host == "" || seenHost[host] {
			return
		}
		seenHost[host] = true
		out = append(out, Finding{Root: root, Path: rel, Kind: KindHost, Detail: host})
	}
	if content {
		for _, host := range badHosts(text) {
			addHost(host)
		}
		for _, tok := range highEntropy(text) {
			out = append(out, Finding{Root: root, Path: rel, Kind: KindEntropy, Detail: clip(tok)})
		}
	}
	for _, sec := range bareSecrets(text) {
		out = append(out, Finding{Root: root, Path: rel, Kind: KindSecret, Detail: clip(sec)})
	}
	if content {
		lower := strings.ToLower(text)
		for _, ioc := range knownIOC {
			if strings.Contains(lower, ioc) {
				out = append(out, Finding{Root: root, Path: rel, Kind: KindIOC, Detail: ioc})
			}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		for _, host := range fetchArgHosts(line) {
			addHost(host)
		}
		if fetchLine(line) {
			out = append(out, Finding{Root: root, Path: rel, Kind: KindFetch, Detail: clip(strings.TrimSpace(line))})
		}
	}
	return out
}

func fetchLine(line string) bool {
	if !fetchExec(line) {
		return false
	}
	return len(badHosts(line)) > 0 || len(fetchArgHosts(line)) > 0
}

// fetchExec reports a download that is run: a pipe into a shell, or a
// substitution handed to sh -c, eval, or Invoke-Expression. shellcmd
// misses a scheme-less target and an integer address, so a downloader
// on the line counts when the shell reader did not mark a fetch.
func fetchExec(line string) bool {
	risks := shellcmd.Risks(line)
	if !slices.Contains(risks, shellcmd.Pipe) && !substitutionExec(line) {
		return false
	}
	return slices.Contains(risks, shellcmd.Fetch) || hasDownloader(line)
}

// substitutionExec is the fetch that never sets a pipe: a shell -c, eval,
// or process substitution that runs the download.
func substitutionExec(line string) bool {
	l := strings.ToLower(line)
	if strings.Contains(l, "<(") {
		return true
	}
	sub := strings.Contains(l, "$(") || strings.Contains(l, "`")
	if !sub {
		return false
	}
	return strings.Contains(l, "eval") || strings.Contains(l, "-c") || strings.Contains(l, "-command")
}

func badHosts(s string) []string {
	seen := map[string]bool{}
	var bad []string
	add := func(host string) {
		host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
		if host == "" || seen[host] || allowedHost(host) {
			return
		}
		seen[host] = true
		bad = append(bad, host)
	}
	for _, loc := range urlRE.FindAllStringIndex(s, -1) {
		raw := strings.TrimRight(s[loc[0]:loc[1]], ".,);]")
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if h := u.Hostname(); h != "" {
			add(h)
		}
	}
	for _, m := range bareRE.FindAllString(s, -1) {
		if !plausibleBare(m) {
			continue
		}
		add(m)
	}
	for _, m := range v4RE.FindAllString(s, -1) {
		add(m)
	}
	for _, m := range v6RE.FindAllString(s, -1) {
		if net.ParseIP(m) == nil {
			continue
		}
		add(m)
	}
	return bad
}

func fileName(host string) bool {
	labels := strings.Split(host, ".")
	return fileExt[strings.ToLower(labels[len(labels)-1])]
}

// plausibleTLD is the public suffixes a bare dotted word can be. A URL
// host is checked even when its suffix is absent here. Code identifiers
// such as config.kind are not.
var plausibleTLD = map[string]bool{}

func init() {
	for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		testNets = append(testNets, n)
	}
	for _, tld := range strings.Fields(`com net org io ai co sh dev app site xyz info gov edu cloud security tools aws me pro fun cc tv uk de fr ru cn jp br in au ca us eu nl se no fi es it pl ch at be nz za kr tw hk sg example invalid test localhost local onion`) {
		plausibleTLD[tld] = true
	}
}

func plausibleBare(host string) bool {
	if fileName(host) {
		return false
	}
	labels := strings.Split(strings.ToLower(host), ".")
	return plausibleTLD[labels[len(labels)-1]]
}

func allowedHost(host string) bool {
	if hostAllowlist[host] {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range testNets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return reservedName(host)
}

func reservedName(host string) bool {
	switch host {
	case "example", "invalid", "test", "localhost", "local", "onion",
		"example.com", "example.net", "example.org":
		return true
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	switch labels[len(labels)-1] {
	case "example", "invalid", "test", "localhost", "local", "onion":
		return true
	}
	tail := labels[len(labels)-2] + "." + labels[len(labels)-1]
	switch tail {
	case "example.com", "example.net", "example.org":
		return true
	default:
		return false
	}
}

func highEntropy(s string) []string {
	var hits []string
	for i := 0; i < len(s); {
		if !tokenByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && tokenByte(s[j]) {
			j++
		}
		tok := s[i:j]
		if len(tok) >= entropyMin && shannon(tok) > entropyMax && !inertMarker(s, i, j) {
			hits = append(hits, tok)
		}
		i = j
	}
	return hits
}

func tokenByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
}

func inertMarker(s string, i, j int) bool {
	return i > 0 && j < len(s) && s[i-1] == '<' && s[j] == '>'
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

func bareSecrets(s string) []string {
	var hits []string
	b := []byte(s)
	for _, re := range secretRE {
		for _, loc := range re.FindAllIndex(b, -1) {
			if fakeSecret(b, loc[0]) || !secretBoundary(b, loc[0]) {
				continue
			}
			hits = append(hits, string(b[loc[0]:loc[1]]))
		}
	}
	return hits
}

func fakeSecret(b []byte, i int) bool {
	if !bytesHasPrefixAt(b, i, fakePrefix) {
		return false
	}
	return secretBoundary(b, i-len(fakePrefix))
}

func bytesHasPrefixAt(b []byte, i int, prefix string) bool {
	return i >= len(prefix) && string(b[i-len(prefix):i]) == prefix
}

func secretBoundary(b []byte, i int) bool {
	if i == 0 {
		return true
	}
	c := b[i-1]
	return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9')
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
