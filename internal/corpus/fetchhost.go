package corpus

import (
	"net/url"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/corpus/iplit"
	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
)

// fetchArgHosts returns unreserved hosts named by a downloader argument
// on line. A scheme-less name counts whatever its suffix, including a
// suffix that looks like a filename. A decimal, hex, or octal IPv4
// literal counts too, as do the short and dotted inet_aton forms.
//
// The shell reader marks a fetch only when it already classified the
// target as remote, so a bare name or an integer address never gets
// that mark. Those lines are still read when a downloader is piped
// into a shell or handed to a substitution.
func fetchArgHosts(line string) []string {
	if !lineReadsFetch(line) {
		return nil
	}
	fields := shellFields(line)
	seen := map[string]bool{}
	var out []string
	for i := 0; i < len(fields); i++ {
		if !isDownloader(fields[i]) {
			continue
		}
		for i++; i < len(fields); i++ {
			a := fields[i]
			if a == "" || a == "--" {
				continue
			}
			if strings.HasPrefix(a, "-") {
				if raw, ok := inlineURL(a); ok {
					addFetchHost(&out, seen, raw)
				}
				if next, urlFlag := flagValue(a); next {
					if i+1 < len(fields) {
						i++
						if urlFlag {
							addFetchHost(&out, seen, fields[i])
						}
					}
				}
				continue
			}
			addFetchHost(&out, seen, a)
		}
	}
	return out
}

func lineReadsFetch(line string) bool {
	risks := shellcmd.Risks(line)
	if slices.Contains(risks, shellcmd.Fetch) {
		return true
	}
	if !hasDownloader(line) {
		return false
	}
	return slices.Contains(risks, shellcmd.Pipe) || substitutionExec(line)
}

func hasDownloader(line string) bool {
	for _, f := range shellFields(line) {
		if isDownloader(f) {
			return true
		}
	}
	return false
}

func addFetchHost(out *[]string, seen map[string]bool, raw string) {
	host, ok := hostOf(raw)
	if !ok || seen[host] || allowedHost(host) {
		return
	}
	seen[host] = true
	*out = append(*out, host)
}

func isDownloader(word string) bool {
	w := strings.ToLower(word)
	w = strings.TrimSuffix(w, ".exe")
	if i := strings.LastIndexAny(w, `/\`); i >= 0 {
		w = w[i+1:]
	}
	switch w {
	case "curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer":
		return true
	default:
		return false
	}
}

// flagValue reports whether flag consumes the next field, and whether
// that field is the URL rather than an output path or a header.
func flagValue(flag string) (next bool, url bool) {
	if strings.Contains(flag, "=") {
		return false, false
	}
	switch strings.ToLower(flag) {
	case "--url", "--uri", "-uri":
		return true, true
	case "-o", "-O", "-d", "-D", "-H", "-A", "-e", "-u", "-K", "-b", "-c",
		"--output", "--output-document", "--data", "--data-raw", "--data-binary",
		"--data-ascii", "--header", "--user-agent", "--referer", "--user",
		"--config", "--cookie", "--cookie-jar", "--dump-header":
		return true, false
	default:
		return false, false
	}
}

func inlineURL(flag string) (string, bool) {
	lower := strings.ToLower(flag)
	for _, p := range []string{"--url=", "--uri="} {
		if v, ok := strings.CutPrefix(lower, p); ok && v != "" {
			return flag[len(p):], true
		}
	}
	return "", false
}

func shellFields(line string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'', '"', '`', ' ', '\t', '\r', '\n', '|', ';', '&', '(', ')', '<', '>':
			flush()
		default:
			b.WriteByte(line[i])
		}
	}
	flush()
	return out
}

func hostOf(arg string) (string, bool) {
	arg = strings.TrimRight(arg, ".,);]")
	if arg == "" {
		return "", false
	}
	if i := strings.Index(arg, "://"); i > 0 {
		if u, err := url.Parse(arg); err == nil {
			if h := u.Hostname(); h != "" {
				return canonicalHost(h)
			}
		}
	}
	if at := strings.LastIndex(arg, "@"); at >= 0 {
		arg = arg[at+1:]
	}
	if i := strings.IndexAny(arg, "/?#"); i >= 0 {
		arg = arg[:i]
	}
	arg = strings.Trim(arg, "[]")
	if h, ok := splitFetchPort(arg); ok {
		arg = h
	}
	return canonicalHost(arg)
}

func canonicalHost(h string) (string, bool) {
	if ip, ok := iplit.ParseIPv4(h); ok {
		return ip.String(), true
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if looseName(h) {
		return h, true
	}
	return "", false
}

func splitFetchPort(h string) (string, bool) {
	i := strings.LastIndex(h, ":")
	if i <= 0 || strings.Contains(h[:i], ":") {
		return "", false
	}
	if !allDigits(h[i+1:]) {
		return "", false
	}
	return h[:i], true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// looseName is a dotted host with no opinion about its suffix.
func looseName(h string) bool {
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabel(label) {
			return false
		}
	}
	return true
}

func hostLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(label)-1:
		default:
			return false
		}
	}
	return true
}
