package output

import (
	"path"
	"regexp"
	"strings"
)

// toolFlag is a short flag whose value is a credential only for one
// specific tool. Short flags such as -t, -k, -p, and -a mean something
// unrelated for most commands (ssh -t allocates a tty, curl -k skips TLS
// verification, docker run -p publishes a port), so they are redacted
// only when the command invokes the tool listed here. This one table
// drives both DefaultRedactor and the Claude Code adapter's source-side
// redaction.
type toolFlag struct {
	tool string
	// subcommand, when set, must appear as its own word somewhere after
	// the tool word (docker ... login ... -p, not docker run -p).
	subcommand string
	flag       string
	// glued allows the value directly after the flag (mysql -pSECRET).
	glued bool
	// separated allows "-f value" and "-f=value".
	separated bool
	// valuePrefix, when set, must start the value and is kept visible;
	// only the rest is the secret (openssl -passin pass:X, but not
	// -passin env:VAR or file:path).
	valuePrefix string
	pattern     *regexp.Regexp
}

var toolSecretFlags = compileToolFlags([]toolFlag{
	{tool: "openssl", flag: "-k", separated: true},
	{tool: "openssl", flag: "-K", separated: true},
	{tool: "openssl", flag: "-pass", separated: true, valuePrefix: "pass:"},
	{tool: "openssl", flag: "-passin", separated: true, valuePrefix: "pass:"},
	{tool: "openssl", flag: "-passout", separated: true, valuePrefix: "pass:"},
	{tool: "vercel", flag: "-t", separated: true},
	{tool: "vc", flag: "-t", separated: true},
	{tool: "codecov", flag: "-t", separated: true},
	{tool: "doctl", flag: "-t", separated: true},
	{tool: "influx", flag: "-t", separated: true},
	{tool: "flyctl", flag: "-t", separated: true},
	{tool: "fly", flag: "-t", separated: true},
	{tool: "sshpass", flag: "-p", glued: true, separated: true},
	{tool: "redis-cli", flag: "-a", separated: true},
	{tool: "redis-cli", flag: "--pass", separated: true},
	{tool: "mysql", flag: "-p", glued: true},
	{tool: "docker", subcommand: "login", flag: "-p", separated: true},
})

var knownTools = toolNameSet(toolSecretFlags)

func toolNameSet(flags []toolFlag) map[string]bool {
	set := make(map[string]bool, len(flags))
	for _, f := range flags {
		set[f.tool] = true
	}
	return set
}

func compileToolFlags(flags []toolFlag) []toolFlag {
	for i := range flags {
		var separator string
		switch {
		case flags[i].glued && flags[i].separated:
			separator = `(=|\s+|)`
		case flags[i].glued:
			separator = `()`
		default:
			separator = `(=|\s+)`
		}
		flags[i].pattern = regexp.MustCompile(`(^|\s)(` + regexp.QuoteMeta(flags[i].flag) + `)` + separator + `('[^']*'|"[^"]*"|` + unquotedCommandValue + `+)`)
	}
	return flags
}

// secretPart splits a tool flag's raw value (possibly quoted) into the
// visible prefix and the secret, or reports false when the value is not
// a secret for flag: it lacks flag.valuePrefix or is a placeholder.
func (flag toolFlag) secretPart(value string) (prefix, secret string, ok bool) {
	inner := unquote(value)
	if !strings.HasPrefix(inner, flag.valuePrefix) {
		return "", "", false
	}
	secret = inner[len(flag.valuePrefix):]
	if placeholderSecret(secret) {
		return "", "", false
	}
	return flag.valuePrefix, secret, true
}

// word is one whitespace-separated token of a command string, with its
// byte offsets in the original string.
type word struct {
	text       string
	start, end int
}

func splitWords(s string) []word {
	var words []word
	i := 0
	for i < len(s) {
		for i < len(s) && isCommandSpace(s[i]) {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && !isCommandSpace(s[i]) {
			i++
		}
		words = append(words, word{text: s[start:i], start: start, end: i})
	}
	return words
}

func isCommandSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// normalizeToolWord reduces a raw command word to the form a tool's name
// would take: strip a surrounding quote, leading shell punctuation such
// as "$(", "`", "(", or "{", and anything before the last "(" or "`" (so
// a subshell like "$(openssl ...)", "x=$(openssl ...)", or "`vercel ...`"
// still exposes the tool name), a path, a case difference,
// a trailing ".exe", and an npm-style "@version" suffix (so "vercel",
// "/usr/local/bin/vercel", "Vercel.EXE", and "vercel@latest" all
// normalize to "vercel"). It returns "" for a word that is only
// punctuation, such as a bare "(" or ")".
func normalizeToolWord(raw string) string {
	w := strings.TrimRight(strings.Trim(raw, `"'`), ")}`;")
	if i := strings.LastIndexAny(w, "(`"); i >= 0 {
		w = w[i+1:]
	}
	w = strings.TrimLeft(w, "$(){`\"'")
	if w == "" {
		return ""
	}
	w = strings.ReplaceAll(w, `\`, "/")
	name := strings.ToLower(path.Base(w))
	name = strings.TrimSuffix(name, ".exe")
	if at := strings.IndexByte(name, '@'); at > 0 {
		name = name[:at]
	}
	return name
}

// toolWordName is normalizeToolWord for a word that can name the command
// being run, or "" for one that cannot. A flag ("-C=/opt/fly") never
// names a command. A path right after a flag is usually that flag's
// argument (make -C /opt/fly -t all), so it names a command only when it
// looks like an executable: its parent directory is bin, sbin, or .bin,
// or it ends in ".exe" (sudo -E /usr/local/bin/fly -t X). A bare name
// after a flag still counts (npx --yes vercel), since wrappers take
// boolean flags before the command.
func toolWordName(prev, raw string) string {
	w := strings.TrimLeft(strings.Trim(raw, `"'`), "$(){`")
	if i := strings.LastIndexAny(w, "(`"); i >= 0 {
		w = strings.TrimLeft(w[i+1:], `"'`)
	}
	if strings.HasPrefix(w, "-") {
		return ""
	}
	if strings.ContainsAny(w, `/\`) && strings.HasPrefix(strings.Trim(prev, `"'`), "-") && !executablePath(w) {
		return ""
	}
	return normalizeToolWord(raw)
}

func executablePath(w string) bool {
	w = strings.ToLower(strings.TrimRight(strings.ReplaceAll(w, `\`, "/"), ")}`;"))
	switch path.Base(path.Dir(w)) {
	case "bin", "sbin", ".bin":
		return true
	}
	return strings.HasSuffix(w, ".exe")
}

// toolActivations maps each tool name found in words to the byte offset
// right after its first occurrence: a secret flag for that tool is only
// recognized from that point on, so an unrelated command earlier in the
// same segment cannot be mistaken for the tool invocation.
func toolActivations(words []word) map[string]int {
	activations := map[string]int{}
	for i, w := range words {
		prev := ""
		if i > 0 {
			prev = words[i-1].text
		}
		name := toolWordName(prev, w.text)
		if name == "" || !knownTools[name] {
			continue
		}
		if _, seen := activations[name]; !seen {
			activations[name] = w.end
		}
	}
	return activations
}

// wordAfter reports whether target appears as a whole word anywhere at
// or after offset, regardless of what comes between the tool word and
// it: "docker --config /c login -p X" and "docker -H tcp://h login -p X"
// both have "login" after "docker" even though neither is adjacent to it.
func wordAfter(words []word, offset int, target string) bool {
	for _, w := range words {
		if w.start < offset {
			continue
		}
		if strings.EqualFold(strings.Trim(w.text, `"'`), target) {
			return true
		}
	}
	return false
}

// shellSeparators returns the spans of the shell separators ||, &&, ;,
// |, and newline in command, left to right; a lone "&" is not one.
func shellSeparators(command string) [][]int {
	var out [][]int
	for i := 0; i < len(command); {
		j := strings.IndexAny(command[i:], ";|&\n")
		if j < 0 {
			break
		}
		i += j
		switch {
		case strings.HasPrefix(command[i:], "||"), strings.HasPrefix(command[i:], "&&"):
			out = append(out, []int{i, i + 2})
			i += 2
		case command[i] == '&':
			i++
		default:
			out = append(out, []int{i, i + 1})
			i++
		}
	}
	return out
}

// RedactToolFlags redacts tool-specific secret flags (see toolSecretFlags)
// in a shell command string. Within each pipeline segment, any word whose
// normalized name (see normalizeToolWord) matches a known tool activates
// that tool's flags for the rest of the segment, regardless of what
// precedes the tool word: a wrapper (sudo, env, npx, pnpm dlx, uvx
// --from, bash -c, a subshell), its own flags, or "sudo -u root". It
// returns the redacted text and the raw values it removed.
func RedactToolFlags(command string) (string, []string) {
	var b strings.Builder
	var removed []string
	start := 0
	locs := append(shellSeparators(command), []int{len(command), len(command)})
	for _, loc := range locs {
		segment := command[start:loc[0]]
		segment, segRemoved := redactToolFlagsInSegment(segment)
		removed = append(removed, segRemoved...)
		b.WriteString(segment)
		b.WriteString(command[loc[0]:loc[1]])
		start = loc[1]
	}
	return b.String(), removed
}

func redactToolFlagsInSegment(segment string) (string, []string) {
	words := splitWords(segment)
	activations := toolActivations(words)
	if len(activations) == 0 {
		return segment, nil
	}
	var removed []string
	for _, flag := range toolSecretFlags {
		offset, ok := activations[flag.tool]
		if !ok {
			continue
		}
		if flag.subcommand != "" && !wordAfter(words, offset, flag.subcommand) {
			continue
		}
		suffix := flag.pattern.ReplaceAllStringFunc(segment[offset:], func(match string) string {
			g := flag.pattern.FindStringSubmatch(match)
			value := g[4]
			prefix, secret, ok := flag.secretPart(value)
			if !ok {
				return match
			}
			removed = append(removed, secret)
			return g[1] + g[2] + g[3] + quoteLike(value, prefix+redactedMarker)
		})
		segment = segment[:offset] + suffix
	}
	return segment, removed
}

// RedactToolArgv redacts tool-specific secret flags in an argv array
// (argv[0] is the command, as in an MCP server's command plus args), the
// same way RedactToolFlags does for a command string: any element's word
// matching a known tool (including a merged element such as command
// "npx vercel") activates that tool's flags for elements from that point
// on. It returns the redacted argv and the raw values it removed.
func RedactToolArgv(argv []string) ([]string, []string) {
	out := append([]string(nil), argv...)
	type elemWord struct {
		elem int
		text string
	}
	var words []elemWord
	for i, elem := range argv {
		for _, w := range strings.Fields(elem) {
			words = append(words, elemWord{elem: i, text: w})
		}
	}
	activations := map[string]int{}
	for i, w := range words {
		prev := ""
		if i > 0 {
			prev = words[i-1].text
		}
		name := toolWordName(prev, w.text)
		if name == "" || !knownTools[name] {
			continue
		}
		if _, seen := activations[name]; !seen {
			activations[name] = w.elem
		}
	}
	if len(activations) == 0 {
		return out, nil
	}
	var removed []string
	for _, flag := range toolSecretFlags {
		anchor, ok := activations[flag.tool]
		if !ok {
			continue
		}
		if flag.subcommand != "" {
			found := false
			for _, w := range words {
				if w.elem >= anchor && strings.EqualFold(strings.Trim(w.text, `"'`), flag.subcommand) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		for i := anchor; i < len(out); i++ {
			elem := out[i]
			switch {
			case flag.separated && elem == flag.flag && i+1 < len(out):
				if prefix, secret, ok := flag.secretPart(out[i+1]); ok {
					removed = append(removed, secret)
					out[i+1] = prefix + redactedMarker
				}
				i++
			case flag.separated && strings.HasPrefix(elem, flag.flag+"="):
				if prefix, secret, ok := flag.secretPart(elem[len(flag.flag)+1:]); ok {
					removed = append(removed, secret)
					out[i] = flag.flag + "=" + prefix + redactedMarker
				}
			case flag.glued && strings.HasPrefix(elem, flag.flag) && len(elem) > len(flag.flag):
				if prefix, secret, ok := flag.secretPart(elem[len(flag.flag):]); ok {
					removed = append(removed, secret)
					out[i] = flag.flag + prefix + redactedMarker
				}
			}
		}
	}
	return out, removed
}

// quoteLike returns replacement wrapped in the same quotes as value, if
// value is quoted.
func quoteLike(value, replacement string) string {
	if len(value) >= 2 {
		quote := value[0]
		if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
			return string(quote) + replacement + string(quote)
		}
	}
	return replacement
}
