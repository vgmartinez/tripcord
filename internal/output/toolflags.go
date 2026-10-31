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
// only when the command's executable is the tool listed here. This one
// table drives both the Claude Code adapter's source-side redaction and
// DefaultRedactor.
type toolFlag struct {
	tool string
	// subcommand, when set, must be the first non-flag word after the
	// executable (docker login -p, not docker run -p).
	subcommand string
	flag       string
	// glued allows the value directly after the flag (mysql -pSECRET).
	glued bool
	// separated allows "-f value" and "-f=value".
	separated bool
	pattern   *regexp.Regexp
}

var toolSecretFlags = compileToolFlags([]toolFlag{
	{tool: "openssl", flag: "-k", separated: true},
	{tool: "vercel", flag: "-t", separated: true},
	{tool: "codecov", flag: "-t", separated: true},
	{tool: "doctl", flag: "-t", separated: true},
	{tool: "influx", flag: "-t", separated: true},
	{tool: "flyctl", flag: "-t", separated: true},
	{tool: "sshpass", flag: "-p", separated: true},
	{tool: "redis-cli", flag: "-a", separated: true},
	{tool: "mysql", flag: "-p", glued: true},
	{tool: "docker", subcommand: "login", flag: "-p", separated: true},
})

func compileToolFlags(flags []toolFlag) []toolFlag {
	for i := range flags {
		separator := `(=|\s+)`
		if flags[i].glued {
			separator = `()`
		}
		flags[i].pattern = regexp.MustCompile(`(^|\s)(` + regexp.QuoteMeta(flags[i].flag) + `)` + separator + `('[^']*'|"[^"]*"|[^\s'";&|]+)`)
	}
	return flags
}

// commandWrappers run the next word as the real command.
var commandWrappers = map[string]bool{
	"sudo": true, "env": true, "exec": true, "command": true, "nohup": true, "time": true,
	"npx": true, "bunx": true, "pnpx": true, "uvx": true,
}

var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// executable returns the lowercased base name of the command words run,
// skipping leading VAR=value assignments and wrappers such as sudo or
// npx (and their own flags), and the words that follow it.
func executable(words []string) (string, []string) {
	afterWrapper := false
	for i, word := range words {
		w := strings.Trim(word, `"'`)
		switch {
		case w == "", envAssignment.MatchString(w):
		case afterWrapper && strings.HasPrefix(w, "-"):
		default:
			name := strings.ToLower(path.Base(strings.ReplaceAll(w, `\`, "/")))
			name = strings.TrimSuffix(name, ".exe")
			if commandWrappers[name] {
				afterWrapper = true
				continue
			}
			return name, words[i+1:]
		}
	}
	return "", nil
}

// flagsFor returns the tool-specific secret flags that apply to a
// command run as tool with the following words args.
func flagsFor(tool string, args []string) []toolFlag {
	var out []toolFlag
	for _, flag := range toolSecretFlags {
		if flag.tool != tool {
			continue
		}
		if flag.subcommand != "" && firstNonFlag(args) != flag.subcommand {
			continue
		}
		out = append(out, flag)
	}
	return out
}

func firstNonFlag(words []string) string {
	for _, word := range words {
		if w := strings.Trim(word, `"'`); w != "" && !strings.HasPrefix(w, "-") {
			return w
		}
	}
	return ""
}

var shellSeparator = regexp.MustCompile(`\|\||&&|[;|\n]`)

// RedactToolFlags redacts tool-specific secret flags (see toolSecretFlags)
// in a shell command string, one pipeline segment at a time, so the
// executable of each segment decides which flags apply. It returns the
// redacted text and the raw values it removed.
func RedactToolFlags(command string) (string, []string) {
	var b strings.Builder
	var removed []string
	start := 0
	locs := append(shellSeparator.FindAllStringIndex(command, -1), []int{len(command), len(command)})
	for _, loc := range locs {
		segment := command[start:loc[0]]
		tool, args := executable(strings.Fields(segment))
		for _, flag := range flagsFor(tool, args) {
			segment = flag.pattern.ReplaceAllStringFunc(segment, func(match string) string {
				g := flag.pattern.FindStringSubmatch(match)
				value := g[4]
				if placeholderSecret(value) {
					return match
				}
				removed = append(removed, strings.Trim(value, `"'`))
				return g[1] + g[2] + g[3] + quoteLike(value, redactedMarker)
			})
		}
		b.WriteString(segment)
		b.WriteString(command[loc[0]:loc[1]])
		start = loc[1]
	}
	return b.String(), removed
}

// RedactToolArgv redacts tool-specific secret flags in an argv array
// (argv[0] is the command), where a flag and its value can be two
// separate elements, as in an MCP server's command and args. It returns
// the redacted argv and the raw values it removed.
func RedactToolArgv(argv []string) ([]string, []string) {
	out := append([]string(nil), argv...)
	tool, args := executable(argv)
	flags := flagsFor(tool, args)
	if len(flags) == 0 {
		return out, nil
	}
	var removed []string
	for i := len(argv) - len(args); i < len(out); i++ {
		for _, flag := range flags {
			elem := out[i]
			switch {
			case flag.separated && elem == flag.flag && i+1 < len(out):
				if !placeholderSecret(out[i+1]) {
					removed = append(removed, out[i+1])
					out[i+1] = redactedMarker
				}
				i++
			case flag.separated && strings.HasPrefix(elem, flag.flag+"="):
				if value := elem[len(flag.flag)+1:]; !placeholderSecret(value) {
					removed = append(removed, value)
					out[i] = flag.flag + "=" + redactedMarker
				}
			case flag.glued && strings.HasPrefix(elem, flag.flag) && len(elem) > len(flag.flag):
				if value := elem[len(flag.flag):]; !placeholderSecret(value) {
					removed = append(removed, value)
					out[i] = flag.flag + redactedMarker
				}
			default:
				continue
			}
			break
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
