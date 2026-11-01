// Package shellcmd reads a hook command line the way a shell splits it,
// without running anything, and reports what in it fetches or runs code
// from the network. It backs the shell.risks CEL function, so a rule
// does not have to parse shell syntax with regular expressions.
//
// Every simple command is read in its own quoting: quotes, separators,
// and pipes are found per command, not per line. A wrapper is unwrapped
// and its payload read as a command line of its own, with the same
// rules and exemptions: sudo, env, exec, command, a shell's -c,
// PowerShell's -Command or positional command, cmd /c, eval, iex, and
// $( ), backtick, and <( ) substitutions.
//
// Static limits: variables are not expanded, so $URL is not a target
// and $(echo cur)l is not curl. nohup, xargs, env -S, busybox, and
// start /b are not unwrapped. A script a hook calls is not read.
package shellcmd

import (
	"net"
	"net/url"
	"slices"
	"strings"
)

// Risks a command line can carry.
const (
	// Fetch is a downloader or remote package runner in command
	// position with a target that is not loopback.
	Fetch = "fetch"
	// Pipe is an unquoted pipe into a shell or Invoke-Expression,
	// except a relative script piped into a bare shell (./x.sh | sh).
	Pipe = "pipe"
	// Encoded is a PowerShell -EncodedCommand, an opaque payload.
	Encoded = "encoded"
)

// maxDepth bounds how far nested payloads are read.
const maxDepth = 8

// Risks reports the risks in a command line, in the order Fetch, Pipe,
// Encoded, each at most once.
func Risks(line string) []string {
	var s scanner
	s.line(line, 0)
	return s.risks()
}

// RisksArgv reports the risks in an argument vector that no shell
// splits, such as a hook's exec and args. A pipe character in an
// argument is literal; a wrapper's payload is still read as a command
// line.
func RisksArgv(argv []string) []string {
	var s scanner
	s.command(argv, 0, false)
	return s.risks()
}

type scanner struct {
	fetch, pipe, encoded bool
}

func (s *scanner) risks() []string {
	out := []string{}
	if s.fetch {
		out = append(out, Fetch)
	}
	if s.pipe {
		out = append(out, Pipe)
	}
	if s.encoded {
		out = append(out, Encoded)
	}
	return out
}

func (s *scanner) line(src string, depth int) {
	if depth > maxDepth || strings.TrimSpace(src) == "" {
		return
	}
	toks, subs := lex(src)
	for _, sub := range subs {
		s.line(sub, depth+1)
	}
	if dotNetDownload(src) {
		s.fetch = true
	}
	cmds := split(toks)
	for i, c := range cmds {
		s.command(c.words, depth, i < len(cmds)-1)
		if c.pipeIn && pipeTarget(c.words) && !localPipe(cmds, i) {
			s.pipe = true
		}
	}
}

// command reads one simple command. followed is set when another
// command comes after it on the same line.
func (s *scanner) command(words []string, depth int, followed bool) {
	w := unwrap(words)
	if len(w) == 0 {
		return
	}
	name, args := progName(w[0]), w[1:]
	switch {
	case posixShells[name]:
		if p, ok := shellPayload(name, args); ok {
			s.line(p, depth+1)
		}
	case name == "powershell" || name == "pwsh":
		p, encoded := psPayload(args)
		if encoded {
			s.encoded = true
		}
		s.line(p, depth+1)
	case name == "cmd":
		if p, ok := cmdPayload(args); ok {
			s.line(p, depth+1)
		}
	case name == "eval" || name == "iex" || name == "invoke-expression":
		s.line(strings.Join(args, " "), depth+1)
	default:
		if fetches(name, args, followed) {
			s.fetch = true
		}
	}
}

var posixShells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"ash": true, "fish": true, "csh": true, "tcsh": true,
}

// pipeShells run what they read on standard input.
var pipeShells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"ash": true, "fish": true, "csh": true, "tcsh": true,
	"cmd": true, "powershell": true, "pwsh": true,
	"iex": true, "invoke-expression": true,
}

// bareShells are the shells the ./x.sh | sh exemption accepts.
var bareShells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "ksh": true}

// reserved words that can start a command before the program name.
var reserved = map[string]bool{
	"!": true, "{": true, "}": true, "if": true, "then": true, "else": true,
	"elif": true, "do": true, "while": true, "until": true, "time": true,
}

// unwrap drops assignments, reserved words, and the wrappers that run
// the rest of the command unchanged. It returns nil for command -v,
// which only looks a name up.
func unwrap(w []string) []string {
	for len(w) > 0 {
		if isAssignment(w[0]) || reserved[w[0]] {
			w = w[1:]
			continue
		}
		switch progName(w[0]) {
		case "sudo", "doas":
			w = skipOptions(w[1:], sudoValues)
		case "env":
			w = skipOptions(w[1:], envValues)
		case "exec":
			w = skipOptions(w[1:], map[string]bool{"-a": true})
		case "command":
			if len(w) > 1 && (w[1] == "-v" || w[1] == "-V") {
				return nil
			}
			w = skipOptions(w[1:], nil)
		default:
			return w
		}
	}
	return w
}

var sudoValues = map[string]bool{
	"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true,
	"-r": true, "-t": true, "-T": true, "-U": true,
	"--user": true, "--group": true, "--host": true, "--prompt": true,
	"--close-from": true, "--chdir": true, "--role": true, "--type": true,
	"--command-timeout": true, "--other-user": true,
}

var envValues = map[string]bool{"-u": true, "--unset": true, "-C": true, "--chdir": true}

// skipOptions drops leading options and the values of those in valued.
func skipOptions(args []string, valued map[string]bool) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:]
		}
		if len(a) < 2 || a[0] != '-' {
			return args
		}
		args = args[1:]
		if valued[a] && len(args) > 0 {
			args = args[1:]
		}
	}
	return args
}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := w[i]
		if c != '_' && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(i > 0 && isDigit(c)) {
			return false
		}
	}
	return true
}

// progName is the lower-case base name of a program, without .exe,
// .cmd, or .bat.
func progName(w string) string {
	if i := strings.LastIndexAny(w, `/\`); i >= 0 {
		w = w[i+1:]
	}
	w = strings.ToLower(w)
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		w = strings.TrimSuffix(w, ext)
	}
	return w
}

// shellPayload returns the command string of sh -c and the other POSIX
// shells. Options are skipped with their values (-o pipefail, -O opt,
// --rcfile file), and -- ends them. Without -c the first operand is a
// script file, not a payload.
func shellPayload(name string, args []string) (string, bool) {
	want := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if want && i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case strings.HasPrefix(a, "--"):
			flag, value, inline := strings.Cut(a, "=")
			switch flag {
			case "--command":
				if inline {
					return value, true
				}
				want = true
			case "--rcfile", "--init-file", "--init-command":
				if !inline {
					i++
				}
			}
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			for _, f := range a[1:] {
				switch {
				case f == 'c':
					want = true
				case f == 'o' || f == 'O' || (f == 'C' && name == "fish"):
					i++
				}
			}
		default:
			if want {
				return a, true
			}
			return "", false
		}
	}
	return "", false
}

// PowerShell parameter kinds.
const (
	psSwitch = iota
	psValue
	psCommand
	psEncoded
	psFile
)

// psPayload returns the command PowerShell runs: the -Command value and
// every argument after it, or the first positional argument and the rest.
// encoded is set for -EncodedCommand. -File runs a script, not a payload.
func psPayload(args []string) (payload string, encoded bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			return strings.Join(args[i:], " "), false
		}
		name, value, inline := strings.Cut(strings.TrimLeft(a, "-"), ":")
		switch psParam(strings.ToLower(name)) {
		case psEncoded:
			return "", true
		case psCommand:
			rest := args[i+1:]
			if inline {
				rest = append([]string{value}, rest...)
			}
			return strings.Join(rest, " "), false
		case psFile:
			return "", false
		case psValue:
			if !inline {
				i++
			}
		}
	}
	return "", false
}

// psParam resolves a PowerShell parameter name, which may be any prefix
// PowerShell accepts.
func psParam(n string) int {
	switch {
	case n == "e" || n == "ec" || prefixOf(n, "encodedcommand", 2):
		return psEncoded
	case n == "c" || prefixOf(n, "command", 2) || n == "cwa" || prefixOf(n, "commandwithargs", 8):
		return psCommand
	case n == "f" || prefixOf(n, "file", 2):
		return psFile
	case n == "ex" || n == "ep" || prefixOf(n, "executionpolicy", 2),
		n == "w" || prefixOf(n, "windowstyle", 2),
		n == "wd" || prefixOf(n, "workingdirectory", 2),
		prefixOf(n, "version", 1),
		n == "o" || n == "of" || prefixOf(n, "outputformat", 2),
		n == "if" || prefixOf(n, "inputformat", 3),
		n == "config" || prefixOf(n, "configurationname", 4), prefixOf(n, "configurationfile", 14),
		prefixOf(n, "custompipename", 2),
		prefixOf(n, "settingsfile", 2),
		prefixOf(n, "psconsolefile", 3),
		n == "ea" || prefixOf(n, "encodedarguments", 8):
		return psValue
	}
	return psSwitch
}

func prefixOf(n, full string, minLen int) bool {
	return len(n) >= minLen && strings.HasPrefix(full, n)
}

// cmdPayload returns what cmd /c, /k, or /r runs. Other switches (/d,
// /s, /q, /v:on) may come first.
func cmdPayload(args []string) (string, bool) {
	for i, a := range args {
		switch l := strings.ToLower(a); {
		case l == "/c" || l == "/k" || l == "/r":
			return strings.Join(args[i+1:], " "), true
		case strings.HasPrefix(l, "/"):
		default:
			return "", false
		}
	}
	return "", false
}

func pipeTarget(words []string) bool {
	w := unwrap(words)
	return len(w) > 0 && pipeShells[progName(w[0])]
}

// localPipe reports the exemption ./x.sh | sh: a pipeline of exactly a
// relative script and a bare shell with no arguments.
func localPipe(cmds []command, i int) bool {
	start := i - 1
	if start < 0 || cmds[start].pipeIn || (i+1 < len(cmds) && cmds[i+1].pipeIn) {
		return false
	}
	left := unwrap(cmds[start].words)
	if len(left) == 0 || !hasAnyPrefix(left[0], "./", "../", `.\`, `..\`) {
		return false
	}
	right := unwrap(cmds[i].words)
	return len(right) == 1 && bareShells[progName(right[0])]
}

// fetches reports a downloader or remote runner with a remote target.
func fetches(name string, args []string, followed bool) bool {
	switch name {
	case "curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer":
		return anyTarget(args, false) == remote
	case "nc", "ncat":
		return anyTarget(args, true) == remote
	case "pnpm", "yarn":
		return len(args) > 0 && args[0] == "dlx" && hasOperand(args[1:])
	case "uvx":
		return remoteTool(args, "--from")
	case "pipx":
		return len(args) > 0 && args[0] == "run" && remoteTool(args[1:], "--spec")
	case "deno":
		return len(args) > 0 && args[0] == "run" && slices.ContainsFunc(args[1:], denoRemote)
	case "npx", "bunx":
		return npxRemote(args)
	case "git":
		return followed && len(args) > 0 && args[0] == "clone" && anyTarget(args[1:], false) != loopback
	case "node":
		code, ok := nodeCode(args)
		return ok && codeFetches(code, "fetch", "http")
	}
	if isPython(name) {
		code, ok := pythonCode(args)
		return ok && codeFetches(code, "urllib", "requests", "http.client")
	}
	return false
}

// Target classes, in increasing precedence.
const (
	noTarget = iota
	loopback
	remote
)

// anyTarget classifies the network targets in args: remote when any is
// remote, loopback when every one is loopback, noTarget when there is
// none. bareHosts accepts host names without a path or port (nc host).
func anyTarget(args []string, bareHosts bool) int {
	best := noTarget
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			_, v, ok := strings.Cut(a, "=")
			if !ok {
				continue
			}
			a = v
		}
		best = max(best, classify(a, bareHosts))
	}
	return best
}

// classify reads one word as a URL, an IPv4 address, or a host name.
// localhost@host, localhost.host, and 127.0.0.1.host are remote: the
// host is what connects. An unparsable URL is remote.
func classify(w string, bareHosts bool) int {
	if i := strings.Index(w, "://"); i > 0 && isScheme(strings.ToLower(w[:i])) {
		u, err := url.Parse(w)
		if err != nil {
			return remote
		}
		switch h := u.Hostname(); {
		case h == "":
			return noTarget
		case isLoopback(h):
			return loopback
		default:
			return remote
		}
	}
	host, _, hasPath := strings.Cut(w, "/")
	hasPort := false
	if i := strings.LastIndexByte(host, ':'); i >= 0 && allDigits(host[i+1:]) {
		host, hasPort = host[:i], true
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && strings.Count(host, ".") == 3 {
		if ip.IsLoopback() {
			return loopback
		}
		return remote
	}
	if !bareHosts && !hasPath && !hasPort {
		return noTarget
	}
	switch {
	case strings.EqualFold(host, "localhost"):
		return loopback
	case isDomain(host):
		return remote
	}
	return noTarget
}

func isScheme(s string) bool {
	return s == "http" || s == "https" || s == "ftp" || s == "ftps"
}

func isLoopback(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// isDomain reports a dotted host name whose last label is letters.
func isDomain(h string) bool {
	labels := strings.Split(strings.ToLower(h), ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z') && !isDigit(c) && c != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if !(tld[i] >= 'a' && tld[i] <= 'z') {
			return false
		}
	}
	return true
}

func hasOperand(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool { return !strings.HasPrefix(a, "-") })
}

// remoteTool reports uvx or pipx run with a package to fetch. A --from
// or --spec that is a local path (., ./, ../, /, ~/, or a relative
// directory) runs local code.
func remoteTool(args []string, fromFlag string) bool {
	operand := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == fromFlag:
			if i+1 < len(args) {
				i++
				if localPath(args[i]) {
					return false
				}
			}
		case strings.HasPrefix(a, fromFlag+"="):
			if localPath(strings.TrimPrefix(a, fromFlag+"=")) {
				return false
			}
		case !strings.HasPrefix(a, "-"):
			operand = true
		}
	}
	return operand
}

func localPath(v string) bool {
	switch {
	case v == "." || v == "..":
		return true
	case hasAnyPrefix(v, "./", "../", "/", "~/", `.\`, `..\`):
		return true
	case strings.Contains(v, "://") || strings.HasPrefix(v, "git+"):
		return false
	}
	return strings.ContainsAny(v, `/\`)
}

func denoRemote(a string) bool {
	return classify(a, false) == remote || hasAnyPrefix(a, "npm:", "jsr:")
}

// npxRemote reports npx or bunx of a remote spec, or with -y. A bare
// name is a local or devDependency binary; --no-install never fetches.
func npxRemote(args []string) bool {
	if slices.ContainsFunc(args, func(a string) bool { return a == "--no-install" }) {
		return false
	}
	for _, a := range args {
		switch strings.ToLower(a) {
		case "-y", "--yes", "--yes=true":
			return true
		}
		if strings.HasPrefix(a, "-") {
			_, v, ok := strings.Cut(a, "=")
			if !ok {
				continue
			}
			a = v
		}
		if remoteSpec(a) {
			return true
		}
	}
	return false
}

func remoteSpec(a string) bool {
	if strings.Contains(a, "://") {
		return classify(a, false) != loopback
	}
	for _, p := range []string{"git+", "github:", "gist:", "gitlab:", "bitbucket:", "npm:", "jsr:"} {
		if strings.Contains(a, p) {
			return true
		}
	}
	if strings.HasPrefix(a, "@") {
		return true
	}
	name, version, ok := strings.Cut(a, "@")
	if !ok || name == "" || version == "" {
		return false
	}
	return version == "latest" || version == "next" || isDigit(version[0])
}

func isPython(name string) bool {
	rest, ok := strings.CutPrefix(name, "python")
	if !ok {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if !isDigit(rest[i]) && rest[i] != '.' {
			return false
		}
	}
	return true
}

// pythonCode returns the -c code when -c comes before any script or -m.
// -W and -X take a value.
func pythonCode(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' || strings.HasPrefix(a, "--") {
			return "", false
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'c':
				if j+1 < len(a) {
					return a[j+1:], true
				}
				if i+1 < len(args) {
					return args[i+1], true
				}
				return "", false
			case 'm':
				return "", false
			case 'W', 'X':
				if j+1 == len(a) {
					i++
				}
				j = len(a)
			}
		}
	}
	return "", false
}

// nodeCode returns the -e or --eval code when it comes before a script.
// -r and --require take a value.
func nodeCode(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-e" || a == "--eval":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case strings.HasPrefix(a, "--eval="):
			return strings.TrimPrefix(a, "--eval="), true
		case a == "-r" || a == "--require":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return "", false
		}
	}
	return "", false
}

// codeFetches reports inline code that names a network API and does not
// aim only at loopback.
func codeFetches(code string, apis ...string) bool {
	if !slices.ContainsFunc(apis, func(api string) bool { return strings.Contains(code, api) }) {
		return false
	}
	return urlTargets(code) != loopback
}

// urlTargets classifies the URLs in free text, as anyTarget does.
func urlTargets(text string) int {
	best := noTarget
	for rest := text; ; {
		i := strings.Index(rest, "://")
		if i < 0 {
			return best
		}
		start := i
		for start > 0 && isSchemeChar(rest[start-1]) {
			start--
		}
		end := i + 3
		for end < len(rest) && !strings.ContainsRune(" \t\r\n'\"`()<>|;", rune(rest[end])) {
			end++
		}
		best = max(best, classify(rest[start:end], false))
		rest = rest[end:]
	}
}

func isSchemeChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// dotNetDownload reports a .NET download call, as in
// IEX (New-Object Net.WebClient).DownloadString('https://...').
func dotNetDownload(src string) bool {
	return hasDownloadCall(src) && urlTargets(src) == remote
}

// hasDownloadCall reports whether src names DownloadString,
// DownloadFile, or DownloadData in any letter case, without copying it.
func hasDownloadCall(src string) bool {
	const verb = "download"
	for i := 0; i+len(verb) <= len(src); i++ {
		if src[i]|0x20 != 'd' || !strings.EqualFold(src[i:i+len(verb)], verb) {
			continue
		}
		rest := src[i+len(verb):]
		for _, kind := range []string{"string", "file", "data"} {
			if len(rest) >= len(kind) && strings.EqualFold(rest[:len(kind)], kind) {
				return true
			}
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
