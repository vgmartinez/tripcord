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
// A payload nested deeper than maxDepth is reported as Nested.
//
// Invoke-Expression is a Pipe when its statement downloads: a downloader
// (curl, wget, iwr, irm, and their long names, or a .NET Download* call)
// whose target is not provably loopback. A variable or $env target is
// not, so iwr $u | iex is a Pipe, while oh-my-posh init pwsh | iex runs
// local output and is not. Decoded content feeding Invoke-Expression is
// Encoded: base64 -d or --decode, FromBase64, or
// [Text.Encoding]::GetString, piped in or passed as the argument.
// PowerShell's $x = <command> is unwrapped, and a variable assigned a
// download or decoded content carries it to a later $x | iex or iex $x
// on the same line.
//
// PowerShell text (a powershell or pwsh payload, an iex argument) is
// read with backtick as the escape character, so I`E`X is IEX. A line
// that contains a backtick is read both ways, since a hook command does
// not say which shell runs it.
//
// Static limits: variables are not expanded, except a default value in
// command position (${NAME:-word}, ${NAME-word}, ${NAME:=word}, or
// ${NAME=word}, where NAME matches [A-Za-z_][A-Za-z0-9_]* and word is a
// literal with no $, backtick, or nested braces), resolved after the
// prefixes unwrap already strips (assignments, sudo, doas, env, exec,
// and command). An empty default (${NAME:-}, ${NAME-}, ${NAME:=}, or
// ${NAME=}) is dropped and the next word is the command. $URL is not a
// fetch target outside Invoke-Expression and $(echo cur)l is not curl.
// nohup, xargs, env -S, busybox, and start /b are not unwrapped. A
// script a hook calls is not read.
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
	// Nested is a payload nested deeper than the reader follows. It is
	// reported rather than skipped, so nesting cannot hide a fetch.
	Nested = "nested"
)

// maxDepth bounds how far nested payloads are read.
const maxDepth = 8

// Risks reports the risks in a command line, in the order Fetch, Pipe,
// Encoded, Nested, each at most once.
func Risks(line string) []string { return Analyze(line).Risks }

// Result is what Analyze found and how much it read.
type Result struct {
	Risks []string
	// Work is the number of bytes read, counting a nested payload once
	// for each level it is read at. The reader is linear in Work, so it
	// is the cost to charge for a call.
	Work int
}

// Analyze is Risks with the work it took.
func Analyze(line string) Result {
	var s scanner
	s.line(line, 0, false)
	if strings.Contains(line, "`") {
		s.line(line, 0, true)
	}
	return Result{Risks: s.risks(), Work: s.work}
}

// RisksArgv reports the risks in an argument vector that no shell
// splits, such as a hook's exec and args. A pipe character in an
// argument is literal; a wrapper's payload is still read as a command
// line.
func RisksArgv(argv []string) []string { return AnalyzeArgv(argv).Risks }

// AnalyzeArgv is RisksArgv with the work it took.
func AnalyzeArgv(argv []string) Result {
	var s scanner
	for _, a := range argv {
		s.work += len(a) + 1
	}
	s.command(argv, 0, false)
	return Result{Risks: s.risks(), Work: s.work}
}

type scanner struct {
	fetch, pipe, encoded, nested bool
	work                         int
	// unpinned records a fetch whose target is not an immutable URL.
	unpinned bool
	// tainted maps a lower-case PowerShell variable name to what was
	// assigned to it: taintFetch, taintDecoded, or both.
	tainted map[string]int
	// locate records, in found, where each command's program and
	// script live (see Locate).
	locate bool
	found  map[string]bool
	// collect gathers, in scripts, the project files the line runs (see
	// ProjectScripts); moved stops it after the line changes directory.
	collect bool
	moved   bool
	scripts []string
}

// What a PowerShell variable holds.
const (
	taintFetch = 1 << iota
	taintDecoded
)

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
	if s.nested {
		out = append(out, Nested)
	}
	return out
}

// line reads a command line. ps marks PowerShell text. It reports
// whether the line decodes a payload (see commandDecodes) in a command or
// in a substitution, so a caller learns that without reading it again.
func (s *scanner) line(src string, depth int, ps bool) (decodes bool) {
	s.work += len(src) + 1
	if strings.TrimSpace(src) == "" {
		return false
	}
	if depth > maxDepth {
		s.nested = true
		return false
	}
	toks, subs := lex(src, ps)
	subDecodes := make([]bool, len(subs))
	for i, sub := range subs {
		subDecodes[i] = s.line(sub, depth+1, ps)
		decodes = decodes || subDecodes[i]
	}
	if decodedExpression(toks, subDecodes) {
		s.encoded = true
	}
	if dotNetDownload(src) {
		s.fetch = true
		if !urlsImmutable(src) {
			s.unpinned = true
		}
	} else if hasDownloadCall(src) && strings.Contains(src, "$") {
		s.unpinned = true
	}
	cmds := split(toks)
	fetched := make([]bool, len(cmds))
	for i, c := range cmds {
		before := s.fetch
		s.fetch = false
		s.command(c.words, depth, i < len(cmds)-1)
		fetched[i] = s.fetch
		s.fetch = s.fetch || before
		if c.pipeIn && pipeTarget(c.words) && !commandIsIEX(c.words) && !localPipe(cmds, i) {
			s.pipe = true
		}
		decodes = decodes || commandDecodes(c.words)
	}
	for start := 0; start < len(cmds); {
		end := start + 1
		for end < len(cmds) && cmds[end].stmt == cmds[start].stmt {
			end++
		}
		s.statement(cmds[start:end], fetched[start:end])
		start = end
	}
	return decodes
}

// commandDefault accepts ${NAME:-word}, ${NAME-word}, ${NAME:=word}, and
// ${NAME=word}. NAME is [A-Za-z_][A-Za-z0-9_]*. word is a literal with
// no $, backtick, or brace, and the replacement is one word. An empty
// word is a drop. :+, +, and anything else are left as written.
func commandDefault(word string) (lit string, drop bool) {
	if len(word) < 3 || word[0] != '$' || word[1] != '{' || word[len(word)-1] != '}' {
		return "", false
	}
	inner := word[2 : len(word)-1]
	i := 0
	if i >= len(inner) || !isNameStart(inner[i]) {
		return "", false
	}
	i++
	for i < len(inner) && isNameCont(inner[i]) {
		i++
	}
	if i >= len(inner) {
		return "", false
	}
	op := 0
	switch {
	case strings.HasPrefix(inner[i:], ":-"), strings.HasPrefix(inner[i:], ":="):
		op = 2
	case inner[i] == '-', inner[i] == '=':
		op = 1
	default:
		return "", false
	}
	lit = inner[i+op:]
	if strings.ContainsAny(lit, "$`{}") {
		return "", false
	}
	if lit == "" {
		return "", true
	}
	return lit, false
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isNameCont(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

// statement reads one statement for Invoke-Expression: it is a Pipe when
// the statement downloads or uses a variable that holds a download, and
// Encoded when it uses a variable that holds decoded content. A
// $x = <command> statement records what x now holds.
func (s *scanner) statement(cmds []command, fetched []bool) {
	name, rhs, assigns := psAssign(cmds[0].words)
	words := func(i int) []string {
		if i == 0 && assigns {
			return rhs
		}
		return cmds[i].words
	}
	taint, iex, decodes := 0, false, false
	for i := range cmds {
		w := words(i)
		taint |= s.taintOf(w)
		iex = iex || commandIsIEX(w)
		decodes = decodes || commandDecodes(w)
	}
	if !iex && !assigns {
		return
	}
	if downloads(cmds, fetched) {
		taint |= taintFetch
	}
	if iex {
		s.pipe = s.pipe || taint&taintFetch != 0
		s.encoded = s.encoded || taint&taintDecoded != 0
	}
	if !assigns {
		return
	}
	if decodes {
		taint |= taintDecoded
	}
	if taint != 0 {
		if s.tainted == nil {
			s.tainted = map[string]int{}
		}
		s.tainted[name] |= taint
	}
}

// taintOf reports what the variables words use hold.
func (s *scanner) taintOf(words []string) int {
	if len(s.tainted) == 0 {
		return 0
	}
	taint := 0
	for _, w := range words {
		for rest := w; ; {
			i := strings.IndexByte(rest, '$')
			if i < 0 {
				break
			}
			rest = rest[i+1:]
			n := 0
			for n < len(rest) && psNameChar(rest[n]) {
				n++
			}
			taint |= s.tainted[strings.ToLower(rest[:n])]
			rest = rest[n:]
		}
	}
	return taint
}

func psNameChar(c byte) bool {
	return c == '_' || c == ':' || isDigit(c) || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// psAssign splits a PowerShell assignment, $x = <command>, $x=<command>,
// or $env:X = <command>, into the lower-case variable name and the
// command.
func psAssign(w []string) (name string, rhs []string, ok bool) {
	if len(w) == 0 || len(w[0]) < 2 || w[0][0] != '$' {
		return "", nil, false
	}
	head, rest := w[0][1:], w[1:]
	name, value, found := strings.Cut(head, "=")
	if !found {
		if len(rest) == 0 || !strings.HasPrefix(rest[0], "=") || strings.HasPrefix(rest[0], "==") {
			return "", nil, false
		}
		value, rest = rest[0][1:], rest[1:]
	} else if strings.HasPrefix(value, "=") {
		return "", nil, false
	}
	if name == "" {
		return "", nil, false
	}
	for i := 0; i < len(name); i++ {
		if !psNameChar(name[i]) {
			return "", nil, false
		}
	}
	if value != "" {
		rest = append([]string{value}, rest...)
	}
	return strings.ToLower(name), rest, true
}

// downloads reports a statement that downloads: a command in it fetches,
// a downloader in it has a target that is not provably loopback, or it
// makes a .NET Download* call to anything but loopback.
func downloads(cmds []command, fetched []bool) bool {
	dotNet, target := false, noTarget
	for i, c := range cmds {
		if fetched[i] || downloader(c.words) {
			return true
		}
		for _, w := range c.words {
			dotNet = dotNet || hasDownloadCall(w)
			if strings.HasPrefix(w, "$") {
				target = remote
			} else {
				target = max(target, urlTargets(w))
			}
		}
	}
	return dotNet && target != loopback
}

// downloader reports curl, wget, iwr, irm, Invoke-WebRequest,
// Invoke-RestMethod, or Start-BitsTransfer with a target that is not
// provably loopback: a variable, $env, or a missing target is not.
func downloader(words []string) bool {
	w := unwrap(words)
	if len(w) == 0 {
		return false
	}
	switch progName(w[0]) {
	case "curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer":
	default:
		return false
	}
	for _, a := range w[1:] {
		if strings.HasPrefix(a, "$") || strings.Contains(a, "=$") || strings.Contains(a, ":$") {
			return true
		}
	}
	return anyTarget(w[1:], false) != loopback
}

// command reads one simple command. followed is set when another
// command comes after it on the same line.
func (s *scanner) command(words []string, depth int, followed bool) {
	w := unwrap(words)
	if len(w) == 0 {
		return
	}
	name, args := progName(w[0]), w[1:]
	if s.collect {
		s.collectScripts(w[0], name, args)
	} else if s.locate {
		s.runs(w[0], name, args)
	}
	switch {
	case posixShells[name]:
		if p, ok := shellPayload(name, args); ok {
			s.line(p, depth+1, false)
		}
	case name == "powershell" || name == "pwsh":
		p, encoded := psPayload(args)
		if encoded {
			s.encoded = true
		}
		s.line(p, depth+1, true)
	case name == "cmd":
		if p, ok := cmdPayload(args); ok {
			s.line(p, depth+1, false)
		}
	case name == "eval":
		s.line(strings.Join(args, " "), depth+1, false)
	case name == "iex" || name == "invoke-expression":
		s.line(strings.Join(args, " "), depth+1, true)
	case isPython(name):
		s.python(args, depth)
	default:
		if fetches(name, args, followed) {
			s.fetch = true
			if !immutableTargets(name, args) {
				s.unpinned = true
			}
		} else if downloaderNames[name] && variableTarget(args) {
			s.unpinned = true
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
// the rest of the command unchanged, and reads a PowerShell assignment
// as its command. Before it reads a word, a default value
// (${NAME:-word}, ${NAME-word}, ${NAME:=word}, ${NAME=word}) replaces
// that word, so sudo ${X:-curl} and FOO=1 ${X:-curl} are curl. An empty
// default is dropped and the next word is read, so ${X:-} curl and
// sudo ${X:-} curl are curl. It returns nil for command -v, which only
// looks a name up.
func unwrap(w []string) []string {
	for len(w) > 0 {
		lit, drop := commandDefault(w[0])
		if drop {
			w = w[1:]
			continue
		}
		if lit != "" {
			next := make([]string, len(w))
			next[0] = lit
			copy(next[1:], w[1:])
			w = next
		}
		if isAssignment(w[0]) || reserved[w[0]] {
			w = w[1:]
			continue
		}
		if _, rhs, ok := psAssign(w); ok {
			w = rhs
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
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || !isDigit(c)) {
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
	payload, _, ok := shellPayloadAt(name, args)
	return payload, ok
}

// shellPayloadAt returns the -c payload and how many operands follow it.
// Those operands are the shell's $0, $1, ..., not part of the command.
func shellPayloadAt(name string, args []string) (payload string, rest int, ok bool) {
	want := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if want && i+1 < len(args) {
				return args[i+1], len(args) - (i + 2), true
			}
			return "", 0, false
		case strings.HasPrefix(a, "--"):
			flag, value, inline := strings.Cut(a, "=")
			switch flag {
			case "--command":
				if inline {
					return value, len(args) - (i + 1), true
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
				return a, len(args) - (i + 1), true
			}
			return "", 0, false
		}
	}
	return "", 0, false
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

// decodedExpression reports a statement that feeds decoded content to
// Invoke-Expression. A statement runs to a separator (;, &&, ||, &);
// quotes are already resolved, so a mention inside echo '…' does not
// count. The decoder is base64 -d/--decode, a FromBase64 call, or
// [Text.Encoding]::GetString, in command position or in a substitution
// in that statement.
// subDecodes holds, for each substitution in order, whether it decodes.
func decodedExpression(toks []token, subDecodes []bool) bool {
	subAt := 0
	var stmt []token
	flush := func() bool {
		n := 0
		for _, t := range stmt {
			n += strings.Count(t.word, subst)
		}
		// A NUL byte in the command is the substitution marker, so the
		// count can run past the real substitutions. Never slice past them.
		if subAt > len(subDecodes) {
			subAt = len(subDecodes)
		}
		if subAt+n > len(subDecodes) {
			n = len(subDecodes) - subAt
		}
		ok := statementDecoded(stmt, subDecodes[subAt:subAt+n])
		subAt += n
		stmt = nil
		return ok
	}
	for _, t := range toks {
		if t.op == opSep || t.op == "&&" || t.op == "||" || t.op == "&" {
			if flush() {
				return true
			}
			continue
		}
		stmt = append(stmt, t)
	}
	return flush()
}

// statementDecoded reports that this statement both decodes and runs
// Invoke-Expression, in either order: `base64 -d | iex` and
// `iex ([Convert]::FromBase64String(...))`.
func statementDecoded(toks []token, subDecodes []bool) bool {
	decodes, iex := false, false
	for _, c := range split(toks) {
		decodes = decodes || commandDecodes(c.words)
		iex = iex || commandIsIEX(c.words)
	}
	if iex && decodes {
		return true
	}
	if !iex {
		return false
	}
	return slices.Contains(subDecodes, true)
}

func commandIsIEX(words []string) bool {
	w := unwrap(words)
	if len(w) == 0 {
		return false
	}
	name := progName(w[0])
	return name == "iex" || name == "invoke-expression"
}

// commandDecodes reports a command that decodes a payload: base64 -d or
// --decode, a FromBase64 call, or [Text.Encoding]::*.GetString.
func commandDecodes(words []string) bool {
	w := unwrap(words)
	if len(w) == 0 {
		return false
	}
	if progName(w[0]) == "base64" && base64Decodes(w[1:]) {
		return true
	}
	head := strings.ToLower(w[0])
	if strings.Contains(head, "frombase64") {
		return true
	}
	return strings.Contains(head, "text.encoding]::") && strings.Contains(head, "getstring")
}

// base64Decodes reports a decode flag: -d, -D, a short cluster containing
// one of them (-di), or --decode. -- ends the flags.
func base64Decodes(args []string) bool {
	for _, a := range args {
		switch {
		case a == "--":
			return false
		case a == "--decode" || strings.HasPrefix(a, "--decode="):
			return true
		case strings.HasPrefix(a, "--") || len(a) < 2 || a[0] != '-':
			continue
		}
		for i := 1; i < len(a); i++ {
			if a[i] == 'd' || a[i] == 'D' {
				return true
			}
		}
	}
	return false
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
	return false
}

// python reads a python -c payload. Inline code that calls urllib,
// requests, or http.client is a fetch, as before. A string passed to
// os.system, os.popen, or another shell runner, and an argv list passed
// to subprocess, is a command line of its own.
func (s *scanner) python(args []string, depth int) {
	code, ok := pythonCode(args)
	if !ok {
		return
	}
	if codeFetches(code, "urllib", "requests", "http.client") {
		s.fetch = true
		s.unpinned = true
	}
	lines, argvs := pythonShellPayloads(code)
	for _, line := range lines {
		s.line(line, depth+1, false)
	}
	for _, argv := range argvs {
		s.command(argv, depth+1, false)
	}
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
	if i := strings.IndexByte(host, '%'); i >= 0 && strings.Contains(host, ":") {
		host = host[:i]
	}
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
			if (c < 'a' || c > 'z') && !isDigit(c) && c != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
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
