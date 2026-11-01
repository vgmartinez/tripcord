package shellcmd

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// checksumScript reports a script that the checksum grammar accepts:
// every fetch downloads to a literal file that a check then verifies,
// and every file the script runs is verified before it runs. The
// grammar is an allowlist. Each command is one of:
//
//  1. curl or wget of one http(s) URL to a literal -o / -O file;
//  2. sha256sum -c <file>, or shasum -a 256 -c <file>;
//  3. echo or printf '<64 hex>  <file>' piped into sha256sum -c [-]
//     (or shasum -a 256 -c [-]), with exactly one entry naming a file
//     that is not - or /dev/*;
//  4. sh or bash <file>, where the script fetched <file>;
//  5. set -e, -eu, -euo pipefail, -eo pipefail, or -o errexit, only
//     before every other command and as statements of their own;
//  6. cd (only before the first fetch, check, or run), mkdir, chmod,
//     or rm;
//  7. export NAME=literal or NAME=literal, except names that change
//     how a command is found or run (PATH, BASH_ENV, LD_*, ...).
//
// Statements are joined by ;, a newline, or &&, and the only pipe is
// the one of form 3. Anything else on the line (another command, a
// function, trap, eval, source, alias, shopt, exec, a subshell, a
// control structure, ||, &, a redirection, $, a backquote, a backslash
// outside single quotes, a glob, or a quoted command name) gives no
// credit. The check covering a run comes after the last fetch before
// that run, and stops it on failure: it is in the same && list, or set
// -e is on and the check is a statement of its own. Each fetch is
// covered by a later check that fails the script: a statement of its
// own under set -e, or in the script's last statement. A form 3 check
// covers only the file it names, and a sums file may not be a fetch
// target. Unusual scripts are not credited; that is the intended
// trade-off.
func checksumScript(src string) bool {
	lists, ok := parseScript(src)
	if !ok {
		return false
	}
	var els []element
	for li, l := range lists {
		for _, p := range l {
			e, ok := classifyPipeline(p)
			if !ok {
				return false
			}
			e.list, e.standalone = li, len(l) == 1
			els = append(els, e)
		}
	}
	return checkElements(els, len(lists)-1)
}

type elementKind int

const (
	kindSet elementKind = iota
	kindFetch
	kindCheck
	kindRun
	kindCd
	kindOther
)

// element is one pipeline of the script. file is the fetch target, the
// file run, or the file a form 3 check names; a form 2 check has file
// "" and its sums file in sums.
type element struct {
	kind       elementKind
	file, sums string
	list       int
	standalone bool
}

func checkElements(els []element, last int) bool {
	errexit, leading, started := false, true, false
	fetched := map[string]bool{}
	for _, e := range els {
		if e.kind != kindSet {
			leading = false
		}
		switch e.kind {
		case kindSet:
			if !leading || !e.standalone {
				return false
			}
			errexit = true
		case kindCd:
			if started {
				return false
			}
		case kindFetch:
			fetched[e.file] = true
			started = true
		case kindCheck, kindRun:
			started = true
		case kindOther:
		}
	}
	for _, e := range els {
		if e.kind == kindCheck && e.sums != "" && fetched[e.sums] {
			return false
		}
	}
	covers := func(c element, file string) bool {
		return c.kind == kindCheck && (c.file == "" || c.file == file)
	}
	anyFetch := false
	for i, e := range els {
		switch e.kind {
		case kindFetch:
			anyFetch = true
			covered := false
			for _, c := range els[i+1:] {
				if c.kind == kindFetch && c.file == e.file {
					break
				}
				if covers(c, e.file) && (errexit && c.standalone || c.list == last) {
					covered = true
					break
				}
			}
			if !covered {
				return false
			}
		case kindRun:
			if !slices.ContainsFunc(els[:i], func(f element) bool { return f.kind == kindFetch && f.file == e.file }) {
				return false
			}
			guarded := false
			for j := i - 1; j >= 0 && els[j].kind != kindFetch; j-- {
				if c := els[j]; covers(c, e.file) && (c.list == e.list || errexit && c.standalone) {
					guarded = true
					break
				}
			}
			if !guarded {
				return false
			}
		case kindSet, kindCheck, kindCd, kindOther:
		}
	}
	return anyFetch
}

func classifyPipeline(p gpipe) (element, bool) {
	switch len(p) {
	case 1:
		return classifyCommand(p[0])
	case 2:
		file, ok := checksumEntry(p[0])
		if !ok || !checksumStdin(p[1]) {
			return element{}, false
		}
		return element{kind: kindCheck, file: file}, true
	default:
		return element{}, false
	}
}

func classifyCommand(c gcmd) (element, bool) {
	if assignment(c[0]) {
		for _, w := range c {
			if !assignment(w) {
				return element{}, false
			}
		}
		return element{kind: kindOther}, true
	}
	if c[0].quote >= 0 {
		return element{}, false
	}
	args := c[1:]
	switch c[0].text {
	case "curl", "wget":
		target, ok := fetchTarget(c[0].text, args)
		return element{kind: kindFetch, file: target}, ok
	case "sha256sum", "shasum":
		sums, ok := checksumFile(c)
		return element{kind: kindCheck, sums: sums}, ok
	case "sh", "bash":
		if len(args) == 0 || strings.HasPrefix(args[0].text, "-") || !literalFile(args[0].text) {
			return element{}, false
		}
		return element{kind: kindRun, file: path.Clean(args[0].text)}, true
	case "set":
		return element{kind: kindSet}, errexitOptions[joinWords(args)] && unquoted(args)
	case "export":
		if len(args) == 0 {
			return element{}, false
		}
		for _, w := range args {
			if !assignment(w) && !exportName(w) {
				return element{}, false
			}
		}
		return element{kind: kindOther}, true
	case "cd":
		return element{kind: kindCd}, len(args) <= 1
	case "mkdir", "chmod", "rm":
		return element{kind: kindOther}, true
	default:
		return element{}, false
	}
}

var errexitOptions = map[string]bool{
	"-e": true, "-eu": true, "-ue": true, "-euo pipefail": true,
	"-eo pipefail": true, "-o errexit": true,
}

// grammarCommands are the names the grammar runs. A fetch target with
// one of these names could replace that command on PATH.
var grammarCommands = map[string]bool{
	"curl": true, "wget": true, "sha256sum": true, "shasum": true,
	"echo": true, "printf": true, "sh": true, "bash": true, "set": true,
	"export": true, "cd": true, "mkdir": true, "chmod": true, "rm": true,
}

var targetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// fetchTarget returns the literal output file of a curl or wget of one
// http(s) URL. Only the listed options are accepted: anything that
// reads a config file (curl -K), names the file remotely (curl -O),
// writes elsewhere, or starts another transfer gives no credit. The
// target's base name may not start with a dot (.curlrc, .wgetrc) or be
// a command the grammar runs.
func fetchTarget(name string, args []gword) (string, bool) {
	var target string
	targets, urls := 0, 0
	setTarget := func(v string) {
		target = v
		targets++
	}
	for i := 0; i < len(args); i++ {
		a := args[i].text
		value := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i].text, true
		}
		switch {
		case strings.HasPrefix(a, "--"):
			flag, v, inline := strings.Cut(a, "=")
			kind := curlLong[flag]
			if name == "wget" {
				kind = wgetLong[flag]
			}
			switch kind {
			case longFlag:
				if inline {
					return "", false
				}
			case longValue, longOutput:
				if !inline {
					var ok bool
					if v, ok = value(); !ok {
						return "", false
					}
				}
				if kind == longOutput {
					setTarget(v)
				}
			default:
				return "", false
			}
		case a == "-nv" && name == "wget":
		case len(a) > 1 && a[0] == '-':
			out, short := byte('o'), "fsSLk"
			if name == "wget" {
				out, short = 'O', "q"
			}
			for j := 1; j < len(a); j++ {
				if a[j] == out {
					v := a[j+1:]
					if v == "" {
						var ok bool
						if v, ok = value(); !ok {
							return "", false
						}
					}
					setTarget(v)
					break
				}
				if strings.IndexByte(short, a[j]) < 0 {
					return "", false
				}
			}
		default:
			lower := strings.ToLower(a)
			if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
				return "", false
			}
			urls++
		}
	}
	if targets != 1 || urls != 1 || !literalFile(target) {
		return "", false
	}
	target = path.Clean(target)
	base := path.Base(target)
	if !targetName.MatchString(base) || grammarCommands[base] {
		return "", false
	}
	return target, true
}

const (
	longNone = iota
	longFlag
	longValue
	longOutput
)

var curlLong = map[string]int{
	"--fail": longFlag, "--silent": longFlag, "--show-error": longFlag,
	"--location": longFlag, "--create-dirs": longFlag, "--compressed": longFlag,
	"--fail-with-body": longFlag, "--no-progress-meter": longFlag,
	"--tlsv1.2": longFlag, "--tlsv1.3": longFlag, "--http1.1": longFlag,
	"--retry": longValue, "--retry-delay": longValue, "--retry-max-time": longValue,
	"--connect-timeout": longValue, "--max-time": longValue, "--proto": longValue,
	"--proto-redir": longValue, "--output": longOutput,
}

var wgetLong = map[string]int{
	"--quiet": longFlag, "--no-verbose": longFlag, "--https-only": longFlag,
	"--tries": longValue, "--timeout": longValue, "--output-document": longOutput,
}

// checksumFile returns the sums file of sha256sum -c <file> or shasum
// -a 256 -c <file>.
func checksumFile(c gcmd) (string, bool) {
	rest, ok := checksumPrefix(c)
	if !ok || len(rest) != 1 || !literalFile(rest[0].text) {
		return "", false
	}
	return path.Clean(rest[0].text), true
}

// checksumStdin reports sha256sum -c or shasum -a 256 -c reading the
// sums from stdin: no file, or -.
func checksumStdin(c gcmd) bool {
	rest, ok := checksumPrefix(c)
	return ok && (len(rest) == 0 || len(rest) == 1 && rest[0].text == "-")
}

// checksumPrefix strips the command name, shasum's -a 256, and -c or
// --check, and returns what follows.
func checksumPrefix(c gcmd) ([]gword, bool) {
	if c[0].quote >= 0 {
		return nil, false
	}
	args := c[1:]
	switch c[0].text {
	case "sha256sum":
	case "shasum":
		switch {
		case len(args) >= 2 && args[0].text == "-a" && args[1].text == "256":
			args = args[2:]
		case len(args) >= 1 && args[0].text == "-a256":
			args = args[1:]
		default:
			return nil, false
		}
	default:
		return nil, false
	}
	if len(args) == 0 || args[0].text != "-c" && args[0].text != "--check" {
		return nil, false
	}
	return args[1:], true
}

var checksumLine = regexp.MustCompile(`^[0-9a-fA-F]{64} [ *]([^\s]+)$`)

// checksumEntry returns the file named by echo '<64 hex>  <file>' or
// printf '<64 hex>  <file>\n': exactly one entry, no echo option, and
// no printf conversion or escape other than a final \n.
func checksumEntry(c gcmd) (string, bool) {
	if c[0].quote >= 0 || len(c) < 2 {
		return "", false
	}
	var text string
	switch c[0].text {
	case "echo":
		if strings.HasPrefix(c[1].text, "-") {
			return "", false
		}
		text = joinWords(c[1:])
	case "printf":
		if len(c) != 2 {
			return "", false
		}
		text = strings.TrimSuffix(c[1].text, `\n`)
		if strings.Contains(text, "%") {
			return "", false
		}
	default:
		return "", false
	}
	if strings.ContainsAny(text, "\\\n") {
		return "", false
	}
	m := checksumLine.FindStringSubmatch(text)
	if m == nil || !literalFile(m[1]) {
		return "", false
	}
	return path.Clean(m[1]), true
}

// literalFile reports a file name that is not empty, an option, stdin,
// or a device.
func literalFile(f string) bool {
	return f != "" && f != "-" && !strings.HasPrefix(f, "-") && !strings.HasPrefix(path.Clean(f), "/dev/")
}

func assignment(w gword) bool {
	name, _, ok := strings.Cut(w.text, "=")
	return ok && (w.quote < 0 || w.quote > len(name)) && isIdent(name) && safeEnvName(name)
}

func exportName(w gword) bool {
	return w.quote < 0 && isIdent(w.text) && safeEnvName(w.text)
}

func isIdent(s string) bool {
	if s == "" || isDigit(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && !isDigit(c) && (c|0x20 < 'a' || c|0x20 > 'z') {
			return false
		}
	}
	return true
}

// safeEnvName rejects variables that change which program runs, what a
// shell or interpreter loads first, or which config curl and wget read.
func safeEnvName(name string) bool {
	u := strings.ToUpper(name)
	switch u {
	case "PATH", "ENV", "IFS", "HOME", "CDPATH", "SHELLOPTS", "PS4",
		"CURL_HOME", "WGETRC", "SYSTEM_WGETRC", "XDG_CONFIG_HOME", "GLIBC_TUNABLES":
		return false
	}
	for _, p := range []string{"BASH", "LD_", "DYLD_", "PERL", "PYTHON", "NODE_", "RUBY", "GCONV"} {
		if strings.HasPrefix(u, p) {
			return false
		}
	}
	return true
}

func unquoted(ws []gword) bool {
	for _, w := range ws {
		if w.quote >= 0 {
			return false
		}
	}
	return true
}

func joinWords(ws []gword) string {
	parts := make([]string, len(ws))
	for i, w := range ws {
		parts[i] = w.text
	}
	return strings.Join(parts, " ")
}

// gword is a word of the grammar. quote is the offset in text where
// quoting first starts, or -1 for a word written without quotes.
type gword struct {
	text  string
	quote int
}

type (
	gcmd  []gword
	gpipe []gcmd
	gand  []gpipe
)

// parseScript splits a script into && lists of pipelines of commands.
// It accepts only words, ;, newlines, &&, |, and # comments. Unquoted
// words may use letters, digits, and _-./:=+,@%^; double quotes may not
// hold $, a backquote, \, or !. Anything else fails.
func parseScript(src string) ([]gand, bool) {
	var (
		lists   []gand
		list    gand
		pipe    gpipe
		cmd     gcmd
		word    strings.Builder
		inWord  bool
		quote   = -1
		pending bool
		empty   = true
	)
	endWord := func() {
		if inWord {
			cmd = append(cmd, gword{text: word.String(), quote: quote})
			word.Reset()
			inWord, quote = false, -1
		}
	}
	endCmd := func() bool {
		endWord()
		if len(cmd) == 0 {
			return false
		}
		pipe = append(pipe, cmd)
		cmd = nil
		return true
	}
	startWord := func() {
		if !inWord {
			inWord, pending, empty = true, false, false
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == ' ' || c == '\t':
			endWord()
		case c == '\n' || c == ';':
			endWord()
			if pending {
				if c == ';' {
					return nil, false
				}
				continue
			}
			if len(cmd) == 0 {
				if c == ';' && empty {
					return nil, false
				}
				empty = true
				continue
			}
			endCmd()
			list = append(list, pipe)
			lists = append(lists, list)
			pipe, list, empty = nil, nil, true
		case c == '&':
			if i+1 >= len(src) || src[i+1] != '&' || !endCmd() {
				return nil, false
			}
			list = append(list, pipe)
			pipe, pending = nil, true
			i++
		case c == '|':
			if i+1 < len(src) && src[i+1] == '|' || !endCmd() {
				return nil, false
			}
			pending = true
		case c == '#' && !inWord:
			for i+1 < len(src) && src[i+1] != '\n' {
				i++
			}
		case c == '\'' || c == '"':
			end := strings.IndexByte(src[i+1:], c)
			if end < 0 {
				return nil, false
			}
			body := src[i+1 : i+1+end]
			if c == '"' && strings.ContainsAny(body, "$`\\!") {
				return nil, false
			}
			startWord()
			if quote < 0 {
				quote = word.Len()
			}
			word.WriteString(body)
			i += end + 1
		case isWordByte(c):
			startWord()
			word.WriteByte(c)
		default:
			return nil, false
		}
	}
	if pending {
		return nil, false
	}
	if endCmd() {
		list = append(list, pipe)
		lists = append(lists, list)
	} else if len(pipe) > 0 || len(list) > 0 {
		return nil, false
	}
	return lists, true
}

func isWordByte(c byte) bool {
	return c|0x20 >= 'a' && c|0x20 <= 'z' || isDigit(c) || strings.IndexByte("_-./:=+,@%^", c) >= 0
}
