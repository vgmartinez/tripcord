package shellcmd

import (
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

// FetchNotRun reports an environment setup command whose every fetch
// only writes data that nothing runs, so it does not run code fetched
// from an unpinned source (TC-CFG-009). others holds the rest of the
// same configuration file: the other setup commands and settings, which
// run in the same environment.
//
// It is an allowlist. The command has no risk but Fetch (no pipe into a
// shell, nothing encoded or nested too deep), and the whole script,
// after one sh, bash, or dash -c wrapper, parses as simple commands
// joined by ;, a newline, &&, ||, or & (see parseNotRun). Each command
// is one of:
//
//  1. curl or wget of one http(s) URL, with only the options fetchTarget
//     knows plus -O, written to standard output, to a literal file
//     (-o, -O, > or >>), or, for wget, to the URL's file name. The file
//     name is a relative path of plain segments with an archive or data
//     extension (see dataFile) and not a manifest a tool reads on its
//     own (package.json, composer.json, ...);
//  2. git clone of one http(s) or git URL, with only --depth, -b,
//     --branch, --single-branch, --no-tags, --filter, and -q, into a
//     literal directory or the one the URL names;
//  3. tar -x or unzip of a file into a literal directory (-C or -d); the
//     directory of a fetched archive counts as fetched too;
//  4. a reader that never runs its operands: cat, grep, jq, head, tail,
//     wc, ls, sha256sum, shasum, md5sum, cmp, diff, test, [, mkdir,
//     rm, echo, or printf, without a redirection;
//  5. any other command that names nothing fetched and has no risk of
//     its own even when another command follows it (so a git clone
//     counts), and no downloader, remote runner, or git clone in any
//     word (sudo git clone, git -C dir clone). cd, pushd, popd,
//     source, ., eval, exec, trap, alias, xargs, find, and shell
//     keywords give no credit.
//
// A fetched name is any fetched file, clone, or extraction directory,
// as written and as its last path segment, compared case-insensitively
// as a substring: a command other than 1 to 4 that contains it, and any
// text in others that contains it, means the fetch may be run. Text in
// others that has a glob character in a command also gives no credit.
// $, backquotes, globs, subshells, functions, here-documents, <, and
// any other construct give no credit, so the analysis never guesses.
//
// What a committed script, build file, or manifest does with a fetched
// name is not read.
func FetchNotRun(line string, others []string) bool {
	if !onlyFetch(Analyze(line).Risks) {
		return false
	}
	return notRunScript(line, others, 0)
}

// FetchNotRunArgv is FetchNotRun for an argument vector: sh, bash, or
// dash -c and a script, or one command that no shell splits.
func FetchNotRunArgv(argv []string, others []string) bool {
	if len(argv) == 0 || !onlyFetch(AnalyzeArgv(argv).Risks) {
		return false
	}
	if payload, ok := notRunShellPayload(argv); ok {
		return notRunScript(payload, others, 1)
	}
	return notRunCommands([]nrCommand{{words: argv}}, others)
}

func onlyFetch(risks []string) bool {
	return len(risks) == 1 && risks[0] == Fetch
}

// notRunMaxDepth bounds the sh -c wrappers FetchNotRun unwraps.
const notRunMaxDepth = 2

func notRunScript(src string, others []string, depth int) bool {
	cmds, ok := parseNotRun(src)
	if !ok || len(cmds) == 0 {
		return false
	}
	if len(cmds) == 1 && len(cmds[0].redirects) == 0 {
		if payload, ok := notRunShellPayload(cmds[0].words); ok {
			if depth >= notRunMaxDepth {
				return false
			}
			return notRunScript(payload, others, depth+1)
		}
	}
	return notRunCommands(cmds, others)
}

// notRunShellPayload returns the script of sh -c <script>, bash -c, or
// dash -c, with only -e, -u, -x, -l, or -i flags and no operand after
// the script.
func notRunShellPayload(argv []string) (string, bool) {
	if len(argv) < 3 {
		return "", false
	}
	switch progName(argv[0]) {
	case "sh", "bash", "dash":
	default:
		return "", false
	}
	if !strings.HasPrefix(argv[0], "/") && strings.Contains(argv[0], "/") {
		return "", false
	}
	sawC := false
	for i, a := range argv[1:] {
		if strings.HasPrefix(a, "-") && len(a) > 1 && !sawC {
			for _, f := range a[1:] {
				switch f {
				case 'c':
					sawC = true
				case 'e', 'u', 'x', 'l', 'i':
				default:
					return "", false
				}
			}
			continue
		}
		if !sawC || i+2 != len(argv) {
			return "", false
		}
		return a, true
	}
	return "", false
}

// nrCommand is a simple command: its words, the files its standard
// output is redirected to, and the files another descriptor is.
type nrCommand struct {
	words     []string
	redirects []string
	others    []string
}

// notRunDenied are commands that change what later names mean, run
// their operands, or start a construct the analysis does not follow.
var notRunDenied = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "source": true, ".": true,
	"eval": true, "exec": true, "trap": true, "alias": true, "xargs": true,
	"find": true, "function": true, "if": true, "then": true, "else": true,
	"elif": true, "fi": true, "for": true, "while": true, "until": true,
	"do": true, "done": true, "case": true, "esac": true, "select": true,
	"in": true, "{": true, "}": true, "!": true, "[[": true, "]]": true,
	"time": true, "coproc": true, "builtin": true, "enable": true,
	"hash": true, "shopt": true,
}

// notRunReaders never run their operands.
var notRunReaders = map[string]bool{
	"cat": true, "grep": true, "jq": true, "head": true, "tail": true,
	"wc": true, "ls": true, "sha256sum": true, "shasum": true,
	"md5sum": true, "cmp": true, "diff": true, "test": true, "[": true,
	"mkdir": true, "rm": true, "echo": true, "printf": true,
}

func notRunCommands(cmds []nrCommand, others []string) bool {
	fetched := map[string]bool{}
	var extracts []nrExtract
	var rest []nrCommand
	for _, c := range cmds {
		if len(c.words) == 0 {
			return false
		}
		name := c.words[0]
		switch {
		case name == "curl" || name == "wget":
			file, ok := notRunFetch(name, c.words[1:], c.redirects)
			if !ok || slices.ContainsFunc(c.others, func(o string) bool { return o != "/dev/null" }) {
				return false
			}
			if file != "" {
				fetched[file] = true
			}
		case name == "git" && len(c.words) > 1 && c.words[1] == "clone":
			dir, ok := notRunClone(c.words[2:])
			if !ok || len(c.redirects)+len(c.others) > 0 {
				return false
			}
			fetched[dir] = true
		case name == "tar" || name == "unzip":
			e, ok := notRunExtract(name, c.words[1:])
			if !ok || len(c.redirects)+len(c.others) > 0 {
				return false
			}
			extracts = append(extracts, e)
		case notRunDenied[name]:
			return false
		case notRunReaders[name] && len(c.redirects)+len(c.others) == 0:
		default:
			if fetchLike(c.words) {
				return false
			}
			rest = append(rest, c)
		}
	}
	// An archive fetched anywhere in the script makes its extraction
	// directory fetched, wherever the extraction is written.
	for changed := true; changed; {
		changed = false
		for _, e := range extracts {
			if !fetched[e.dir] && mentionsAny(e.archive, fetched) {
				fetched[e.dir] = true
				changed = true
			}
		}
	}
	for _, c := range rest {
		for _, w := range slices.Concat(c.words, c.redirects, c.others) {
			if mentionsAny(w, fetched) {
				return false
			}
		}
	}
	for _, o := range others {
		if mentionsAny(o, fetched) {
			return false
		}
	}
	return true
}

// fetchLike reports a command that has a risk of its own, read as if
// another command followed it (so git clone counts), or that names a
// downloader, a remote runner, or git clone in any word, such as sudo
// git clone or git -C dir clone.
func fetchLike(words []string) bool {
	var s scanner
	for _, w := range words {
		s.work += len(w) + 1
	}
	s.command(words, 0, true)
	if len(s.risks()) > 0 || s.unpinned {
		return true
	}
	git := false
	for _, w := range words {
		switch name := progName(w); {
		case downloaderNames[name] || remoteRunners[name]:
			return true
		case name == "git":
			git = true
		case git && w == "clone":
			return true
		}
	}
	return false
}

// remoteRunners are programs that fetch and run code by name.
var remoteRunners = map[string]bool{
	"nc": true, "ncat": true, "npx": true, "bunx": true, "uvx": true,
	"pipx": true, "deno": true, "dlx": true,
}

// mentionsAny reports whether text contains a fetched name, as written
// or as its last path segment, ignoring case.
func mentionsAny(text string, fetched map[string]bool) bool {
	lower := strings.ToLower(text)
	for name := range fetched {
		n := strings.ToLower(name)
		if strings.Contains(lower, n) || strings.Contains(lower, path.Base(n)) {
			return true
		}
	}
	return false
}

// notRunFetch returns the file a curl or wget writes, or "" for
// standard output.
func notRunFetch(name string, args, redirects []string) (string, bool) {
	var file, rawURL string
	files, urls, remoteName := 0, 0, false
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch {
		case a == "--remote-name" && name == "curl":
			remoteName = true
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
					if v, ok = next(); !ok {
						return "", false
					}
				}
				if kind == longOutput {
					file = v
					files++
				}
			default:
				return "", false
			}
		case a == "-nv" && name == "wget":
		case len(a) > 1 && a[0] == '-':
			out, short := byte('o'), "fsSLO"
			if name == "wget" {
				out, short = 'O', "q"
			}
			for j := 1; j < len(a); j++ {
				if a[j] == out {
					v := a[j+1:]
					if v == "" {
						var ok bool
						if v, ok = next(); !ok {
							return "", false
						}
					}
					file = v
					files++
					break
				}
				if strings.IndexByte(short, a[j]) < 0 {
					return "", false
				}
				if a[j] == 'O' {
					remoteName = true
				}
			}
		default:
			lower := strings.ToLower(a)
			if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
				return "", false
			}
			rawURL = a
			urls++
		}
	}
	if urls != 1 {
		return "", false
	}
	for _, r := range redirects {
		file = r
		files++
	}
	if remoteName || (name == "wget" && files == 0) {
		base, ok := urlFileName(rawURL)
		if !ok {
			return "", false
		}
		file = base
		files++
	}
	switch {
	case files == 0:
		return "", true
	case files > 1:
		return "", false
	}
	if !dataFile(file) {
		return "", false
	}
	return file, true
}

// urlFileName is the last path segment of an http(s) URL, as curl -O
// and wget name the file they write.
func urlFileName(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return "", false
	}
	segs := strings.Split(u.EscapedPath(), "/")
	base := segs[len(segs)-1]
	return base, plainFilename.MatchString(base)
}

// notRunClone returns the directory git clone writes.
func notRunClone(args []string) (string, bool) {
	var operands []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-q" || a == "--quiet" || a == "--single-branch" || a == "--no-tags":
		case a == "--depth" || a == "-b" || a == "--branch":
			if i+1 >= len(args) || !plainFilename.MatchString(args[i+1]) {
				return "", false
			}
			i++
		case strings.HasPrefix(a, "--depth=") || strings.HasPrefix(a, "--branch=") ||
			strings.HasPrefix(a, "--filter="):
		case strings.HasPrefix(a, "-"):
			return "", false
		default:
			operands = append(operands, a)
		}
	}
	if len(operands) == 0 || len(operands) > 2 {
		return "", false
	}
	lower := strings.ToLower(operands[0])
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") &&
		!strings.HasPrefix(lower, "git://") {
		return "", false
	}
	var dir string
	if len(operands) == 2 {
		dir = operands[1]
	} else {
		u, err := url.Parse(operands[0])
		if err != nil {
			return "", false
		}
		dir = strings.TrimSuffix(path.Base(strings.TrimSuffix(u.Path, "/")), ".git")
	}
	return dir, plainDir(dir)
}

type nrExtract struct{ archive, dir string }

// notRunExtract reads tar -x and unzip into an explicit directory. tar
// takes x, z, j, J, v, and f in its first word (with or without -) and
// -C, --strip-components, -v, and -f after it; unzip takes -q, -o, and
// -d.
func notRunExtract(name string, args []string) (nrExtract, bool) {
	var e nrExtract
	if name == "unzip" {
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case a == "-q" || a == "-o" || a == "-qo" || a == "-oq":
			case a == "-d":
				if i+1 >= len(args) || e.dir != "" {
					return e, false
				}
				i++
				e.dir = args[i]
			case strings.HasPrefix(a, "-") || e.archive != "":
				return e, false
			default:
				e.archive = a
			}
		}
		return e, e.archive != "" && plainDir(e.dir)
	}
	if len(args) == 0 {
		return e, false
	}
	mode := strings.TrimPrefix(args[0], "-")
	if mode == "" || !strings.Contains(mode, "x") || strings.Trim(mode, "xzjJvf") != "" {
		return e, false
	}
	wantFile := strings.Contains(mode, "f")
	if wantFile && !strings.HasSuffix(mode, "f") {
		return e, false
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case wantFile:
			e.archive, wantFile = a, false
		case a == "-f":
			if e.archive != "" {
				return e, false
			}
			wantFile = true
		case a == "-C":
			if i+1 >= len(args) || e.dir != "" {
				return e, false
			}
			i++
			e.dir = args[i]
		case a == "-v" || strings.HasPrefix(a, "--strip-components="):
		default:
			return e, false
		}
	}
	return e, !wantFile && e.archive != "" && plainDir(e.dir)
}

// plainDir is a relative path of plain segments (see plainFilename)
// that is not a directory tools load code from.
func plainDir(dir string) bool {
	if dir == "" || !plainPath(dir) {
		return false
	}
	for _, seg := range strings.Split(dir, "/") {
		if codeDirs[strings.ToLower(seg)] {
			return false
		}
	}
	return true
}

func plainPath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if !plainFile(seg) {
			return false
		}
	}
	return true
}

// codeDirs are directory names that tools load or run code from without
// naming the files in them.
var codeDirs = map[string]bool{
	"bin": true, "sbin": true, "libexec": true, "node_modules": true,
	"vendor": true, "site-packages": true, "hooks": true,
}

var dataExtension = regexp.MustCompile(`(?i)\.(tar|tar\.gz|tgz|tar\.xz|txz|tar\.bz2|tbz2?|tar\.zst|tzst|zip|gz|xz|bz2|zst|json|csv|tsv)$`)

// manifestFiles are data-named files a tool reads, and may run commands
// from, without being given the name.
var manifestFiles = map[string]bool{
	"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"composer.json": true, "deno.json": true, "project.json": true,
	"nx.json": true, "lerna.json": true, "turbo.json": true, "rush.json": true,
	"bower.json": true, "opencode.json": true, "crush.json": true,
	"mcp.json": true, "settings.json": true, "tasks.json": true,
	"launch.json": true, "devcontainer.json": true, "environment.json": true,
	"hooks.json": true, "plugin.json": true, "marketplace.json": true,
	"extensions.json": true, "app.json": true, "tsconfig.json": true,
	"jsconfig.json": true, "vercel.json": true, "firebase.json": true,
}

// dataFile is a fetched file name that only a command naming it reads:
// a relative path of plain segments, ending in an archive or data
// extension, that is not a manifest (see manifestFiles).
func dataFile(name string) bool {
	if !plainPath(name) || !dataExtension.MatchString(name) {
		return false
	}
	return !manifestFiles[strings.ToLower(path.Base(name))]
}

// parseNotRun splits a script into simple commands. It accepts words,
// single quotes, double quotes without $, a backquote, \, or !, a
// backslash-newline continuation, # comments, the separators ;,
// newline, &&, ||, and &, and the redirections > word, >> word, N>
// word, and N>&M. Anything else fails.
func parseNotRun(src string) ([]nrCommand, bool) {
	var (
		cmds   []nrCommand
		cur    nrCommand
		word   strings.Builder
		inWord bool
		redir  bool
		stderr bool
	)
	endWord := func() {
		if !inWord {
			return
		}
		switch {
		case redir && stderr:
			cur.others = append(cur.others, word.String())
			redir = false
		case redir:
			cur.redirects = append(cur.redirects, word.String())
			redir = false
		default:
			cur.words = append(cur.words, word.String())
		}
		word.Reset()
		inWord = false
	}
	endCmd := func() bool {
		endWord()
		if redir {
			return false
		}
		if len(cur.words) > 0 {
			cmds = append(cmds, cur)
		} else if len(cur.redirects)+len(cur.others) > 0 {
			return false
		}
		cur = nrCommand{}
		return true
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case c == '\\':
			if i+1 >= len(src) || src[i+1] != '\n' {
				return nil, false
			}
			endWord()
			i++
		case c == '\n' || c == ';':
			if c == ';' && i+1 < len(src) && src[i+1] == ';' {
				return nil, false
			}
			if !endCmd() {
				return nil, false
			}
		case c == '&' || c == '|':
			double := i+1 < len(src) && src[i+1] == c
			if c == '|' && !double || c == '&' && i+1 < len(src) && src[i+1] == '>' {
				return nil, false
			}
			if !endCmd() {
				return nil, false
			}
			if double {
				i++
			}
		case c == '>':
			if redir {
				return nil, false
			}
			stderr = false
			if inWord {
				// Only a file descriptor number may come right before >.
				w := word.String()
				if w == "" || strings.Trim(w, "0123456789") != "" {
					return nil, false
				}
				stderr = w != "1"
				word.Reset()
				inWord = false
			}
			if i+1 < len(src) && src[i+1] == '>' {
				i++
			}
			if i+1 < len(src) && src[i+1] == '&' {
				j := i + 2
				for j < len(src) && isDigit(src[j]) {
					j++
				}
				if j == i+2 {
					return nil, false
				}
				i = j - 1
				continue
			}
			redir = true
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
			inWord = true
			word.WriteString(body)
			i += end + 1
		case isWordByte(c):
			inWord = true
			word.WriteByte(c)
		default:
			return nil, false
		}
	}
	if !endCmd() {
		return nil, false
	}
	return cmds, true
}
