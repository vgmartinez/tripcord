package shellcmd

import (
	"net/url"
	"strings"
)

// Unpinned is Analyze, with no risks when the line is pinned: every
// fetch in it is pinned, the line pipes into a shell only what a pinned
// fetch downloaded, and nothing in it is encoded or nested deeper than
// the reader follows. A line is pinned in one of two ways, and a line
// that mixes them is not pinned:
//
//   - Immutable URL. Every fetch is a downloader (curl, wget, iwr, irm,
//     Invoke-WebRequest, Invoke-RestMethod, Start-BitsTransfer) or a
//     deno run whose every remote target is an allowlisted https URL
//     (see immutableURL), or a .NET Download* call whose every remote
//     URL is. Piping that download into a shell is pinned.
//   - Checksum. Each direct fetch is followed by sha256sum -c <file>
//     (or sha384sum, sha512sum, or shasum -a 256|384|512). The file is
//     not /dev/* or -, and the check has no other flag. It is joined to
//     the fetch and to whatever runs it only by &&, in one simple list.
//     A set -e or set -euo pipefail also covers it (see errexitVerified)
//     when the set is a foreground top-level command before the first
//     fetch, and the fetch and the check are each a simple command on
//     their own, ended by ; or a newline. set +e, eval, source, ., ||,
//     !, or a pipe anywhere on the line defeats it.
//
// Package runners (npx, bunx, pnpm and yarn dlx, uvx, pipx run), git
// clone, inline python or node code, a variable target, and a .NET
// download are never checksum-verified; a version number or tag is not
// a pin.
func Unpinned(line string) Result {
	var s scanner
	s.line(line, 0, false)
	if strings.Contains(line, "`") {
		s.line(line, 0, true)
	}
	return s.unpinnedResult()
}

// UnpinnedArgv is Unpinned for an argument vector (see RisksArgv). A
// single command has no checksum check after it, so only an immutable
// URL pins it.
func UnpinnedArgv(argv []string) Result {
	var s scanner
	for _, a := range argv {
		s.work += len(a) + 1
	}
	s.command(argv, 0, false)
	if s.direct {
		s.unverified = true
	}
	return s.unpinnedResult()
}

func (s *scanner) unpinnedResult() Result {
	pinned := s.fetch && !s.encoded && !s.nested &&
		(!s.unpinned || (!s.pipe && !s.unverified))
	if pinned {
		return Result{Risks: []string{}, Work: s.work}
	}
	return Result{Risks: s.risks(), Work: s.work}
}

var downloaderNames = map[string]bool{
	"curl": true, "wget": true, "iwr": true, "irm": true,
	"invoke-webrequest": true, "invoke-restmethod": true, "start-bitstransfer": true,
}

// variableTarget reports a downloader argument that is a variable, as
// downloader does: its value is not known, so it cannot be pinned.
func variableTarget(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "$") || strings.Contains(a, "=$") || strings.Contains(a, ":$") {
			return true
		}
	}
	return false
}

// immutableTargets reports a fetch whose every remote target is an
// immutable URL: a downloader without a variable target, or deno run.
func immutableTargets(name string, args []string) bool {
	switch {
	case downloaderNames[name]:
		if variableTarget(args) {
			return false
		}
	case name == "deno" && len(args) > 0:
		args = args[1:]
	default:
		return false
	}
	found := false
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			_, v, ok := strings.Cut(a, "=")
			if !ok {
				continue
			}
			a = v
		}
		if classify(a, false) != remote {
			continue
		}
		if !immutableURL(a) {
			return false
		}
		found = true
	}
	return found
}

// urlsImmutable reports free text whose every remote URL is immutable.
func urlsImmutable(text string) bool {
	found := false
	for rest := text; ; {
		i := strings.Index(rest, "://")
		if i < 0 {
			return found
		}
		start := i
		for start > 0 && isSchemeChar(rest[start-1]) {
			start--
		}
		end := i + 3
		for end < len(rest) && !strings.ContainsRune(" \t\r\n'\"`()<>|;", rune(rest[end])) {
			end++
		}
		if w := rest[start:end]; classify(w, false) == remote {
			if !immutableURL(w) {
				return false
			}
			found = true
		}
		rest = rest[end:]
	}
}

// immutableURL reports an https URL whose host and path place a commit
// where that service treats it as immutable. Any other host, a
// userinfo, a trailing-dot host, a non-https URL, and a path with a .
// or .. segment (decoded or not) are rejected: a hex string in the path
// is not itself a pin.
//
//	raw.githubusercontent.com/<owner>/<repo>/<sha>/...
//	github.com/<owner>/<repo>/raw/<sha>/...
//	github.com/<owner>/<repo>/archive/<sha>.tar.gz|.zip
//	codeload.github.com/<owner>/<repo>/<tar.gz|zip|legacy.tar.gz|legacy.zip>/<sha>
//	gist.githubusercontent.com/<user>/<id>/raw/<sha>/...
//	gist.github.com/<user>/<id>/raw/<sha>/...
//	cdn.jsdelivr.net/gh/<user>/<repo>@<sha>/...
//	gitlab.com/<group>/<project>/-/raw/<sha>/...
//
// jsDelivr and GitLab are included because a full commit SHA on those
// exact paths addresses one stored tree, the same way GitHub's raw and
// archive paths do. A sha256: digest is never a pin: curl and wget do
// not verify it, so the server can return anything under that name.
func immutableURL(w string) bool {
	u, err := url.Parse(w)
	if err != nil || u.User != nil || !strings.EqualFold(u.Scheme, "https") {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(host, ".") {
		return false
	}
	segs := pathSegments(u.EscapedPath())
	if dotSegment(segs) {
		return false
	}
	switch strings.ToLower(host) {
	case "raw.githubusercontent.com":
		return len(segs) >= 4 && isCommit(segs[2])
	case "github.com":
		return githubImmutable(segs)
	case "codeload.github.com":
		return codeloadImmutable(segs)
	case "gist.githubusercontent.com", "gist.github.com":
		return len(segs) >= 4 && segs[2] == "raw" && isCommit(segs[3])
	case "cdn.jsdelivr.net":
		return jsDelivrImmutable(segs)
	case "gitlab.com":
		return gitlabImmutable(segs)
	default:
		return false
	}
}

func pathSegments(path string) []string {
	var segs []string
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			segs = append(segs, seg)
		}
	}
	return segs
}

// dotSegment reports a . or .. path segment, as written or after
// percent-decoding in any case (%2e, .%2E). curl and wget resolve them
// before the request, so <sha>/../main fetches main.
func dotSegment(segs []string) bool {
	for _, seg := range segs {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			return true
		}
		if seg == "." || seg == ".." || decoded == "." || decoded == ".." {
			return true
		}
	}
	return false
}

func githubImmutable(segs []string) bool {
	if len(segs) >= 5 && segs[2] == "raw" && isCommit(segs[3]) {
		return true
	}
	return len(segs) == 4 && segs[2] == "archive" && commitFile(segs[3])
}

func codeloadImmutable(segs []string) bool {
	if len(segs) != 4 {
		return false
	}
	switch segs[2] {
	case "tar.gz", "zip", "legacy.tar.gz", "legacy.zip":
		return isCommit(segs[3])
	default:
		return false
	}
}

func jsDelivrImmutable(segs []string) bool {
	if len(segs) < 3 || segs[0] != "gh" {
		return false
	}
	_, version, ok := strings.Cut(segs[2], "@")
	return ok && isCommit(version)
}

func gitlabImmutable(segs []string) bool {
	for i := 0; i+2 < len(segs); i++ {
		if segs[i] == "-" && segs[i+1] == "raw" && isCommit(segs[i+2]) {
			return true
		}
	}
	return false
}

func isCommit(s string) bool {
	return (len(s) == 40 || len(s) == 64) && isHex(s)
}

func commitFile(name string) bool {
	for _, ext := range []string{".tar.gz", ".zip"} {
		if stem, ok := strings.CutSuffix(name, ext); ok {
			return isCommit(stem)
		}
	}
	return false
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if !isDigit(s[i]) && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// verifiedFetches reports that each direct fetch is covered by a clean
// checksum (see Unpinned). Anything short of the two accepted shapes is
// not verified.
func verifiedFetches(cmds []command, direct []bool) bool {
	if !anyDirect(direct) {
		return true
	}
	if errexitVerified(cmds, direct) {
		return true
	}
	for i, d := range direct {
		if d && !andListVerified(cmds, i) {
			return false
		}
	}
	return true
}

func anyDirect(direct []bool) bool {
	for _, d := range direct {
		if d {
			return true
		}
	}
	return false
}

// errexitVerified reports the set -e shape: a foreground top-level set -e
// before the first direct fetch, and each direct fetch a simple command
// on its own followed by a check that is also a simple command on its
// own, each ended by ; or a newline. A fetch or check inside an && or ||
// list, backgrounded with &, or inside a compound command does not abort
// on failure, so it does not count. eval, source, ., set +e, ||, !, or a
// pipe anywhere on the line defeats errexit.
func errexitVerified(cmds []command, direct []bool) bool {
	top := topLevel(cmds)
	if errexitDefeated(cmds) || !errexitBefore(cmds, top, firstDirect(direct)) {
		return false
	}
	for i, d := range direct {
		if d && !checksumFollows(cmds, top, i) {
			return false
		}
	}
	return true
}

func firstDirect(direct []bool) int {
	for i, d := range direct {
		if d {
			return i
		}
	}
	return len(direct)
}

// topLevel reports, for each command, that it is outside (), {},
// if/while/for/case, and a function body.
func topLevel(cmds []command) []bool {
	top := make([]bool, len(cmds))
	compound := 0
	for i, c := range cmds {
		top[i] = c.depth == 0 && compound == 0
		compound = adjustCompound(compound, c.words)
	}
	return top
}

// errexitBefore reports a set -e or set -euo pipefail that is a
// foreground simple command at top level, ended by ; or a newline, and
// that comes before the first direct fetch.
func errexitBefore(cmds []command, top []bool, fetch int) bool {
	for i := 0; i < fetch; i++ {
		on, _ := setErrexit(cmds[i].words)
		if on && simpleStatement(cmds, top, i) {
			return true
		}
	}
	return false
}

// simpleStatement reports a top-level command that is a whole statement
// on its own: not in a pipeline, not in an && or || list, not
// backgrounded, and ended by ; or a newline.
func simpleStatement(cmds []command, top []bool, i int) bool {
	return top[i] && statementLen(cmds, i) == 1 && cmds[i].sep == opSep && startsStatement(cmds, i) && !reservedStart(cmds[i].words)
}

// startsStatement reports a command that the previous statement ended
// with ; or a newline, or that starts the line.
func startsStatement(cmds []command, i int) bool {
	return i == 0 || cmds[i-1].sep == opSep
}

// reservedStart reports a command that begins with a reserved word (if,
// while, !, {, ...). A check that is an if or while condition does not
// abort under set -e.
func reservedStart(words []string) bool {
	for _, w := range words {
		if isAssignment(w) {
			continue
		}
		return reserved[w]
	}
	return false
}

// errexitDefeated reports what turns set -e off or keeps a failure from
// aborting: set +e, eval, source, or . anywhere, and ||, !, or a pipe.
func errexitDefeated(cmds []command) bool {
	for _, c := range cmds {
		if c.pipeIn || c.sep == "||" || hasBang(c.words) {
			return true
		}
		if _, off := setErrexit(c.words); off {
			return true
		}
		w := unwrap(c.words)
		if len(w) > 1 && progName(w[0]) == "builtin" {
			w = w[1:]
		}
		if len(w) > 0 {
			switch progName(w[0]) {
			case "eval", "source", ".":
				return true
			}
		}
	}
	return false
}

func andListVerified(cmds []command, fetch int) bool {
	if cmds[fetch].sep != "&&" || statementLen(cmds, fetch) != 1 {
		return false
	}
	start, end, ok := nextStatement(cmds, fetch)
	if !ok || end-start != 1 || cmds[start].pipeIn || reservedStart(cmds[start].words) || !cleanChecksum(cmds[start].words) {
		return false
	}
	for j := start; j < len(cmds); j++ {
		if cmds[j].pipeIn || cmds[j].sep == "||" || hasBang(cmds[j].words) {
			return false
		}
	}
	return cmds[start].sep == "&&" || cmds[start].sep == ""
}

// checksumFollows reports a fetch that is a simple statement followed
// by a check that is one too. The check may also end the line.
func checksumFollows(cmds []command, top []bool, fetch int) bool {
	if !simpleStatement(cmds, top, fetch) {
		return false
	}
	start, end, ok := nextStatement(cmds, fetch)
	if !ok || end-start != 1 || !top[start] || cmds[start].pipeIn || reservedStart(cmds[start].words) {
		return false
	}
	if sep := cmds[start].sep; sep != opSep && sep != "" {
		return false
	}
	return cleanChecksum(cmds[start].words)
}

func statementLen(cmds []command, i int) int {
	n := 1
	for j := i - 1; j >= 0 && cmds[j].stmt == cmds[i].stmt; j-- {
		n++
	}
	for j := i + 1; j < len(cmds) && cmds[j].stmt == cmds[i].stmt; j++ {
		n++
	}
	return n
}

func nextStatement(cmds []command, i int) (start, end int, ok bool) {
	for j := i + 1; j < len(cmds); j++ {
		if cmds[j].stmt == cmds[i].stmt {
			continue
		}
		start = j
		end = j + 1
		for end < len(cmds) && cmds[end].stmt == cmds[start].stmt {
			end++
		}
		return start, end, true
	}
	return 0, 0, false
}

func hasBang(words []string) bool {
	for _, w := range words {
		if w == "!" {
			return true
		}
	}
	return false
}

func adjustCompound(depth int, words []string) int {
	for _, w := range words {
		switch w {
		case "{", "if", "while", "until", "for", "case", "function":
			depth++
		case "}", "fi", "done", "esac":
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

// setErrexit reports whether these words turn errexit on or off. A short
// cluster enables it when it contains e (set -e, set -euo pipefail) and
// disables it when the cluster starts with + (set +e).
func setErrexit(words []string) (on, off bool) {
	compound := 0
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch w {
		case "{", "if", "while", "until", "for", "case", "function":
			compound++
			continue
		case "}", "fi", "done", "esac":
			if compound > 0 {
				compound--
			}
			continue
		}
		if w != "set" || compound > 0 {
			continue
		}
		for _, a := range words[i+1:] {
			switch {
			case a == "-o" || a == "+o":
				continue
			case a == "errexit":
				continue
			case len(a) > 1 && (a[0] == '-' || a[0] == '+') && a[1] != '-' && a[1] != '+':
				if strings.IndexByte(a, 'e') < 0 {
					continue
				}
				if a[0] == '+' {
					off = true
				} else {
					on = true
				}
			}
		}
		// -o errexit and +o errexit are pairs, so scan them explicitly.
		args := words[i+1:]
		for j := 0; j < len(args); j++ {
			if (args[j] == "-o" || args[j] == "+o") && j+1 < len(args) && args[j+1] == "errexit" {
				if args[j] == "+o" {
					off = true
				} else {
					on = true
				}
			}
		}
	}
	return on, off
}

// cleanChecksum reports sha256sum, sha384sum, or sha512sum -c <file>,
// or shasum -a 256|384|512 -c <file>. --check is the long form of -c.
// Any other flag, a missing file, -, and /dev/* do not count.
func cleanChecksum(words []string) bool {
	if hasBang(words) {
		return false
	}
	w := unwrap(words)
	if len(w) == 0 {
		return false
	}
	name := progName(w[0])
	switch name {
	case "sha256sum", "sha384sum", "sha512sum", "shasum":
	default:
		return false
	}
	check, strong := false, name != "shasum"
	var files []string
	args := w[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case a == "--check":
			check = true
		case strings.HasPrefix(a, "--"):
			return false
		case name == "shasum" && a == "-a" && i+1 < len(args):
			i++
			strong = sha2Bits(args[i])
		case name == "shasum" && strings.HasPrefix(a, "-a") && len(a) > 2:
			strong = sha2Bits(a[2:])
		case len(a) > 1 && a[0] == '-' && a[1] != '-':
			for _, c := range a[1:] {
				if c != 'c' {
					return false
				}
				check = true
			}
		default:
			files = append(files, a)
		}
	}
	if !check || !strong || len(files) == 0 {
		return false
	}
	for _, file := range files {
		if file == "-" || file == "" || strings.HasPrefix(file, "/dev/") {
			return false
		}
	}
	return true
}

func sha2Bits(v string) bool {
	return v == "256" || v == "384" || v == "512"
}
