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
//   - Checksum. The whole line is a script the checksum grammar
//     accepts (see checksumScript): only fetches to literal files,
//     sha256sum checks that cover them, runs of verified files with sh
//     or bash, a leading set -e, and a few file and variable commands.
//     Anything else on the line gives no checksum credit.
//
// Package runners (npx, bunx, pnpm and yarn dlx, uvx, pipx run), git
// clone, inline python or node code, a variable target, and a .NET
// download are never checksum-verified; a version number or tag is not
// a pin. Unpinned has no sums files, so a sha256sum -c <file> check
// covers nothing; see UnpinnedSums.
func Unpinned(line string) Result { return UnpinnedSums(line, nil) }

// UnpinnedSums is Unpinned where a sha256sum -c <file> check covers the
// files sums lists for <file>.
func UnpinnedSums(line string, sums Sums) Result {
	return UnpinnedSumsTargets(line, sums, nil)
}

// UnpinnedSumsTargets is UnpinnedSums where targets is the committed
// symlink names among the grammar script's fetch and run files. A
// downloader follows such a symlink while writing, and a checker or
// shell follows one while reading, so either gets no checksum credit.
func UnpinnedSumsTargets(line string, sums Sums, targets map[string]bool) Result {
	var s scanner
	s.line(line, 0, false)
	if strings.Contains(line, "`") {
		s.line(line, 0, true)
	}
	return s.unpinnedResult(checksumScript(line, sums) && safeChecksumTargets(line, targets))
}

// UnpinnedArgv is Unpinned for an argument vector (see RisksArgv). A
// single command has no checksum check after it, so only an immutable
// URL pins it, unless the vector is exactly sh or bash, -c, and a
// script the checksum grammar accepts.
func UnpinnedArgv(argv []string) Result { return UnpinnedArgvSums(argv, nil) }

// UnpinnedArgvSums is UnpinnedArgv with sums (see UnpinnedSums).
func UnpinnedArgvSums(argv []string, sums Sums) Result {
	return UnpinnedArgvSumsTargets(argv, sums, nil)
}

// UnpinnedArgvSumsTargets is UnpinnedArgvSums with targets (see
// UnpinnedSumsTargets).
func UnpinnedArgvSumsTargets(argv []string, sums Sums, targets map[string]bool) Result {
	var s scanner
	for _, a := range argv {
		s.work += len(a) + 1
	}
	s.command(argv, 0, false)
	verified := shellScriptArgv(argv) && checksumScript(argv[2], sums) && safeChecksumTargets(argv[2], targets)
	return s.unpinnedResult(verified)
}

func safeChecksumTargets(line string, targets map[string]bool) bool {
	for _, name := range ChecksumTargets(line) {
		if targets[name] {
			return false
		}
	}
	return true
}

// unpinnedResult is the scan's result, with no risks when every fetch is
// an immutable URL or verified is set (the line is a checksum script).
func (s *scanner) unpinnedResult(verified bool) Result {
	pinned := s.fetch && !s.encoded && !s.nested &&
		(!s.unpinned || (!s.pipe && verified))
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
