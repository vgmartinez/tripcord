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
//   - Checksum. Nothing is piped into a shell or Invoke-Expression, and
//     each command that fetches is followed, as the next statement of
//     the same command line, by a SHA-2 checksum check (sha256sum,
//     sha384sum, or sha512sum with -c or --check, or shasum -a 256, 384,
//     or 512 with -c) that stops the line when it fails: it is joined to
//     what follows by &&, ends the line, or runs after set -e.
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
// or an OCI digest where that service treats it as immutable. Any other
// host, a userinfo, a trailing-dot host, and a non-https URL are
// rejected: a hex string in the path is not itself a pin.
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
// archive paths do. A sha256: digest counts only as an OCI registry
// blob or manifest (a blobs or manifests segment followed by
// sha256:<64 hex>), not as a path segment on an arbitrary host.
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
		return ociDigest(segs)
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

func ociDigest(segs []string) bool {
	registry := false
	for _, seg := range segs {
		if seg == "blobs" || seg == "manifests" {
			registry = true
			continue
		}
		digest, ok := strings.CutPrefix(seg, "sha256:")
		if registry && ok && len(digest) == 64 && isHex(digest) {
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

// verifiedFetches reports that each command marked in direct is
// followed, as the next statement, by a checksum check that stops the
// line when it fails (see Unpinned).
func verifiedFetches(cmds []command, direct []bool) bool {
	errexit := make([]bool, len(cmds))
	on := false
	for i, c := range cmds {
		errexit[i] = on
		on = on || setsErrexit(c.words)
	}
	for i, d := range direct {
		if !d {
			continue
		}
		next := -1
		for j := i + 1; j < len(cmds); j++ {
			if cmds[j].stmt != cmds[i].stmt {
				next = j
				break
			}
		}
		if next < 0 {
			return false
		}
		checked, last := false, next
		for j := next; j < len(cmds) && cmds[j].stmt == cmds[next].stmt; j++ {
			checked = checked || checksumCheck(cmds[j].words)
			last = j
		}
		if !checked {
			return false
		}
		switch cmds[last].sep {
		case "&&", "":
		case opSep:
			if !errexit[last] {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// setsErrexit reports set -e (alone or in a cluster such as -eu) or
// set -o errexit.
func setsErrexit(words []string) bool {
	w := unwrap(words)
	if len(w) == 0 || w[0] != "set" {
		return false
	}
	for i, a := range w[1:] {
		switch {
		case a == "-o" && i+2 < len(w) && w[i+2] == "errexit":
			return true
		case len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.IndexByte(a[1:], 'e') >= 0:
			return true
		}
	}
	return false
}

// checksumCheck reports sha256sum, sha384sum, or sha512sum with -c or
// --check, or shasum with -c and -a 256, 384, or 512.
func checksumCheck(words []string) bool {
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
	args := w[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--check":
			check = true
		case a == "-a" || a == "--algorithm":
			if i+1 < len(args) {
				i++
				strong = strong || sha2Bits(args[i])
			}
		case strings.HasPrefix(a, "--algorithm="):
			strong = strong || sha2Bits(strings.TrimPrefix(a, "--algorithm="))
		case strings.HasPrefix(a, "-a") && name == "shasum":
			strong = strong || sha2Bits(a[2:])
		case len(a) > 1 && a[0] == '-' && a[1] != '-':
			check = check || strings.IndexByte(a[1:], 'c') >= 0
		}
	}
	return check && strong
}

func sha2Bits(v string) bool {
	return v == "256" || v == "384" || v == "512"
}
