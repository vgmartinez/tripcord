package shellcmd

import (
	"bytes"
	"slices"
)

// Sums is what a repository's checksum files list: for each sums file,
// by the name a command gives it, the files its entries check. A sums
// file that is not committed, resolves outside the repository, or is
// not in sha256sum's format has no entry (see ParseSums), and a
// sha256sum -c of a file with no entry covers nothing.
type Sums map[string][]string

// MaxSumsBytes caps how much of one sums file is read.
const MaxSumsBytes = 64 << 10

// ParseSums returns the file names of a sha256sum file: one
// "<64 hex>  <name>" or "<64 hex> *<name>" entry per line, with an
// optional final newline. Anything else, including an empty file, a
// blank line, a carriage return, or the BSD "SHA256 (name) = ..." form,
// is malformed and ok is false.
func ParseSums(data []byte) (names []string, ok bool) {
	data = bytes.TrimSuffix(data, []byte("\n"))
	if len(data) == 0 {
		return nil, false
	}
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		m := checksumLine.FindSubmatch(line)
		if m == nil {
			return nil, false
		}
		if name := string(m[1]); !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names, true
}

// ChecksumFiles returns the sums files the form 2 checks (sha256sum -c
// <file>, shasum -a 256 -c <file>) of a checksum-grammar script name,
// or nil when line is not one the grammar parses.
func ChecksumFiles(line string) []string {
	lists, ok := parseScript(line)
	if !ok {
		return nil
	}
	var out []string
	for _, l := range lists {
		for _, p := range l {
			if e, ok := classifyPipeline(p); ok && e.kind == kindCheck && e.sums != "" && !slices.Contains(out, e.sums) {
				out = append(out, e.sums)
			}
		}
	}
	return out
}

// ChecksumFilesArgv is ChecksumFiles for an argument vector: only sh or
// bash, -c, and a script have any.
func ChecksumFilesArgv(argv []string) []string {
	if !shellScriptArgv(argv) {
		return nil
	}
	return ChecksumFiles(argv[2])
}

// ChecksumTargets returns the files a checksum-grammar script fetches
// or runs, or nil when line is not one the grammar parses. The caller
// uses this to reject a committed symlink at either final path: curl
// would otherwise follow it while writing and sha256sum or sh would
// follow it while reading.
func ChecksumTargets(line string) []string {
	lists, ok := parseScript(line)
	if !ok {
		return nil
	}
	var out []string
	for _, l := range lists {
		for _, p := range l {
			e, ok := classifyPipeline(p)
			if !ok {
				return nil
			}
			if (e.kind == kindFetch || e.kind == kindRun) && !slices.Contains(out, e.file) {
				out = append(out, e.file)
			}
		}
	}
	return out
}

// ChecksumTargetsArgv is ChecksumTargets for an argument vector: only
// sh or bash, -c, and a script have any.
func ChecksumTargetsArgv(argv []string) []string {
	if !shellScriptArgv(argv) {
		return nil
	}
	return ChecksumTargets(argv[2])
}

func shellScriptArgv(argv []string) bool {
	return len(argv) == 3 && (argv[0] == "sh" || argv[0] == "bash") && argv[1] == "-c"
}
