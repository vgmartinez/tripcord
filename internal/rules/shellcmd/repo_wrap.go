package shellcmd

import (
	"path"
	"strings"
)

// RepoFile is a path a shell wrapper runs. FromRoot is relative to the
// repository root (a git toplevel). Beside is relative to the directory
// that holds the config file (a Claude plugin root). Otherwise the path
// is relative to that directory for a nested config file, and to the
// repository root for a config file at the root.
type RepoFile struct {
	Path     string
	Beside   bool
	FromRoot bool
}

// RepoWrapper reports whether argv is a shell wrapper around the
// repository's own files. ok is false for a pipe, a fetch, an inline
// interpreter, a remote script, or a path that leaves the repository.
// The files it returns have to exist in the scanned tree before the
// wrapper is quiet, except a dotenv sourced by a `set -a` loader: that
// file is usually gitignored, and the command it wraps is the same
// launcher shell.mcp already accepts. A loader without `set -a` still
// names the dotenv, so `. ./.env && exec npx` stays a finding when the
// file is absent.
func RepoWrapper(argv []string) ([]RepoFile, bool) {
	if len(argv) == 0 || argvHasOpaque(argv) {
		return nil, false
	}
	if len(argv) == 1 {
		if words, ok := shellWords(argv[0]); ok {
			return RepoWrapper(words)
		}
	}
	w := unwrap(argv)
	if len(w) == 0 {
		return nil, false
	}
	name, args := progName(w[0]), w[1:]
	if name == "powershell" || name == "pwsh" {
		return psScript(args)
	}
	if !posixShells[name] {
		return nil, false
	}
	if payload, _, ok := shellPayloadAt(name, args); ok {
		return payloadWrap(payload)
	}
	return directScript(name, args)
}

func payloadWrap(payload string) ([]RepoFile, bool) {
	if payload == "" || strings.Contains(payload, "`") || strings.Contains(payload, "%") || strings.Contains(payload, "^") {
		return nil, false
	}
	if files, ok := gitExec(payload); ok {
		return files, true
	}
	if files, ok := gitAssignChain(payload); ok {
		return files, true
	}
	if files, ok := envLoader(payload); ok {
		return files, true
	}
	return simpleLaunch(payload)
}

// directScript is `bash script.sh` with no -c. A login flag and `--`
// do not add a command. Anything else before the script does.
func directScript(name string, args []string) ([]RepoFile, bool) {
	if !posixShells[name] {
		return nil, false
	}
	if _, ok := shellPayload(name, args); ok {
		return nil, false
	}
	if len(args) > 0 && (args[0] == "-l" || args[0] == "--login") {
		args = args[1:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return nil, false
	}
	if rel, ok := pluginRel(args[0]); ok {
		if badArgs(args[1:]) {
			return nil, false
		}
		return []RepoFile{{Path: rel, Beside: true}}, true
	}
	rel, ok := relInside(args[0])
	if !ok || badArgs(args[1:]) {
		return nil, false
	}
	return []RepoFile{{Path: rel}}, true
}

// gitExec is `exec "$(git rev-parse --show-toplevel)/scripts/x.sh"`.
// The only substitution allowed is that one command, and only as a
// prefix of one path.
func gitExec(payload string) ([]RepoFile, bool) {
	toks, subs := lex(payload, false)
	if len(subs) != 1 || !gitTop(subs[0]) || hasOp(toks) {
		return nil, false
	}
	cmds := split(toks)
	if len(cmds) != 1 || cmds[0].pipeIn || cmds[0].depth != 0 {
		return nil, false
	}
	w := unwrap(cmds[0].words)
	if len(w) == 0 {
		return nil, false
	}
	rel, ok := topRel(w[0])
	if !ok || badArgs(w[1:]) {
		return nil, false
	}
	return []RepoFile{{Path: rel, FromRoot: true}}, true
}

// gitAssignChain is the committed-script form
//
//	repo=$(git rev-parse --show-toplevel) || exit 1; cd "$repo" || exit 1; exec bun run <file>
//
// The same line with any other substitution, or any extra command, is
// not this form. <file> is returned so a missing file stays a finding.
func gitAssignChain(payload string) ([]RepoFile, bool) {
	toks, subs := lex(payload, false)
	if len(subs) != 1 || !gitTop(subs[0]) {
		return nil, false
	}
	cmds := split(toks)
	if len(cmds) != 5 {
		return nil, false
	}
	seps := []string{"||", ";", "||", ";", ""}
	for i, c := range cmds {
		if c.pipeIn || c.depth != 0 || c.sep != seps[i] {
			return nil, false
		}
	}
	if len(cmds[0].words) != 1 || cmds[0].words[0] != "repo="+subst {
		return nil, false
	}
	if !exitOne(cmds[1].words) || !exitOne(cmds[3].words) {
		return nil, false
	}
	if len(cmds[2].words) != 2 || cmds[2].words[0] != "cd" || (cmds[2].words[1] != "$repo" && cmds[2].words[1] != "${repo}") {
		return nil, false
	}
	return bunRun(unwrap(cmds[4].words))
}

func bunRun(w []string) ([]RepoFile, bool) {
	if len(w) < 3 || progName(w[0]) != "bun" || w[1] != "run" {
		return nil, false
	}
	rel, ok := relInside(w[2])
	if !ok || badArgs(w[3:]) {
		return nil, false
	}
	return []RepoFile{{Path: rel, FromRoot: true}}, true
}

func exitOne(words []string) bool {
	return len(words) == 2 && words[0] == "exit" && words[1] == "1"
}

type prefixKind int

const (
	prefixSet prefixKind = iota
	prefixSetA
	prefixSource
	prefixCD
	prefixFile
)

// envLoader is `set -a && source .env && npx -y pkg` and the same
// commands joined with `;`. Every command but the last is `set -a`,
// `set +a`, `source` or `.` of one relative path, or `cd` of one
// relative directory. The last command is one launcher.
func envLoader(payload string) ([]RepoFile, bool) {
	toks, subs := lex(payload, false)
	if len(subs) > 0 {
		return nil, false
	}
	toks, ok := dropNullRedirects(toks)
	if !ok {
		return nil, false
	}
	for _, t := range toks {
		if t.op != "" && t.op != "&&" && t.op != ";" {
			return nil, false
		}
	}
	cmds := split(toks)
	if len(cmds) < 2 {
		return nil, false
	}
	sawSetA := false
	var sources, dirs, must []string
	for i := 0; i < len(cmds)-1; i++ {
		c := cmds[i]
		if c.pipeIn || c.depth != 0 || (c.sep != "&&" && c.sep != ";") {
			return nil, false
		}
		kind, rel, ok := loaderPrefix(c.words)
		if !ok {
			return nil, false
		}
		switch kind {
		case prefixSetA:
			sawSetA = true
		case prefixSet:
		case prefixSource:
			sources = append(sources, rel)
		case prefixCD:
			dirs = append(dirs, rel)
		case prefixFile:
			must = append(must, rel)
		default:
			// A new prefix is not a loader. Fail closed.
			return nil, false
		}
	}
	last := cmds[len(cmds)-1]
	if last.pipeIn || last.depth != 0 || last.sep != "" {
		return nil, false
	}
	files, ok := launchFiles(last.words)
	if !ok {
		return nil, false
	}
	for _, rel := range sources {
		if sawSetA && dotenvBase(rel) {
			continue
		}
		files = append(files, RepoFile{Path: rel})
	}
	for _, rel := range dirs {
		files = append(files, RepoFile{Path: rel})
	}
	for _, rel := range must {
		files = append(files, RepoFile{Path: rel})
	}
	if !sawSetA && len(files) == 0 {
		return nil, false
	}
	return dedupe(files), true
}

// simpleLaunch is one launcher, possibly with plain parameter
// expansions in its arguments: exec npx -y pkg --dsn "$DSN". A command
// substitution, a pipe, or a second command is not one launcher.
func simpleLaunch(payload string) ([]RepoFile, bool) {
	toks, subs := lex(payload, false)
	if len(subs) > 0 || hasOp(toks) {
		return nil, false
	}
	cmds := split(toks)
	if len(cmds) != 1 || cmds[0].pipeIn || cmds[0].depth != 0 {
		return nil, false
	}
	return launchFiles(cmds[0].words)
}

// dropNullRedirects removes redirections to /dev/null. 2>&1 is already
// consumed by the lexer. Any other redirection stays a finding.
func dropNullRedirects(toks []token) ([]token, bool) {
	out := make([]token, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		if toks[i].op != opRedirect {
			out = append(out, toks[i])
			continue
		}
		if i+1 >= len(toks) || toks[i+1].op != "" || toks[i+1].word != "/dev/null" {
			return nil, false
		}
		i++
	}
	return out, true
}

func loaderPrefix(words []string) (prefixKind, string, bool) {
	w := unwrap(words)
	switch {
	case len(w) == 2 && w[0] == "set" && w[1] == "-a":
		return prefixSetA, "", true
	case len(w) == 2 && w[0] == "set" && w[1] == "+a":
		return prefixSet, "", true
	case len(w) == 2 && (w[0] == "source" || w[0] == "."):
		rel, ok := relInside(w[1])
		if !ok {
			return 0, "", false
		}
		return prefixSource, rel, true
	case len(w) == 2 && progName(w[0]) == "cd":
		rel, ok := relInside(w[1])
		if !ok {
			return 0, "", false
		}
		return prefixCD, rel, true
	case len(w) == 3 && w[0] == "chmod" && (w[1] == "+x" || w[1] == "a+x"):
		rel, ok := relInside(w[2])
		if !ok {
			return 0, "", false
		}
		return prefixFile, rel, true
	case len(w) == 4 && w[0] == "xattr" && w[1] == "-d" && xattrName(w[2]):
		rel, ok := relInside(w[3])
		if !ok {
			return 0, "", false
		}
		return prefixFile, rel, true
	default:
		return 0, "", false
	}
}

func xattrName(s string) bool {
	if s == "" || strings.ContainsAny(s, "/$`") || !plainParams(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '.' && c != '_' && c != '-' && !isDigit(c) && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func launchFiles(words []string) ([]RepoFile, bool) {
	w := unwrap(words)
	if len(w) == 0 {
		return nil, false
	}
	if strings.Contains(w[0], subst) || badArgs(w) || !literalProgram(w[0]) || location(w[0]) != "" || isMCPDownload(w[0]) {
		return nil, false
	}
	name := progName(w[0])
	if strings.ContainsAny(w[0], `/\`) && !knownTool(name) {
		rel, ok := relInside(w[0])
		if !ok {
			return nil, false
		}
		return []RepoFile{{Path: rel}}, true
	}
	switch name {
	case "eval", "source", ".", "iex", "invoke-expression":
		return nil, false
	}
	if posixShells[name] || name == "cmd" || name == "powershell" || name == "pwsh" {
		return directScript(name, w[1:])
	}
	if inlineCode(name, w[1:]) {
		return nil, false
	}
	if script, ok := scriptOperand(name, w[1:]); ok {
		rel, ok := relInside(script)
		if !ok {
			return nil, false
		}
		return []RepoFile{{Path: rel}}, true
	}
	if interpreter(name) {
		return nil, false
	}
	return nil, true
}

func inlineCode(name string, args []string) bool {
	switch {
	case isPython(name):
		_, ok := pythonCode(args)
		return ok
	case name == "node":
		_, ok := nodeCode(args)
		return ok
	case name == "deno":
		return len(args) > 0 && args[0] == "eval"
	case name == "ruby" || name == "perl" || name == "php" || name == "bun" || name == "tsx" || name == "ts-node":
		for _, a := range args {
			switch a {
			case "-e", "-c", "-r", "--eval":
				return true
			}
			if strings.HasPrefix(a, "--eval=") {
				return true
			}
		}
	}
	return false
}

// knownTool is a launcher an absolute system path may name. Any other
// absolute program is a script outside the repository.
func knownTool(name string) bool {
	switch name {
	case "npx", "bunx", "uvx", "uv", "pipx", "node", "php", "ruby", "perl", "bun", "deno", "go", "tsx", "ts-node":
		return true
	default:
		return isPython(name)
	}
}

func interpreter(name string) bool {
	return isPython(name) || name == "node" || name == "ruby" || name == "perl" || name == "php" || name == "deno" || name == "bun" || name == "tsx" || name == "ts-node"
}

func gitTop(sub string) bool {
	f := strings.Fields(sub)
	return len(f) == 3 && f[0] == "git" && f[1] == "rev-parse" && f[2] == "--show-toplevel"
}

func topRel(word string) (string, bool) {
	rest, ok := strings.CutPrefix(word, subst+"/")
	if !ok || strings.Contains(rest, subst) {
		return "", false
	}
	return relInside(rest)
}

func pluginRel(w string) (string, bool) {
	var rest string
	switch {
	case strings.HasPrefix(w, "${CLAUDE_PLUGIN_ROOT}/"):
		rest = strings.TrimPrefix(w, "${CLAUDE_PLUGIN_ROOT}/")
	case strings.HasPrefix(w, "$CLAUDE_PLUGIN_ROOT/"):
		rest = strings.TrimPrefix(w, "$CLAUDE_PLUGIN_ROOT/")
	default:
		return "", false
	}
	return relInside(rest)
}

// relInside is a relative path that stays inside its base. A variable,
// a URL, a glob, or a climb into `..` is not.
func relInside(w string) (string, bool) {
	if w == "" || strings.Contains(w, subst) || strings.ContainsAny(w, "$%`*?[]{}~") || strings.Contains(w, "://") || strings.Contains(w, `\`) || strings.HasPrefix(w, "/") {
		return "", false
	}
	c := path.Clean(w)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

func dotenvBase(rel string) bool {
	base := path.Base(rel)
	if base == ".env" {
		return true
	}
	rest, ok := strings.CutPrefix(base, ".env.")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c != '.' && c != '_' && c != '-' && !isDigit(c) && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// plainParams allows $NAME and ${NAME}. A command substitution, a
// default expansion, or any other parameter operator does not.
func plainParams(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		if i+1 >= len(s) || s[i+1] == '(' {
			return false
		}
		if s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end <= 0 || !ident(s[i+2:i+2+end]) {
				return false
			}
			i += 2 + end
			continue
		}
		if !identStart(s[i+1]) {
			return false
		}
		j := i + 2
		for j < len(s) && identCont(s[j]) {
			j++
		}
		i = j - 1
	}
	return true
}

func ident(s string) bool {
	if s == "" || !identStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !identCont(s[i]) {
			return false
		}
	}
	return true
}

func identStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func identCont(c byte) bool {
	return identStart(c) || isDigit(c)
}

func httpURL(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "http://") || strings.Contains(l, "https://") || strings.Contains(l, "ftp://")
}

// psScript is powershell -File or pwsh -File of one relative path.
// -Command and -EncodedCommand stay findings.
func psScript(args []string) ([]RepoFile, bool) {
	file, ok := psFileArg(args)
	if !ok || badArgs(args) {
		return nil, false
	}
	rel, ok := relInside(file)
	if !ok {
		return nil, false
	}
	return []RepoFile{{Path: rel}}, true
}

func badArgs(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, subst) || strings.Contains(a, "`") || strings.Contains(a, "git+") || httpURL(a) || !plainParams(a) {
			return true
		}
		low := strings.ToLower(a)
		for _, p := range []string{"github:", "gist:", "gitlab:", "bitbucket:", "npm:", "jsr:"} {
			if strings.Contains(low, p) {
				return true
			}
		}
	}
	return false
}

func hasOp(toks []token) bool {
	for _, t := range toks {
		if t.op != "" {
			return true
		}
	}
	return false
}

func dedupe(files []RepoFile) []RepoFile {
	var out []RepoFile
	for _, f := range files {
		seen := false
		for _, have := range out {
			if have == f {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, f)
		}
	}
	return out
}
