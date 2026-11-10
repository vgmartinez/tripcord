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
//
// Dotenv is one of .env, .env.local, or .env.claude. The caller keeps
// the wrapper only when a file that is present is a strict dotenv
// (see scriptcheck). DotenvOptional is set when `set -a` sourced it:
// the file may be absent. Without that flag a missing dotenv is a
// finding, which is `. ./.env && exec npx` with no committed .env.
type RepoFile struct {
	Path           string
	Beside         bool
	FromRoot       bool
	Dotenv         bool
	DotenvOptional bool
}

// RepoWrapper reports whether argv is a shell wrapper around the
// repository's own files. ok is false for a pipe, a fetch, an inline
// interpreter, a remote script, or a path that leaves the repository.
// The files it returns have to exist in the scanned tree before the
// wrapper is quiet, except a dotenv sourced under `set -a`. That file
// is marked Dotenv and DotenvOptional: absence is fine, and a file
// that is present has to be a strict dotenv. The same content check
// applies to `. ./.env && exec npx` when the file is in the tree; a
// missing file there is still a finding. Only .env, .env.local, and
// .env.claude are dotenvs.
func RepoWrapper(argv []string) ([]RepoFile, bool) {
	if len(argv) == 0 || argvHasOpaque(argv) {
		return nil, false
	}
	if len(argv) == 1 {
		if words, ok := shellWords(argv[0]); ok {
			return RepoWrapper(words)
		}
	}
	w, ok := repoUnwrap(argv)
	if !ok || len(w) == 0 || mentionsDirChange(w) {
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
	w, ok := repoUnwrap(cmds[0].words)
	if !ok || len(w) == 0 {
		return nil, false
	}
	rel, ok := topRel(w[0])
	if !ok || badArgs(w[1:]) {
		return nil, false
	}
	return []RepoFile{{Path: rel, FromRoot: true}}, true
}

// gitAssignChain is the one cd that is followed: a repository-root cd
// and then exec bun run of a relative file. It is quiet only when
// every one of these holds.
//
// The git command is exactly V=$(git rev-parse --show-toplevel) or
// cd "$(git rev-parse --show-toplevel)". No other git arguments, no
// git -C, --git-dir, or --work-tree, and no environment prefix
// (GIT_DIR, GIT_WORK_TREE, any GIT_*, or any other VAR=) on that line
// or in an earlier command. The cd uses that same variable,
// double-quoted, and the variable is not reassigned after the
// assignment. Between that cd and the exec there is no other cd,
// pushd, -C, --chdir, or --cwd. || exit 1 after the assignment or the
// cd is the same form. Any other variant is not.
func gitAssignChain(payload string) ([]RepoFile, bool) {
	toks, subs := lex(payload, false)
	if len(subs) != 1 || !gitTop(subs[0]) {
		return nil, false
	}
	cmds := split(toks)
	for _, c := range cmds {
		if c.pipeIn || c.depth != 0 {
			return nil, false
		}
	}
	gitAt := -1
	name := ""
	for i, c := range cmds {
		if !cmdHasSubst(c) {
			continue
		}
		if gitAt >= 0 {
			return nil, false
		}
		gitAt = i
		switch {
		case len(c.words) == 1:
			n, ok := assignVar(c.words[0])
			if !ok {
				return nil, false
			}
			name = n
		case len(c.words) == 2 && c.words[0] == "cd" && c.words[1] == subst:
			if !strings.Contains(payload, `cd "$(git rev-parse --show-toplevel)"`) {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	if gitAt < 0 || envBefore(cmds[:gitAt]) {
		return nil, false
	}
	cdAt := gitAt
	if name != "" {
		next, ok := skipExit(cmds, gitAt)
		if !ok || next >= len(cmds) || !quotedVarCD(payload, cmds[next], name) {
			return nil, false
		}
		cdAt = next
	}
	execAt, ok := skipExit(cmds, cdAt)
	if !ok || execAt != len(cmds)-1 || cmds[execAt].sep != "" {
		return nil, false
	}
	if name != "" {
		for _, c := range cmds[gitAt+1:] {
			if assignsName(c, name) {
				return nil, false
			}
		}
	}
	for _, c := range cmds[cdAt+1:] {
		if dirShift(c.words) {
			return nil, false
		}
	}
	w, ok := repoUnwrap(cmds[execAt].words)
	if !ok || dirShift(w) {
		return nil, false
	}
	return bunRun(w)
}

func cmdHasSubst(c command) bool {
	for _, w := range c.words {
		if strings.Contains(w, subst) {
			return true
		}
	}
	return false
}

func assignVar(word string) (string, bool) {
	name, ok := strings.CutSuffix(word, "="+subst)
	if !ok || !shellIdent(name) {
		return "", false
	}
	return name, true
}

func shellIdent(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

func quotedVarCD(payload string, c command, name string) bool {
	if len(c.words) != 2 || c.words[0] != "cd" {
		return false
	}
	switch c.words[1] {
	case "$" + name:
		return strings.Contains(payload, `cd "$`+name+`"`)
	case "${" + name + "}":
		return strings.Contains(payload, `cd "${`+name+`}"`)
	default:
		return false
	}
}

func assignsName(c command, name string) bool {
	prefix := name + "="
	for _, w := range c.words {
		if isAssignment(w) && strings.HasPrefix(w, prefix) {
			return true
		}
	}
	return false
}

// envBefore reports an export or assignment before the git command.
// The V= substitution itself is not in this prefix.
func envBefore(cmds []command) bool {
	for _, c := range cmds {
		if len(c.words) > 0 && (c.words[0] == "export" || progName(c.words[0]) == "env") {
			return true
		}
		for _, w := range c.words {
			if isAssignment(w) || strings.HasPrefix(w, "GIT_") {
				return true
			}
		}
	}
	return false
}

// skipExit moves past an optional "|| exit 1" onto the next command.
func skipExit(cmds []command, i int) (int, bool) {
	if i < 0 || i >= len(cmds) {
		return 0, false
	}
	sep := cmds[i].sep
	i++
	if sep == "||" {
		if i >= len(cmds) || !exitOne(cmds[i].words) {
			return 0, false
		}
		sep = cmds[i].sep
		i++
	}
	if sep != ";" && sep != "" {
		return 0, false
	}
	return i, true
}

// dirShift reports a directory change after the repository-root cd.
func dirShift(words []string) bool {
	for _, w := range words {
		if progName(w) == "cd" || progName(w) == "pushd" {
			return true
		}
		switch w {
		case "-C", "--chdir", "--cwd":
			return true
		}
		if strings.HasPrefix(w, "--chdir=") || strings.HasPrefix(w, "--cwd=") {
			return true
		}
	}
	return false
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
	prefixFile
)

// envLoader is `set -a && source .env && npx -y pkg` and the same
// commands joined with `;` or a newline. Every command but the last is
// `set -a`, `set +a`, `source` or `.` of one relative path, `chmod +x`
// of one relative path, or `xattr -d` of one relative path. `cd` and
// `pushd` are rejected: the following relative script would be resolved
// against the config directory, not the directory the shell enters.
// The last command is one known launcher, or a relative file.
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
	var sources, must []string
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
		if dotenvBase(rel) {
			files = append(files, RepoFile{Path: rel, Dotenv: true, DotenvOptional: sawSetA})
			continue
		}
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
	w, ok := repoUnwrap(words)
	if !ok {
		return 0, "", false
	}
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
	case len(w) >= 1 && (progName(w[0]) == "cd" || progName(w[0]) == "pushd"):
		// A relative script after cd or pushd is not the file next to
		// the config. Reject instead of resolving it.
		return 0, "", false
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
	w, ok := repoUnwrap(words)
	if !ok || len(w) == 0 || mentionsDirChange(w) {
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
	// A package runner may be the server. Any other bare program,
	// including rm, notes-mcp, or evil-mcp, stays a finding.
	if noFileLauncher(name, w[1:]) {
		return nil, true
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
	return nil, false
}

// noFileLauncher is the closed list of package runners that name no
// file in the tree. The words are the arguments after the program.
func noFileLauncher(name string, args []string) bool {
	switch name {
	case "npx", "bunx", "uvx", "uv", "pipx":
		return true
	case "pnpm", "yarn":
		return len(args) > 0 && args[0] == "dlx"
	case "npm":
		return len(args) > 0 && (args[0] == "exec" || args[0] == "dlx")
	case "bun":
		return len(args) > 0 && args[0] == "x"
	default:
		return false
	}
}

// repoUnwrap drops assignments and the wrappers unwrap drops, and fails
// closed when that would hide a different command. A `$` in program
// position is not rewritten with commandDefault, so ${X:-rm} stays a
// finding. env -C, sudo -D or --chdir, and any --cwd or --chdir option
// on those wrappers fail closed too: the directory change is not a
// path inside the tree.
func repoUnwrap(w []string) ([]string, bool) {
	for len(w) > 0 {
		if strings.Contains(w[0], "$") {
			return nil, false
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
			next, ok := dropWrapperOpts(w[1:], sudoValues)
			if !ok {
				return nil, false
			}
			w = next
		case "env":
			next, ok := dropWrapperOpts(w[1:], envValues)
			if !ok {
				return nil, false
			}
			w = next
		case "exec":
			next, ok := dropWrapperOpts(w[1:], map[string]bool{"-a": true})
			if !ok {
				return nil, false
			}
			w = next
		case "command":
			if len(w) > 1 && (w[1] == "-v" || w[1] == "-V") {
				return nil, false
			}
			next, ok := dropWrapperOpts(w[1:], nil)
			if !ok {
				return nil, false
			}
			w = next
		default:
			return w, true
		}
	}
	return w, true
}

// dropWrapperOpts drops leading options the way skipOptions does, and
// rejects a directory change. -C and -D are directory changes when the
// caller lists them as options that take a value (env -C, sudo -D).
func dropWrapperOpts(args []string, valued map[string]bool) ([]string, bool) {
	for len(args) > 0 {
		a := args[0]
		if a == "--" {
			return args[1:], true
		}
		if len(a) < 2 || a[0] != '-' {
			return args, true
		}
		if dirOpt(a, valued) {
			return nil, false
		}
		args = args[1:]
		if valued[a] && len(args) > 0 {
			args = args[1:]
		}
	}
	return args, true
}

func dirOpt(a string, valued map[string]bool) bool {
	switch a {
	case "--chdir", "--cwd":
		return true
	case "-C", "-D":
		return valued[a]
	default:
		return strings.HasPrefix(a, "--chdir=") || strings.HasPrefix(a, "--cwd=")
	}
}

func mentionsDirChange(words []string) bool {
	for _, w := range words {
		if w == "--chdir" || w == "--cwd" || strings.HasPrefix(w, "--chdir=") || strings.HasPrefix(w, "--cwd=") {
			return true
		}
	}
	return false
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
	if strings.ContainsAny(sub, "=\n;&|<>`$") || strings.Contains(sub, "--git-dir") || strings.Contains(sub, "--work-tree") {
		return false
	}
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

// dotenvBase is the closed list of dotenv names. Any other sourced
// path is an ordinary file: it has to be in the tree, and its bytes
// are not read.
func dotenvBase(rel string) bool {
	switch path.Base(rel) {
	case ".env", ".env.local", ".env.claude":
		return true
	default:
		return false
	}
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
