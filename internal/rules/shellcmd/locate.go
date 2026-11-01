package shellcmd

import (
	"path"
	"strings"
)

// Locations of what a command runs, in the order Locate reports them.
const (
	// Network is a program or script named by a non-loopback http,
	// https, or ftp URL, or on a UNC share (\\host\share, //host/share).
	Network = "network"
	// Home is under the home directory: ~, $HOME, %USERPROFILE%,
	// $env:APPDATA, an XDG_*_HOME directory, /home/<user>, /Users/<user>,
	// /root, or C:\Users\<user>.
	Home = "home"
	// Temp is a temporary directory: /tmp, /var/tmp, /dev/shm, macOS
	// /private/tmp and /var/folders, $TMPDIR, %TEMP%, $RUNNER_TEMP, or
	// C:\Windows\Temp.
	Temp = "temp"
	// Absolute is any other absolute path, except a program without a
	// script extension under a system directory (/usr, /bin, /opt,
	// C:\Program Files, ...): /usr/local/bin/tripcord is a binary, while
	// /opt/hooks/check.sh is a script outside the repository.
	Absolute = "absolute"
	// Parent climbs above the project directory: ../x.sh, or
	// $CLAUDE_PROJECT_DIR/../x.sh.
	Parent = "parent"
)

// Located is what Locate found and how much it read.
type Located struct {
	Locations []string
	// Work is the bytes read, as in Result.
	Work int
}

// Locate reports where the programs and scripts a command line runs
// live, each class at most once. It reads the line as Analyze does,
// with the same unwrapping, so bash -c 'sh /tmp/x.sh' is a Temp. In each
// simple command it reads the program and, for an interpreter, the
// script it is given: the first operand of sh, bash, python, node, ruby,
// perl, php, bun, tsx, ts-node, deno run, source, and ., and the -File
// of powershell and pwsh. Arguments are not read: echo /tmp/x and
// cat ~/.ssh/config run no program there.
//
// A project variable is the project directory: CLAUDE_PROJECT_DIR,
// CLAUDE_PLUGIN_ROOT, GEMINI_PROJECT_DIR, CURSOR_PROJECT_DIR, and PWD,
// written $NAME, ${NAME}, %NAME%, or $env:NAME. Any other variable, a
// substitution, and a bare program name found on PATH have no location.
func Locate(line string) Located {
	s := scanner{locate: true}
	s.line(line, 0, false)
	if strings.Contains(line, "`") {
		s.line(line, 0, true)
	}
	return Located{Locations: s.locations(), Work: s.work}
}

// LocateArgv is Locate for an argument vector that no shell splits.
func LocateArgv(argv []string) Located {
	s := scanner{locate: true}
	for _, a := range argv {
		s.work += len(a) + 1
	}
	s.command(argv, 0, false)
	return Located{Locations: s.locations(), Work: s.work}
}

// ProjectScripts returns the files inside the project that a command
// line runs, as clean slash-separated paths relative to the project
// directory: a program written as a path (./x.sh, scripts/x,
// "$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh) and the script an
// interpreter is given (bash x.sh, node .cursor/hooks/x.mjs). A bare
// operand without a directory or an extension (node server) is not
// included, because an interpreter may resolve it to another file.
//
// It is conservative, for a check that a script exists: a line with a
// backslash is not read (POSIX and PowerShell split it differently),
// nor is anything after cd, pushd, or Set-Location, a path with a
// variable other than a project variable, or a glob. CLAUDE_PLUGIN_ROOT
// is not the project directory here.
func ProjectScripts(line string) []string {
	if strings.Contains(line, `\`) {
		return nil
	}
	s := scanner{locate: true, collect: true}
	s.line(line, 0, false)
	return s.scripts
}

// ProjectScriptsArgv is ProjectScripts for an argument vector that no
// shell splits.
func ProjectScriptsArgv(argv []string) []string {
	for _, a := range argv {
		if strings.Contains(a, `\`) {
			return nil
		}
	}
	s := scanner{locate: true, collect: true}
	s.command(argv, 0, false)
	return s.scripts
}

var changesDir = map[string]bool{"cd": true, "pushd": true, "chdir": true, "set-location": true, "sl": true, "push-location": true}

func (s *scanner) collectScripts(program, name string, args []string) {
	if changesDir[name] {
		s.moved = true
	}
	if s.moved {
		return
	}
	if p, ok := projectPath(program, true); ok {
		s.addScript(p)
	}
	if script, ok := scriptOperand(name, args); ok {
		if p, ok := projectPath(script, false); ok {
			s.addScript(p)
		}
	}
}

func (s *scanner) addScript(p string) {
	for _, have := range s.scripts {
		if have == p {
			return
		}
	}
	s.scripts = append(s.scripts, p)
}

// projectPath returns w as a path relative to the project directory, if
// it names one inside it.
func projectPath(w string, program bool) (string, bool) {
	if w == "" || strings.Contains(w, subst) || strings.Contains(w, "://") {
		return "", false
	}
	p := w
	if name, rest, ok := leadingVar(p); ok {
		if !projectVars[name] || name == "CLAUDE_PLUGIN_ROOT" {
			return "", false
		}
		p = "." + rest
	}
	if strings.ContainsAny(p, "$%`*?[]{}~:") || strings.HasPrefix(p, "/") {
		return "", false
	}
	hasDir := strings.Contains(p, "/")
	if program && !hasDir {
		return "", false
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	if !hasDir && path.Ext(c) == "" {
		return "", false
	}
	return c, true
}

var locationOrder = []string{Network, Home, Temp, Absolute, Parent}

func (s *scanner) locations() []string {
	out := []string{}
	for _, l := range locationOrder {
		if s.found[l] {
			out = append(out, l)
		}
	}
	return out
}

// runs records where the program of one unwrapped simple command, and
// the script an interpreter is given, live.
func (s *scanner) runs(program, name string, args []string) {
	s.place(program)
	if script, ok := scriptOperand(name, args); ok {
		s.place(script)
	}
}

func (s *scanner) place(w string) {
	l := location(w)
	if l == "" {
		return
	}
	if s.found == nil {
		s.found = map[string]bool{}
	}
	s.found[l] = true
}

// scriptOperand returns the script file an interpreter runs. Inline code
// (-c, -e, eval) and a module (-m) are not a file.
func scriptOperand(name string, args []string) (string, bool) {
	switch {
	case posixShells[name]:
		if _, ok := shellPayload(name, args); ok {
			return "", false
		}
		return firstOperand(args, func(a string) bool {
			return a == "-o" || a == "-O" || a == "--rcfile" || a == "--init-file" || (name == "fish" && a == "-C")
		}, "-s")
	case name == "powershell" || name == "pwsh":
		return psFileArg(args)
	case isPython(name):
		if _, ok := pythonCode(args); ok {
			return "", false
		}
		return firstOperand(args, func(a string) bool { return a == "-W" || a == "-X" }, "-m")
	case name == "node":
		if _, ok := nodeCode(args); ok {
			return "", false
		}
		return firstOperand(args, func(a string) bool { return a == "-r" || a == "--require" }, "-p", "--print")
	case name == "ruby" || name == "perl":
		return firstOperand(args, func(a string) bool { return a == "-I" || a == "-r" }, "-e", "-E")
	case name == "php":
		return firstOperand(args, func(a string) bool { return a == "-d" || a == "-c" }, "-r")
	case name == "bun":
		if len(args) > 0 && args[0] == "run" {
			args = args[1:]
		}
		return firstOperand(args, nil, "-e", "--eval")
	case name == "deno":
		if len(args) == 0 || args[0] != "run" {
			return "", false
		}
		return firstOperand(args[1:], nil)
	case name == "tsx" || name == "ts-node":
		return firstOperand(args, nil, "-e", "--eval")
	case name == "source" || name == ".":
		if len(args) > 0 {
			return args[0], true
		}
	}
	return "", false
}

// firstOperand returns the first argument that is not an option. valued
// reports an option that takes the next argument; an option in inline
// means there is no script operand.
func firstOperand(args []string, valued func(string) bool, inline ...string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case len(a) < 2 || (a[0] != '-' && a[0] != '+'):
			return a, true
		}
		for _, f := range inline {
			if a == f {
				return "", false
			}
		}
		if valued != nil && valued(a) {
			i++
		}
	}
	return "", false
}

// psFileArg returns the -File value of a powershell or pwsh command line.
func psFileArg(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			return "", false
		}
		name, value, inline := strings.Cut(strings.TrimLeft(a, "-"), ":")
		switch psParam(strings.ToLower(name)) {
		case psFile:
			if inline {
				return value, true
			}
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case psCommand, psEncoded:
			return "", false
		case psValue:
			if !inline {
				i++
			}
		}
	}
	return "", false
}

var (
	projectVars = map[string]bool{
		"CLAUDE_PROJECT_DIR": true, "CLAUDE_PLUGIN_ROOT": true, "GEMINI_PROJECT_DIR": true,
		"CURSOR_PROJECT_DIR": true, "PWD": true,
	}
	homeVars = map[string]bool{
		"HOME": true, "USERPROFILE": true, "HOMEPATH": true, "APPDATA": true, "LOCALAPPDATA": true,
		"XDG_CONFIG_HOME": true, "XDG_DATA_HOME": true, "XDG_CACHE_HOME": true, "XDG_STATE_HOME": true,
	}
	tempVars = map[string]bool{"TMPDIR": true, "TEMP": true, "TMP": true, "RUNNER_TEMP": true}

	tempDirs   = []string{"/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/private/var/folders", "/var/folders", "/windows/temp"}
	systemDirs = []string{
		"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/nix", "/snap", "/etc",
		"/applications", "/system", "/library",
		"/windows", "/program files", "/program files (x86)", "/programdata",
	}
	scriptExts = []string{".sh", ".bash", ".zsh", ".fish", ".ksh", ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".rb", ".pl", ".php", ".lua", ".ps1", ".psm1", ".cmd", ".bat"}
)

// location classifies one program or script word.
func location(w string) string {
	if w == "" || strings.Contains(w, subst) {
		return ""
	}
	if i := strings.Index(w, "://"); i > 0 {
		if classify(w, false) == remote {
			return Network
		}
		return ""
	}
	p := strings.ReplaceAll(w, `\`, "/")
	if strings.HasPrefix(p, "//") {
		return Network
	}
	if name, rest, ok := leadingVar(p); ok {
		switch {
		case projectVars[name]:
			p = "." + rest
		case homeVars[name]:
			return Home
		case tempVars[name]:
			return Temp
		default:
			return ""
		}
	}
	if strings.HasPrefix(p, "~") {
		return Home
	}
	if len(p) >= 3 && p[1] == ':' && p[2] == '/' && isLetter(p[0]) {
		p = p[2:]
	}
	if strings.HasPrefix(p, "/") {
		return absolute(path.Clean(p))
	}
	if c := path.Clean(p); c == ".." || strings.HasPrefix(c, "../") {
		return Parent
	}
	return ""
}

// absolute classifies a cleaned absolute path.
func absolute(p string) string {
	l := strings.ToLower(p)
	switch {
	case underAny(l, tempDirs), underUserDir(l, "/users/", "/appdata/local/temp"):
		return Temp
	case underUserDir(l, "/home/", ""), underUserDir(l, "/users/", ""), under(l, "/root"):
		return Home
	case underAny(l, systemDirs) && !hasAnySuffix(l, scriptExts):
		return ""
	}
	return Absolute
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if under(p, d) {
			return true
		}
	}
	return false
}

// underUserDir reports a path below <root><user><sub>, such as
// /users/alice/appdata/local/temp/x.ps1. A bare /home or /users is not.
func underUserDir(p, root, sub string) bool {
	rest, ok := strings.CutPrefix(p, root)
	if !ok {
		return false
	}
	user, tail, _ := strings.Cut(rest, "/")
	if user == "" {
		return false
	}
	return sub == "" || under("/"+tail, sub)
}

// leadingVar splits a leading $NAME, ${NAME}, %NAME%, or $env:NAME from
// p. The name is upper-cased: Windows variable names ignore case, and no
// two names this package knows differ only in case.
func leadingVar(p string) (name, rest string, ok bool) {
	var n int
	switch {
	case strings.HasPrefix(p, "${"):
		end := strings.IndexByte(p, '}')
		if end < 0 {
			return "", "", false
		}
		name, rest = p[2:end], p[end+1:]
	case strings.HasPrefix(p, "%"):
		end := strings.IndexByte(p[1:], '%')
		if end < 0 {
			return "", "", false
		}
		name, rest = p[1:end+1], p[end+2:]
	case strings.HasPrefix(p, "$"):
		body := p[1:]
		if len(body) > 4 && strings.EqualFold(body[:4], "env:") {
			body = body[4:]
		}
		for n < len(body) && (body[n] == '_' || isLetter(body[n]) || isDigit(body[n])) {
			n++
		}
		name, rest = body[:n], body[n:]
	default:
		return "", "", false
	}
	if name == "" || (rest != "" && rest[0] != '/') {
		return "", "", false
	}
	return strings.ToUpper(name), rest, true
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func hasAnySuffix(s string, suffixes []string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}
