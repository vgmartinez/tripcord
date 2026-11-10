package scriptcheck

import (
	"os"
	"path/filepath"
	"strings"
)

// dotenvMax is the largest committed dotenv a set -a loader may quiet.
// Anything larger is treated as not a dotenv, so TC-CFG-003 stays matched.
const dotenvMax = 64 << 10

// dotenvAllows reports whether a sourced dotenv may leave the wrapper
// quiet. optional is the set -a case: a file that is not in the tree
// may, because it is the user's local .env. Without optional, a missing
// file is a finding. A file that is present may only when it is a
// regular file of at most dotenvMax bytes, it resolves inside root, and
// dotenvText accepts it. A symlink that leaves the tree, a file that
// cannot be read, and a file larger than dotenvMax do not.
func dotenvAllows(root, rel string, optional bool) bool {
	cleaned := filepath.Clean(filepath.FromSlash(rel))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || filepath.IsAbs(cleaned) {
		return false
	}
	abs := filepath.Join(root, cleaned)
	if _, err := os.Lstat(abs); err != nil {
		return optional && os.IsNotExist(err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || !insideRoot(root, resolved) {
		return false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() > dotenvMax {
		return false
	}
	data, err := os.ReadFile(resolved)
	if err != nil || int64(len(data)) > dotenvMax {
		return false
	}
	return dotenvText(data)
}

// dotenvText reports whether data is a strict dotenv: every line is
// blank, a comment, or KEY=VALUE. KEY matches [A-Za-z_][A-Za-z0-9_]*
// and may be prefixed by "export ". VALUE must not contain $, a
// backtick, ;, &, |, <, >, a newline inside quotes, or a trailing
// backslash.
func dotenvText(data []byte) bool {
	if int64(len(data)) > dotenvMax {
		return false
	}
	open := quoteNone
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		line := data[start:i]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		next, ok := dotenvLine(line, open)
		if !ok {
			return false
		}
		open = next
		start = i + 1
	}
	return true
}

type quoteState int

const (
	quoteNone quoteState = iota
	quoteSingle
	quoteDouble
)

func dotenvLine(line []byte, open quoteState) (quoteState, bool) {
	if open != quoteNone {
		return quoteNone, false
	}
	if strings.TrimSpace(string(line)) == "" {
		return quoteNone, true
	}
	body := strings.TrimLeft(string(line), " \t")
	if strings.HasPrefix(body, "#") {
		return quoteNone, true
	}
	value, ok := dotenvValue(string(line))
	if !ok || strings.HasSuffix(value, `\`) {
		return quoteNone, false
	}
	return scanQuotes(value)
}

func dotenvValue(line string) (string, bool) {
	rest := line
	if strings.HasPrefix(rest, "export ") {
		rest = strings.TrimLeft(rest[len("export "):], " ")
	}
	if rest == "" || !dotenvIdentStart(rest[0]) {
		return "", false
	}
	i := 1
	for i < len(rest) && dotenvIdentCont(rest[i]) {
		i++
	}
	if i >= len(rest) || rest[i] != '=' {
		return "", false
	}
	return rest[i+1:], true
}

func dotenvIdentStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func dotenvIdentCont(b byte) bool {
	return dotenvIdentStart(b) || (b >= '0' && b <= '9')
}

func scanQuotes(value string) (quoteState, bool) {
	state := quoteNone
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '$', '`', ';', '&', '|', '<', '>', '\n', '\r':
			return quoteNone, false
		case '\'':
			if state == quoteDouble {
				continue
			}
			if state == quoteSingle {
				state = quoteNone
			} else {
				state = quoteSingle
			}
		case '"':
			if state == quoteSingle {
				continue
			}
			if state == quoteDouble {
				state = quoteNone
			} else {
				state = quoteDouble
			}
		}
	}
	return state, true
}
