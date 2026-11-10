package output

import (
	"regexp"
	"strings"
)

// Two credential shapes carry no flag or assignment name for the other
// passes to key on: the netrc grammar ("machine h login u password X")
// and a "-p X" next to a user name. Both are redacted for every command,
// not only for known tools: a leaked password is worse than a hidden
// port, so a rare false redaction is the accepted cost.

// passwordWordHead matches the word "password" or "passwd" at a shell
// word start, with only blanks or line continuations after it on the
// same line. Groups: leading byte, the word, the gap. A "--password" flag
// has "-" before it, and "db_password" a name byte, so neither matches;
// "password: x" and "password = x" have ":" or "=" after the gap and are
// read as assignments by RedactAssignments.
var passwordWordHead = regexp.MustCompile("(?i)(^|[\\s;&|(`\"'])(passw(?:or)?d)((?:[ \\t]|" + lineContinuation + ")+)")

// passwordWordValue reads the value after passwordWordHead, anchored. Like
// secretFlagSpaceValue it never starts with "-" (the next flag), and it
// never starts with "=" or ":" either, which belong to an assignment.
var passwordWordValue = regexp.MustCompile(`^(?:` + quotedValue + `|[^-=:\s;&|"'\n)` + "`" + `]` + unquotedCommandValue + `*)`)

// redactPasswordWords replaces the word after each "password"/"passwd"
// word in command and returns the raw values it removed. A match inside
// the argument of a literalTextFlags flag (git commit -m 'fix password
// handling') is left alone, as are placeholders.
func redactPasswordWords(command string) (string, []string) {
	if !strings.Contains(asciiLower(command), "passw") {
		return command, nil
	}
	var removed []string
	var b strings.Builder
	var spans literalSpans
	spansFound := false
	quotes := indexEscapedQuotes(command)
	pos, written := 0, 0
	for pos < len(command) {
		m := passwordWordHead.FindStringSubmatchIndex(command[pos:])
		if m == nil {
			break
		}
		wordStart, sepEnd := pos+m[4], pos+m[1]
		pos = sepEnd
		var body string
		if alt, ok := quotes.at(command, sepEnd); ok {
			body = alt
		} else {
			loc := passwordWordValue.FindStringIndex(command[sepEnd:])
			if loc == nil {
				continue
			}
			body = command[sepEnd : sepEnd+loc[1]]
		}
		if placeholderSecret(body) {
			continue
		}
		if !spansFound {
			spans, spansFound = findLiteralSpans(command), true
		}
		if spans.contains(wordStart) {
			continue
		}
		removed = append(removed, unquote(body))
		b.WriteString(command[written:sepEnd])
		b.WriteString(quoteLike(body, redactedMarker))
		pos += len(body)
		written = pos
	}
	b.WriteString(command[written:])
	return b.String(), removed
}

// userContextFlags are the words that make a "-p X" in the same command
// a login: a user name flag, or the login subcommand.
var userContextFlags = map[string]bool{
	"-u": true, "-U": true, "-l": true, "--user": true, "--username": true, "--login": true, "login": true,
}

var userContextFlagPrefixes = []string{"--user=", "--username=", "--login="}

// portMapping is a "-p" value that publishes a port ("8080:80",
// "127.0.0.1:80:80/tcp"), not a password.
var portMapping = regexp.MustCompile(`^(?:[0-9a-fA-F.:\[\]]*:)?[0-9]+(?:-[0-9]+)?(?::[0-9]+(?:-[0-9]+)?)?(?:/(?:tcp|udp|sctp))?$`)

func hasUserContext(words []string) bool {
	for _, w := range words {
		w = strings.Trim(w, `"'`)
		if userContextFlags[w] {
			return true
		}
		for _, prefix := range userContextFlagPrefixes {
			if strings.HasPrefix(w, prefix) {
				return true
			}
		}
	}
	return false
}

// passwordShortValue reports whether value after "-p" is a secret: not a
// flag, a placeholder, or, when keepPort is set, a port mapping. keepPort
// is only for docker run and podman run (and their container run forms).
// Any other command that names a user redacts the value even when it
// contains ":", so "ssh -l alice -p deadbeef:22" does not pass as a port.
func passwordShortValue(value string, keepPort bool) bool {
	inner := unquote(value)
	if keepPort && strings.Contains(inner, ":") && portMapping.MatchString(inner) {
		return false
	}
	return inner != "" && !strings.HasPrefix(inner, "-") && !placeholderSecret(inner)
}

// passwordArgValue is passwordShortValue for an argv element. The element
// after a "password" word is a secret even when it has a port mapping's
// shape.
func passwordArgValue(value string, afterWord, keepPort bool) bool {
	if !afterWord {
		return passwordShortValue(value, keepPort)
	}
	inner := unquote(value)
	return inner != "" && !strings.HasPrefix(inner, "-") && !placeholderSecret(inner)
}

// isContainerRun reports whether words invoke docker run or podman run,
// including "docker container run" and "podman container run". A wrapper
// or a path (sudo docker, /usr/bin/podman) still counts. docker login
// does not.
func isContainerRun(words []string) bool {
	for i := 0; i < len(words); i++ {
		prev := ""
		if i > 0 {
			prev = words[i-1]
		}
		name := toolWordName(prev, words[i])
		if name != "docker" && name != "podman" {
			continue
		}
		if containerRunAfter(words[i+1:]) {
			return true
		}
	}
	return false
}

// containerRunAfter reports whether the words after the tool name are a
// run subcommand. Global options may sit between the tool and run
// ("docker -H host run"); a different subcommand ("login", "build") does
// not.
func containerRunAfter(words []string) bool {
	for i := 0; i < len(words); {
		w := strings.ToLower(strings.Trim(words[i], `"'`))
		switch {
		case w == "run":
			return true
		case w == "container":
			return containerThenRun(words[i+1:])
		case optionTakesValue(w):
			i += 2
		case strings.HasPrefix(w, "-"):
			i++
		default:
			return false
		}
	}
	return false
}

func containerThenRun(words []string) bool {
	for i := 0; i < len(words); {
		w := strings.ToLower(strings.Trim(words[i], `"'`))
		switch {
		case w == "run":
			return true
		case optionTakesValue(w):
			i += 2
		case strings.HasPrefix(w, "-"):
			i++
		default:
			return false
		}
	}
	return false
}

// optionTakesValue reports whether flag is a docker or podman global
// option that takes the next word as its argument, so that word is not
// the subcommand. A flag with its value glued by "=" does not.
func optionTakesValue(flag string) bool {
	switch flag {
	case "-h", "--host", "-c", "--context", "--config", "-l", "--log-level":
		return true
	default:
		return false
	}
}

var shortPasswordFlag = regexp.MustCompile(`(^|\s)(-p)((?:\s|` + lineContinuation + `)+)`)

// redactUserContextPassword redacts the value of "-p" in a command
// segment that also names a user (-u, -U, -l, --user, --username,
// --login, or a login subcommand): "docker login -u bot -p X", "regcli
// --user bot -p X", "ssh -l alice -p deadbeef:22". Without a user next
// to it, -p is left alone (mkdir -p, cp -p, ssh -p 22, docker run -p
// 80:80). A value containing ":" is still kept when the command is
// docker run or podman run, including container run, because that -p
// publishes a port. It returns the raw values it removed.
func redactUserContextPassword(segment string) (string, []string) {
	if !strings.Contains(segment, "-p") {
		return segment, nil
	}
	var words []string
	for _, w := range splitWords(segment) {
		words = append(words, w.text)
	}
	if !hasUserContext(words) {
		return segment, nil
	}
	keepPort := isContainerRun(words)
	var removed []string
	var b strings.Builder
	quotes := indexEscapedQuotes(segment)
	pos, written := 0, 0
	for pos < len(segment) {
		m := shortPasswordFlag.FindStringSubmatchIndex(segment[pos:])
		if m == nil {
			break
		}
		sepEnd := pos + m[1]
		pos = sepEnd
		var body string
		if alt, ok := quotes.at(segment, sepEnd); ok {
			body = alt
		} else {
			loc := secretFlagSpaceValue.FindStringIndex(segment[sepEnd:])
			if loc == nil {
				continue
			}
			body = segment[sepEnd : sepEnd+loc[1]]
		}
		if !passwordShortValue(body, keepPort) {
			continue
		}
		removed = append(removed, unquote(body))
		b.WriteString(segment[written:sepEnd])
		b.WriteString(quoteLike(body, redactedMarker))
		pos += len(body)
		written = pos
	}
	b.WriteString(segment[written:])
	return b.String(), removed
}

// redactArgvPasswordWords is redactPasswordWords and
// redactUserContextPassword for an argv array: the secret is the element
// after an element that is "password"/"passwd", or after "-p" when some
// element names a user. It returns a redacted copy and the raw values it
// removed.
func redactArgvPasswordWords(argv []string) ([]string, []string) {
	out := append([]string(nil), argv...)
	var removed []string
	userContext := hasUserContext(argv)
	keepPort := isContainerRun(argv)
	for i := 0; i+1 < len(argv); i++ {
		word := strings.ToLower(strings.Trim(argv[i], `"'`))
		isPasswordWord := word == "password" || word == "passwd"
		if !isPasswordWord && (!userContext || argv[i] != "-p") {
			continue
		}
		if value := argv[i+1]; passwordArgValue(value, isPasswordWord, keepPort) {
			removed = append(removed, unquote(value))
			out[i+1] = quoteLike(value, redactedMarker)
			i++
		}
	}
	return out, removed
}
