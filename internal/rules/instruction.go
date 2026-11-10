package rules

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/vgmartinez/tripcord/internal/hiddenchar"
	"github.com/vgmartinez/tripcord/internal/model"
)

var (
	instructionPrefix = regexp.MustCompile(`(?i)^[ \t]*(?:(?:#{1,6}|>+|<!--[ \t]*(?:(?:assistant|user|system|human):[ \t]+)?)[ \t]*|(?:[-*+]|\d+[.)])[ \t]+|\*\*[ \t]*)*(?:(?:please|always|first|you[ \t]+(?:must|should)|make[ \t]+sure[ \t]+to)[,:; \t]+)*`)
	// Longer verbs come first so get-content is not read as get and
	// printenv is not read as print. look up is one phrasal verb.
	instructionRead = regexp.MustCompile(`(?i)\b(?:look[ \t]+up|get-content|printenv|access|echo|retrieve|read|cat|cp|copy|open|load|source|print|dump|collect|extract|show|curl|wget|type|get)\b`)
	// Copulas, auxiliaries, and clause words end the noun phrase. A
	// hyphenated token is not plain, so it is not listed here.
	instructionGapStop  = regexp.MustCompile(`(?i)^(?:not|never|no|don'?t|without|avoid|if|when|where|while|unless|once|and|or|but|then|before|after|is|are|was|were|be|been|being|am|despite|cannot|can|could|should|would|will|shall|may|might|must|do|does|did|have|has|had|first|next|above|below|however|because|since|although|though|until)$|^(?:won|can|don|isn|aren|wasn|weren|couldn|shouldn|wouldn|doesn|didn|hasn|haven|hadn)['’]t$`)
	instructionGapPrep  = regexp.MustCompile(`(?i)^(?:from|in|of|on|at|into|inside|within|via|through|using|with|for)$`)
	instructionGapDet   = regexp.MustCompile(`(?i)^(?:the|all|your|my|our|this|these|any|every|each|its|their|those|a|an)$`)
	instructionGapPlain = regexp.MustCompile(`^[A-Za-z][A-Za-z']*$`)
	// A secret value names what is read, not where it is stored. Outside a
	// direct object of a read verb it needs a local path after it.
	instructionSecretValue = regexp.MustCompile(`(?i)^(?:environment[ \t]+variables?|credentials|secrets?|api[_ ]?keys?|tokens?|passwords?|private[ \t]+key)$`)
	instructionStoredPrep  = regexp.MustCompile(`(?i)^(?:from|in|inside|within|under|of|via|using)$`)
	instructionLocalPath   = regexp.MustCompile(`^(?:~/|\$\{?HOME\}?/|\.{1,2}/|/|\.[\p{L}\p{N}_]|[\p{L}\p{N}_.-]+/)`)
	instructionRedirect    = regexp.MustCompile(`(?:^|[^-])>`)
	// "access token" and "access key" are compound nouns, not the verb.
	instructionAccessCompound = regexp.MustCompile(`(?i)^[ \t]*(?:tokens?|keys?)\b`)
	instructionOpenPR         = regexp.MustCompile(`(?i)^[ \t]+(?:a[ \t]+)?(?:pull[ \t]+request|pr)\b`)
	instructionSend           = regexp.MustCompile(`(?i)\b(?:send|post|upload|email|exfiltrate|transmit|forward)\b`)
	instructionSecret         = regexp.MustCompile(`(?i)(?:\.env(?:\.(?:local|production|development|prod|dev))?(?:\.?(?:[^\w.]|$)|$)|\bprintenv\b|\bprocess\.env\b|\bos\.environ\b|environment variables?|\bcredentials\b|\bsecrets?\b|api[_ ]?keys?\b|\btokens?\b|\bpasswords?\b|private key|(?:~|\$HOME|\$\{HOME\}|/root|/home/[^\s/]+)/\.(?:aws|ssh)|/proc/(?:self|\$(?:\{PPID\}|PPID)|\d+)/environ(?:\.?(?:[^\w.]|$)|$)|\bid_rsa\b|\b(?:aws_[a-z0-9_]+|github_token)\b)`)
	instructionObject         = regexp.MustCompile(`(?i)^[ \t]*(?:(?:--?[a-z][a-z0-9-]*(?:[= ][^ \t]*)?[ \t]+))*?(?:https?://[^ \t]+[ \t]+)?(?:(?:the|all|your|my|our|this|these|any|every|each|its|their|those)[ \t]+)*(?:(?:contents?|values?)[ \t]+of[ \t]+)?(?:\$env:)?(?:[` + "`" + `'"@][ \t]*)?`)
	instructionModifier       = regexp.MustCompile(`(?i)^[ \t]*(?:-[a-z]|(?:sections?|polic(?:y|ies)|flows?|counts?|offsets?|usage|budgets?|docs?|documentation|readme|tables?|runbooks?|design|handling|management|templates?|reset|fields?|requirements?|pages?|code|rotation|formats?|limits?|rules?|guides?|examples?|scopes?|refresh|expiry|expiration|validation|forms?)\b)`)
	instructionClauseEnd      = regexp.MustCompile(`[;]|(?:\.(?:[ \t]|$))`)
	// A period ends a prose sentence. A curl span keeps ';' and the shell
	// operators, which separate commands rather than sentences.
	instructionProseEnd = regexp.MustCompile(`\.(?:[ \t]|$)`)
	// Plain http(s) URLs are ignored, except a URL that embeds $( or a
	// backtick: stripping that URL would hide $(cat .env) inside it.
	// Header and user flags are stripped by stripCurlFlags, which also
	// takes a glued quote, an equals form, and an unquoted header whose
	// value continues past the first word (Authorization: Bearer $TOKEN).
	instructionURLNoise = regexp.MustCompile(`(?i)\bhttps?://(?:(?:[^ \t$` + "`" + `]|\$[^(\t ])*\$?)(?:[ \t]|$)`)
	// "come from" / "comes from" names where a credential originates.
	// It is not an instruction to source a file.
	instructionComesFrom = regexp.MustCompile(`(?i)(?:^|[ \t])(?:come|comes)[ \t]+from\b`)
	instructionURL       = regexp.MustCompile(`(?i)\bhttps?://`)
	instructionNamedSink = regexp.MustCompile(`(?i)\b(?:webhooks?|gist|pastebin|slack|discord)\b`)
	instructionDataSink  = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\r\n]*(?:\B-(?:d|F)\b|--data(?:-[a-z]+)?(?:=|[ \t])|--form(?:=|[ \t])|(?:-X|--request)[ \t=]*POST\b)`)
	instructionToSink    = regexp.MustCompile(`(?i)\bto\b`)
)

// instructionMatchLine returns the first 1-based line that asks the agent to
// read a secret target or to send one to an outbound sink. It never returns
// the line text: findings expose only this coordinate.
func instructionMatchLine(content string) int {
	for line, text := range strings.Split(content, "\n") {
		text = stripInstructionHidden(text)
		prefix := instructionPrefix.FindStringIndex(text)
		if prefix == nil {
			continue
		}
		rest := text[prefix[1]:]
		if read := instructionRead.FindStringIndex(rest); read != nil {
			if read[0] == 0 {
				if strings.EqualFold(rest[read[0]:read[1]], "open") && instructionOpenPR.MatchString(rest[read[1]:]) {
					continue
				}
				verb := strings.ToLower(rest[read[0]:read[1]])
				// printenv is the read: it names no further object. A
				// documentation modifier ("printenv documentation") is quiet.
				if verb == "printenv" {
					if instructionModifier.MatchString(rest[read[1]:]) {
						continue
					}
					return line + 1
				}
				if verb == "curl" || verb == "wget" {
					// instructionCurlSpan keeps the commands after &&, ||,
					// |, and ;. instructionClause would drop them at ';'.
					if instructionSecret.MatchString(stripInstructionCurlNoise(instructionCurlSpan(rest[read[1]:]))) {
						return line + 1
					}
				}
				clause := instructionClause(rest[read[1]:])
				if verb == "echo" {
					if instructionEchoSecret(clause) {
						return line + 1
					}
					continue
				}
				if verb == "access" && instructionAccessCompound.MatchString(clause) {
					continue
				}
				if instructionGapTarget(clause, 0, false, instructionAcquire(verb)) {
					return line + 1
				}
			}
		}
		if send := instructionSend.FindStringIndex(rest); send != nil {
			if send[0] != 0 {
				continue
			}
			after := instructionClause(rest[send[1]:])
			if !instructionDirectSecret(after) {
				continue
			}
			if instructionURL.MatchString(after) || instructionNamedSink.MatchString(after) ||
				instructionDataSink.MatchString(after) || instructionToSink.MatchString(after) {
				return line + 1
			}
		}
	}
	return 0
}

// stripInstructionHidden drops bidi controls and zero-width characters
// so they cannot sit in front of a verb or split a target. Tag
// characters and other letters, including homoglyphs, stay.
func stripInstructionHidden(text string) string {
	return strings.Map(func(r rune) rune {
		switch hiddenchar.Class(r) {
		case hiddenchar.Bidi, hiddenchar.ZeroWidth:
			return -1
		default:
			return r
		}
	}, text)
}

// instructionWordGap is the most words that may sit between a read verb
// and its target. Every skipped token counts, including a determiner.
const instructionWordGap = 6

// instructionHit is a secret at the head of a phrase. value is set when it
// names the secret itself (an API key, a token) rather than where secrets
// are stored (.env, ~/.ssh, process.env, GITHUB_TOKEN). tail follows it.
type instructionHit struct {
	at, blocked, value bool
	tail               string
}

func instructionDirectSecret(text string) bool {
	h := instructionHead(text)
	return h.at && !h.blocked
}

// instructionHead reports whether a secret is the direct object of text.
// blocked is set when that secret is followed by a documentation modifier,
// which ends the search instead of letting the gap walk past it.
func instructionHead(text string) instructionHit {
	text = instructionObject.ReplaceAllString(text, "")
	secret := instructionSecret.FindStringIndex(text)
	if secret == nil || secret[0] != 0 {
		return instructionHit{}
	}
	tail := text[secret[1]:]
	return instructionHit{
		at:      true,
		blocked: instructionModifier.MatchString(tail),
		value:   instructionSecretValue.MatchString(strings.TrimRight(text[:secret[1]], " \t")),
		tail:    tail,
	}
}

// instructionStored reports whether a secret value is read from a local
// path: "API key from the .env file", "credentials in ~/.config". A
// person, product, URL, or UI ("from 1Password", "in Notion", "at
// https://...") is where a credential is obtained, not a file the agent
// opens.
func instructionStored(tail string) bool {
	word, rest := firstInstructionWord(tail)
	if !instructionStoredPrep.MatchString(word) {
		return false
	}
	for {
		word, rest = firstInstructionWord(rest)
		if !instructionGapDet.MatchString(word) {
			break
		}
	}
	word = strings.TrimLeft(word, "`'\"")
	return !strings.Contains(word, "://") && instructionLocalPath.MatchString(word)
}

// instructionAcquire reports verbs that as often mean obtaining a
// credential or opening a page ("Get an API key at ...", "Access the
// secret manager UI") as reading one. Their object must say where the
// secret is stored.
func instructionAcquire(verb string) bool {
	switch strings.Join(strings.Fields(verb), " ") {
	case "get", "retrieve", "access", "look up":
		return true
	default:
		return false
	}
}

// instructionEchoSecret matches echo of a secret value. echo prints its
// operands: a quoted literal, a path such as .env, or output redirected
// with > is written, not read.
func instructionEchoSecret(clause string) bool {
	trimmed := strings.TrimLeft(clause, " \t")
	if strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, "'") || strings.HasPrefix(trimmed, "`") {
		return false
	}
	if instructionRedirect.MatchString(clause) {
		return false
	}
	h := instructionHead(clause)
	return h.at && !h.blocked && h.value
}

// instructionGapTarget matches a secret that is the direct object, or
// that follows at most instructionWordGap words inside the same noun
// phrase. A negation, a clause word, a documentation word, or a token
// that is not a plain word stops the walk. A preposition after a content
// word also stops, so a later secret is not picked up out of a new phrase.
// Once a word other than a determiner is skipped, or for an acquire
// verb, a secret value must be followed by a local path.
func instructionGapTarget(text string, skipped int, widened, strict bool) bool {
	h := instructionHead(text)
	if h.blocked {
		return false
	}
	if h.at {
		// "Source credentials for the run come from the connection"
		// names an origin. A direct-object secret value with no local
		// path in that tail is not a request to read a file.
		if h.value && instructionComesFrom.MatchString(h.tail) && !instructionHasLocalPath(h.tail) {
			return false
		}
		return !h.value || (!widened && !strict) || instructionStored(h.tail)
	}
	if skipped >= instructionWordGap {
		return false
	}
	word, rest := firstInstructionWord(text)
	if word == "" {
		return false
	}
	switch {
	case instructionGapStop.MatchString(word) || instructionModifier.MatchString(word):
		return false
	case instructionGapDet.MatchString(word):
		return instructionGapTarget(rest, skipped+1, widened, strict)
	case instructionGapPrep.MatchString(word):
		if widened {
			return false
		}
		return instructionGapTarget(rest, skipped+1, true, strict)
	case instructionGapPlain.MatchString(word):
		return instructionGapTarget(rest, skipped+1, true, strict)
	default:
		return false
	}
}

func firstInstructionWord(text string) (string, string) {
	text = strings.TrimLeft(text, " \t")
	if text == "" {
		return "", ""
	}
	i := 0
	for i < len(text) && text[i] != ' ' && text[i] != '\t' {
		i++
	}
	return text[:i], text[i:]
}

// curlNoiseFlags are the Authorization and user flags the rule ignores.
// Longer flags come first so --header is not read as -H.
var curlNoiseFlags = []string{"--oauth2-bearer", "--header", "--user", "-H", "-u"}

// stripInstructionCurlNoise drops auth-header and user-flag values, then
// plain http(s) URLs. A URL that embeds $( or a backtick is kept.
func stripInstructionCurlNoise(clause string) string {
	return instructionURLNoise.ReplaceAllString(stripCurlFlags(clause), " ")
}

func stripCurlFlags(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		flag, ok := curlFlagAt(s, i)
		if !ok {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteByte(' ')
		i = consumeCurlValue(s, i+len(flag), flag)
	}
	return b.String()
}

func curlFlagAt(s string, i int) (string, bool) {
	if i > 0 && s[i-1] != ' ' && s[i-1] != '\t' {
		return "", false
	}
	for _, flag := range curlNoiseFlags {
		if len(s) < i+len(flag) || !strings.EqualFold(s[i:i+len(flag)], flag) {
			continue
		}
		end := i + len(flag)
		if end == len(s) {
			return flag, true
		}
		switch s[end] {
		case ' ', '\t', '=', '"', '\'':
			return flag, true
		}
	}
	return "", false
}

// consumeCurlValue reads the value of a curl auth flag. A quoted value is
// one string. An unquoted header that contains ":" continues through the
// following words, so "Authorization: Bearer $TOKEN" is one value. The
// walk stops at the next flag, at an http(s) URL (which the URL pass
// still has to see), and at a shell operator or a command substitution
// that follows the value, so the next command stays in the clause.
func consumeCurlValue(s string, i int, flag string) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i < len(s) && s[i] == '=' {
		i++
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	if i >= len(s) {
		return i
	}
	if s[i] == '"' || s[i] == '\'' {
		q := s[i]
		i++
		for i < len(s) && s[i] != q {
			i++
		}
		if i < len(s) {
			i++
		}
		return i
	}
	start := i
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	if headerFlag(flag) && strings.Contains(s[start:i], ":") {
		return consumeHeaderTail(s, i)
	}
	return i
}

func consumeHeaderTail(s string, i int) int {
	for {
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if j >= len(s) {
			return j
		}
		if s[j] == '-' || curlURLToken(s[j:]) {
			return i
		}
		for k := j; k < len(s) && s[k] != ' ' && s[k] != '\t'; k++ {
			if !headerStop(s, k) {
				continue
			}
			if k == j {
				return i
			}
			return k
		}
		i = j
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
	}
}

// headerStop reports a shell control operator or a following command
// substitution at k. '&' covers a background command and '&&'. '|'
// covers '|', '||', and '|&'. '$(' , a backtick, and '<(' end the value
// only when they start a substitution, so '$TOKEN' stays inside it.
// '.' ends a clause only when a space or the end of the string follows
// it, so '.env' is not a stop.
func headerStop(s string, k int) bool {
	switch s[k] {
	case '&', '|', ';', '\n', '`':
		return true
	case '$', '<':
		return k+1 < len(s) && s[k+1] == '('
	case '.':
		return k+1 == len(s) || s[k+1] == ' ' || s[k+1] == '\t' || s[k+1] == '\n'
	default:
		return false
	}
}

func curlURLToken(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "http://") || strings.HasPrefix(strings.ToLower(s), "https://")
}

func headerFlag(flag string) bool {
	return strings.EqualFold(flag, "-H") || strings.EqualFold(flag, "--header")
}

// instructionHasLocalPath reports a storage path anywhere in tail, so an
// origin sentence that also names .env or ~/.aws stays a read.
func instructionHasLocalPath(tail string) bool {
	rest := tail
	for {
		word, next := firstInstructionWord(rest)
		if word == "" {
			return false
		}
		// Trim quotes, opening parentheses and brackets, and trailing
		// punctuation. strings.Trim would also drop the leading dot,
		// and .env would no longer match.
		word = strings.TrimLeft(word, "`'\"([{")
		word = strings.TrimRight(word, "`'\".,);]}")
		if instructionLocalPath.MatchString(word) {
			return true
		}
		rest = next
	}
}

func instructionClause(text string) string {
	if end := instructionClauseEnd.FindStringIndex(text); end != nil {
		return text[:end[0]]
	}
	return text
}

// instructionCurlSpan is the curl or wget command plus the commands a
// shell separator attaches to it. A prose period still ends it.
func instructionCurlSpan(text string) string {
	if end := instructionProseEnd.FindStringIndex(text); end != nil {
		return text[:end[0]]
	}
	return text
}

func instructionMatchLineItem(item model.ConfigItem) int {
	raw := item.Payload
	if len(item.Detect) > 0 {
		raw = []byte(item.Detect)
	}
	var payload map[string]any
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&payload); err != nil {
		return 0
	}
	content, _ := payload["content"].(string)
	return instructionMatchLine(content)
}
