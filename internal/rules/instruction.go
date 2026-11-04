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
	instructionPrefix    = regexp.MustCompile(`(?i)^[ \t]*(?:(?:#{1,6}|>+|<!--[ \t]*(?:(?:assistant|user|system|human):[ \t]+)?)[ \t]*|(?:[-*+]|\d+[.)])[ \t]+|\*\*[ \t]*)*(?:(?:please|always|first|you[ \t]+(?:must|should)|make[ \t]+sure[ \t]+to)[,:; \t]+)*`)
	instructionRead      = regexp.MustCompile(`(?i)\b(?:read|cat|cp|copy|open|load|source|printenv|print|dump|collect|extract|show|curl|wget|type|get-content)\b`)
	instructionOpenPR    = regexp.MustCompile(`(?i)^[ \t]+(?:a[ \t]+)?(?:pull[ \t]+request|pr)\b`)
	instructionSend      = regexp.MustCompile(`(?i)\b(?:send|post|upload|email|exfiltrate|transmit|forward)\b`)
	instructionSecret    = regexp.MustCompile(`(?i)(?:\.env(?:\.(?:local|production|development|prod|dev))?(?:\.?(?:[^\w.]|$)|$)|\bprintenv\b|\bprocess\.env\b|\bos\.environ\b|environment variables?|\bcredentials\b|\bsecrets?\b|api[_ ]?keys?\b|\btokens?\b|\bpasswords?\b|private key|(?:~|\$HOME|\$\{HOME\}|/root|/home/[^\s/]+)/\.(?:aws|ssh)|/proc/(?:self|\$(?:\{PPID\}|PPID)|\d+)/environ(?:\.?(?:[^\w.]|$)|$)|\bid_rsa\b|\b(?:aws_[a-z0-9_]+|github_token)\b)`)
	instructionObject    = regexp.MustCompile(`(?i)^[ \t]*(?:(?:--?[a-z][a-z0-9-]*(?:[= ][^ \t]*)?[ \t]+))*?(?:https?://[^ \t]+[ \t]+)?(?:(?:the|all|your|my|our|this|these|any|every|each|its|their|those)[ \t]+)*(?:(?:contents?|values?)[ \t]+of[ \t]+)?(?:\$env:)?(?:[` + "`" + `'"@][ \t]*)?`)
	instructionModifier  = regexp.MustCompile(`(?i)^[ \t]*(?:-[a-z]|(?:sections?|polic(?:y|ies)|flows?|counts?|usage|budgets?|docs?|documentation|readme|tables?|runbooks?|design|handling|management|templates?|reset|fields?|requirements?|pages?|code|rotation|formats?|limits?|rules?|guides?|examples?|scopes?|refresh|expiry|expiration|validation|forms?)\b)`)
	instructionClauseEnd = regexp.MustCompile(`[;]|(?:\.(?:[ \t]|$))`)
	// Header and user-flag values are ordinary auth, not a secret read.
	// Plain http(s) URLs are ignored too, except a URL that embeds $( or
	// a backtick: stripping that URL would hide $(cat .env) inside it.
	instructionCurlNoise = regexp.MustCompile(`(?i)(?:(?:^|[ \t])(?:-H|--header|-u|--user|--oauth2-bearer)(?:=|[ \t]+)(?:"[^"]*"|'[^']*'|[^ \t]+))|\bhttps?://(?:(?:[^ \t$` + "`" + `]|\$[^(\t ])*\$?)(?:[ \t]|$)`)
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
				if (verb == "curl" || verb == "wget") && instructionSecret.MatchString(instructionCurlNoise.ReplaceAllString(instructionClause(rest[read[1]:]), " ")) {
					return line + 1
				}
				if instructionDirectSecret(rest[read[1]:]) {
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

func instructionDirectSecret(text string) bool {
	text = instructionObject.ReplaceAllString(text, "")
	secret := instructionSecret.FindStringIndex(text)
	return secret != nil && secret[0] == 0 && !instructionModifier.MatchString(text[secret[1]:])
}

func instructionClause(text string) string {
	if end := instructionClauseEnd.FindStringIndex(text); end != nil {
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
