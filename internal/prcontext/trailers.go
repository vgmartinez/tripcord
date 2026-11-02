package prcontext

import "strings"

// coAuthors returns the Co-authored-by values in message, in file order.
// Only the trailing trailer block counts: a Co-authored-by line followed
// by more prose is a sentence, not a trailer. Folded trailer lines (a
// continuation with a leading space) are not reassembled.
func coAuthors(message string) []string {
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	i := len(lines) - 1
	for i >= 0 && strings.TrimSpace(lines[i]) == "" {
		i--
	}
	var found []string
	for i >= 0 {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || !trailerKey(key) {
			break
		}
		if strings.EqualFold(key, "Co-authored-by") {
			found = append(found, strings.TrimSpace(value))
		}
		i--
	}
	reverse(found)
	return found
}

func trailerKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// splitIdentity splits "Name <email>" into its name and address. A bare
// address is returned as the email.
func splitIdentity(value string) (name, email string) {
	if start := strings.LastIndex(value, "<"); start >= 0 {
		if end := strings.Index(value[start:], ">"); end >= 0 {
			return strings.TrimSpace(value[:start]), strings.TrimSpace(value[start+1 : start+end])
		}
	}
	value = strings.TrimSpace(value)
	if strings.Contains(value, "@") && !strings.ContainsAny(value, " \t") {
		return "", value
	}
	return value, ""
}
