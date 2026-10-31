package kit

import "github.com/vgmartinez/tripcord/internal/output"

// SafeArgv sanitizes an argv array (argv[0] is the program, as in an
// OpenCode MCP server's "command": ["docker", "login", "-p", "X"] or a
// devcontainer lifecycle command in array form). Every element is
// sanitized with SafeValue, then output.RedactToolArgv redacts the
// tool-specific secret flags that a per-element scan cannot recognize,
// because a short flag like -p is only a credential for the specific
// tool that treats it as one. What either step removes is recorded for
// the next Add's key discriminator. A non-string element is sanitized
// and left in place.
func (s *Source) SafeArgv(argv []any) []any {
	out, _ := s.SafeValue("", argv).([]any)
	raw := make([]string, len(argv))
	for i, arg := range argv {
		raw[i], _ = arg.(string)
	}
	redacted, removed := output.RedactToolArgv(raw)
	if len(removed) == 0 {
		return out
	}
	s.recordRemoved(removed...)
	for i, arg := range argv {
		if _, isString := arg.(string); isString && redacted[i] != raw[i] {
			out[i] = s.SafeString(redacted[i])
		}
	}
	return out
}
