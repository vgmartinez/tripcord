package output

import (
	"strings"
	"testing"
)

// BenchmarkDefaultRedactor measures 1 MiB of each near-miss shape the
// redaction passes have to reject, plus plain text, for comparing a
// change against main with benchstat.
func BenchmarkDefaultRedactor(b *testing.B) {
	for _, tc := range []struct{ name, unit string }{
		{"plain", "npm run build && echo done "},
		{"colon-free-text", "x secret: a "},
		{"glued-flag", "a--token=b"},
		{"literal-flag", "-e --token v "},
		{"placeholder-flag", " --token=$X"},
		{"flow-mapping", "{token: a, "},
		{"equals-names", "TOKEN_TTL=1 "},
		{"user-flag", "-u root "},
		{"tool-flag", "sshpass -p $X "},
	} {
		input := strings.Repeat(tc.unit, (1<<20)/len(tc.unit))
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				DefaultRedactor(input)
			}
		})
	}
}
