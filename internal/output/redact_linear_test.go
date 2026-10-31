package output

import (
	"strings"
	"testing"
	"time"
)

// TestRedactionScalesLinearly guards against a redaction pass that
// retries a rejected candidate byte by byte, or scans back to the start
// of the line for each one: on a long line of near-miss candidates that
// is quadratic, which turns a large config excerpt into a hang. Growing
// the input 4x must cost well under the 16x a quadratic pass would.
func TestRedactionScalesLinearly(t *testing.T) {
	t.Parallel()
	units := map[string]string{
		"free-text colon":    "x secret: a ",
		"glued flag":         "a--token=b",
		"literal flag":       "-e --token v ",
		"placeholder flag":   " --token=$X",
		"flow mapping":       "{token: a, ",
		"quoted key":         `"token": $X `,
		"header placeholder": "-H token:$X ",
		"user flag":          "-u root ",
		"tool flag":          "sshpass -p $X ",
	}
	for name, unit := range units {
		small := fastestRedaction(strings.Repeat(unit, (8<<10)/len(unit)))
		large := fastestRedaction(strings.Repeat(unit, (32<<10)/len(unit)))
		if large > 10*small+50*time.Millisecond {
			t.Errorf("%s: 8KiB took %v, 32KiB took %v", name, small, large)
		}
	}
}

func fastestRedaction(input string) time.Duration {
	fastest := time.Duration(1<<63 - 1)
	for range 3 {
		start := time.Now()
		DefaultRedactor(input)
		fastest = min(fastest, time.Since(start))
	}
	return fastest
}
