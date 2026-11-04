package output

import (
	"strings"
	"testing"
	"time"
)

// TestRedactionScalesLinearly guards against a redaction pass that
// retries a rejected candidate byte by byte, or scans back to the start
// of the line for each one: on a long line of near-miss candidates that
// is quadratic, which turns a large config excerpt into a hang.
// 1 MiB is 16x the 64 KiB input; a linear pass costs about 16x, a
// quadratic one about 256x. The best of several runs is what counts, so
// a busy -race runner or a single CPU does not fail a linear pass, and
// the 64x budget still rejects a quadratic one. A fixed time allowance
// is not added: at a few tens of kilobytes it was large enough to hide
// a backward scan that takes tens of seconds at 1 MiB.
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
		small := fastestRedaction(strings.Repeat(unit, (64<<10)/len(unit)))
		large := fastestRedaction(strings.Repeat(unit, (1<<20)/len(unit)))
		ratio := float64(large) / float64(small)
		t.Logf("%s: 64KiB %v, 1MiB %v (%.1fx)", name, small, large, ratio)
		if large > 64*small {
			t.Errorf("%s: 64KiB took %v, 1MiB took %v (%.1fx, budget 64x)", name, small, large, ratio)
		}
	}
}

// TestBlockScalarCandidatesScaleLinearly holds the YAML block scalar
// check to linear cost on one long, newline-free line of near-miss
// headers, the shape that once ran a backward line scan per candidate
// (12s for 1 MiB). 1 MiB is 16x the 64 KiB input; a linear pass costs
// about 16x, a quadratic one about 256x. The 64x budget, plus a fixed
// allowance for a slow or busy runner, sits far from both.
func TestBlockScalarCandidatesScaleLinearly(t *testing.T) {
	t.Parallel()
	units := map[string]string{
		"pipe value":            "api_key: |x ",
		"mid-line key":          "x api_key: |x ",
		"token key":             "token: |x ",
		"separated":             "api_key: |x; ",
		"folded value":          "api_key: >x ",
		"comment without break": "api_key: | #c ",
		"comment value miss":    "token: #x ",
		"comment key run":       "# token: #\n",
	}
	for name, unit := range units {
		small := fastestRedaction(strings.Repeat(unit, (64<<10)/len(unit)))
		large := fastestRedaction(strings.Repeat(unit, (1<<20)/len(unit)))
		if large > 64*small+250*time.Millisecond {
			t.Errorf("%s: 64KiB took %v, 1MiB took %v (%.1fx, budget 64x)", name, small, large, float64(large)/float64(small))
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
