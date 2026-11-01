package claude

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/adapters"
)

// hookHeavyPhrase has a tool secret flag, a generic secret flag, and a
// credential "key: value": every source-side redaction pass has work.
const hookHeavyPhrase = "sshpass -p x --token y secret: a"

// hookHeavyShape is one way to fill a settings.json with hookHeavyPhrase.
type hookHeavyShape string

const (
	// repeatedHooks is many hooks all running hookHeavyPhrase.
	repeatedHooks hookHeavyShape = "repeated"
	// distinctHooks is many hooks each running a different variant of
	// it, so no memo can skip work.
	distinctHooks hookHeavyShape = "distinct"
	// oneLongHook is a single hook whose command is hookHeavyPhrase over
	// and over: one string as long as the file.
	oneLongHook hookHeavyShape = "long"
	// pathColonHook and flagPathColonHook exercise colon assignment
	// scanning through path-like prefixes, which must remain linear.
	pathColonHook     hookHeavyShape = "path-colon"
	flagPathColonHook hookHeavyShape = "flag-path-colon"
)

var hookHeavyShapes = []hookHeavyShape{repeatedHooks, distinctHooks, oneLongHook, pathColonHook, flagPathColonHook}

// hookHeavySettings returns a settings.json of the given shape just
// under the 1 MiB read cap.
func hookHeavySettings(tb testing.TB, shape hookHeavyShape) []byte {
	tb.Helper()
	wrap := func(hooks []any) []byte {
		raw, err := json.Marshal(map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{"hooks": hooks}}}})
		if err != nil {
			tb.Fatal(err)
		}
		return raw
	}
	if shape == oneLongHook || shape == pathColonHook || shape == flagPathColonHook {
		budget := int(adapters.MaxConfigFileBytes) - 128 - len(wrap([]any{map[string]any{"type": "command", "command": ""}}))
		command := strings.Repeat(hookHeavyCommand(shape, 0)+"; ", budget/(len(hookHeavyCommand(shape, 0))+2))
		return wrap([]any{map[string]any{"type": "command", "command": command}})
	}
	var hooks []any
	size := int64(len(wrap(nil)))
	for i := 0; ; i++ {
		command := hookHeavyCommand(shape, i)
		hook := map[string]any{"type": "command", "command": command}
		raw, err := json.Marshal(hook)
		if err != nil {
			tb.Fatal(err)
		}
		if size += int64(len(raw)) + 1; size > adapters.MaxConfigFileBytes-128 {
			return wrap(hooks)
		}
		hooks = append(hooks, hook)
	}
}

func hookHeavyCommand(shape hookHeavyShape, i int) string {
	if shape == distinctHooks {
		return fmt.Sprintf("sshpass -p x%d --token y%d secret: a%d", i, i, i)
	}
	switch shape {
	case pathColonHook:
		return "a/token:x"
	case flagPathColonHook:
		return "--k=a-b/password:z"
	default:
		return hookHeavyPhrase
	}
}

func hookHeavyRoot(tb testing.TB, shape hookHeavyShape) string {
	tb.Helper()
	root := tb.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), hookHeavySettings(tb, shape), 0o600); err != nil {
		tb.Fatal(err)
	}
	return root
}

func discoverHookHeavy(tb testing.TB, root string) int {
	tb.Helper()
	items, err := New(Options{}).Discover(context.Background(), root)
	var diag *adapters.DiagnosticError
	if err != nil && !errors.As(err, &diag) {
		tb.Fatal(err)
	}
	if len(items) == 0 {
		tb.Fatal("no items")
	}
	return len(items)
}

// BenchmarkDiscoverHookHeavySettings is the end-to-end cost of one 1 MiB
// settings.json of hooks: read, parse, source-side redaction, keys, and
// signatures. TestDiscoverHookHeavyBudget holds it to a budget in CI.
func BenchmarkDiscoverHookHeavySettings(b *testing.B) {
	for _, shape := range hookHeavyShapes {
		b.Run(string(shape), func(b *testing.B) {
			root := hookHeavyRoot(b, shape)
			b.ResetTimer()
			for range b.N {
				discoverHookHeavy(b, root)
			}
		})
	}
}

// hookHeavyBudget is, per shape, the most a hook-heavy discovery may
// cost relative to decoding the repeated-hooks file with encoding/json,
// both timed in the same process so the ratio does not depend on the
// runner's speed. The fixed baseline is main at b8ec37c, about 130x
// (repeated), 115x (distinct), and 210x (long) on a 4-core x86-64
// machine, where this tree measures about 10x, 30x, and 40x. The budget
// leaves about 2x of headroom for runner noise and still fails on a
// regression to main, on losing kit's Sanitize memo (about 70x
// distinct), or on signing a long command by re-redacting it (about
// 85x long).
//
// The s1 discriminator memoizes output.DefaultRedactor on payload field
// names (kit.redactedFieldName), or repeatedHooks would re-redact the
// same few names for every one of its identical hooks. repeatedHooks
// measures about 14x here and up to about 17x on a CI runner (the Detect
// view rules evaluate added about 3x), so its budget is 20x.
var hookHeavyBudget = map[hookHeavyShape]float64{
	repeatedHooks: 20, distinctHooks: 60, oneLongHook: 80,
	pathColonHook: 80, flagPathColonHook: 80,
}

// TestDiscoverHookHeavyBudget runs only with TRIPCORD_PERF_BUDGET set
// (the CI perf job): a timing check is too noisy for -race runs.
func TestDiscoverHookHeavyBudget(t *testing.T) {
	if os.Getenv("TRIPCORD_PERF_BUDGET") == "" {
		t.Skip("set TRIPCORD_PERF_BUDGET=1 to check the end-to-end performance budget")
	}
	raw := hookHeavySettings(t, repeatedHooks)
	reference := fastest(func() {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
	})
	for _, shape := range hookHeavyShapes {
		root := hookHeavyRoot(t, shape)
		got := fastest(func() { discoverHookHeavy(t, root) })
		ratio := float64(got) / float64(reference)
		t.Logf("%s: discover %v, json decode %v, ratio %.1f (budget %.0f)", shape, got, reference, ratio, hookHeavyBudget[shape])
		if ratio > hookHeavyBudget[shape] {
			t.Errorf("%s: discovery is %.1fx a JSON decode of a file of the same size, over the %.0fx budget", shape, ratio, hookHeavyBudget[shape])
		}
	}
}

// fastest returns the shortest of several timed runs of f, the least
// noisy estimate of its cost.
func fastest(f func()) time.Duration {
	best := time.Duration(math.MaxInt64)
	for range 7 {
		start := time.Now()
		f()
		best = min(best, time.Since(start))
	}
	return best
}
