package rules

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vgmartinez/tripcord/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func compileT(t *testing.T, env *Env, src string) *Expr {
	t.Helper()
	x, err := env.Compile(src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return x
}

const runOnFolderOpen = `has(task.runOptions) && has(task.runOptions.runOn) && task.runOptions.runOn == "folderOpen"`

func taskInput(t *testing.T, limits Limits, payload string) *Input {
	t.Helper()
	in, err := ConfigInput(model.ConfigItem{
		Harness: model.SurfaceVSCode, Scope: model.ScopeRepo, Path: ".vscode/tasks.json",
		Kind: model.ConfigKindTask, Payload: json.RawMessage(payload),
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestEvalVariables(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"label":"x","runOptions":{"runOn":"folderOpen"},"n":3}`)
	for src, want := range map[string]bool{
		runOnFolderOpen: true,
		`has(payload.label) && payload.label == "x"`:              true,
		`config.kind == "task"`:                                   true,
		`config.path.endsWith("tasks.json")`:                      true,
		`config.harness == "vscode"`:                              true,
		`has(payload.n) && payload.n == 3`:                        true,
		`has(payload.label) && payload.label.lowerAscii() == "x"`: true,
		`has(task.runOptions) && !has(task.x)`:                    true,
		`"runOptions" in task && "runOn" in task.runOptions && task.runOptions.runOn == "folderOpen"`:        true,
		`has(task.runOptions) && has(task.runOptions.runOn) ? task.runOptions.runOn == "folderOpen" : false`: true,
		`!has(payload.tools) || size(payload.tools) == 0`:                                                    true,
		`event.kind == "" && event.source.harness == "" && event.session.id == ""`:                           true,
		`has(task.missing) && has(task.missing.deep) && task.missing.deep == "a"`:                            false,
		`event.kind == "tool_call"`: false,
	} {
		got, err := compileT(t, env, src).Eval(context.Background(), in)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", src, got, err, want)
		}
	}
}

func TestTaskOnlyBoundForTaskItems(t *testing.T) {
	env := testEnv(t)
	in, err := ConfigInput(model.ConfigItem{
		Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".mcp.json",
		Kind: model.ConfigKindMCPServer, Payload: json.RawMessage(`{"runOptions":{"runOn":"folderOpen"}}`),
	}, env.Limits())
	if err != nil {
		t.Fatal(err)
	}
	got, err := compileT(t, env, runOnFolderOpen).Eval(context.Background(), in)
	if err != nil || got {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestEventInput(t *testing.T) {
	env := testEnv(t)
	ev := model.Event{
		Schema: model.SchemaEvent, ID: "evt_1", TS: time.Unix(0, 0).UTC(),
		Source:  model.Source{Harness: model.HarnessClaude, Surface: "cloud", Version: "1", Origin: "hook:PreToolUse"},
		Session: model.EventSession{ID: "s"}, Kind: model.EventKindToolCall, Tool: "shell",
		Command: "railway volume delete prod",
	}
	in, err := EventInput(ev, env.Limits())
	if err != nil {
		t.Fatal(err)
	}
	x := compileT(t, env, `event.kind == "tool_call" && event.tool == "shell" && event.command.matches("(?i)railway\\s+(volume|environment)\\s+delete") && event.source.harness == "claude"`)
	if got, err := x.Eval(context.Background(), in); err != nil || !got {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestEvalCostLimit(t *testing.T) {
	limits := DefaultLimits()
	// Isolate the cost check: under -race the default timeout fires first.
	limits.EvalTimeout = 10 * time.Second
	env, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]string, 2000)
	for i := range items {
		items[i] = "1"
	}
	in := taskInput(t, env.Limits(), `{"items":[`+strings.Join(items, ",")+`]}`)
	x := compileT(t, env, `has(payload.items) && payload.items.all(a, payload.items.all(b, a == b))`)
	start := time.Now()
	_, err = x.Eval(context.Background(), in)
	if !errors.Is(err, ErrCostLimit) {
		t.Fatalf("err = %v, want ErrCostLimit", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("cost limit took %v", d)
	}
}

func TestEvalTimeout(t *testing.T) {
	limits := DefaultLimits()
	limits.CostLimit = 1 << 62
	limits.EvalTimeout = time.Millisecond
	env, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]string, 3000)
	for i := range items {
		items[i] = "1"
	}
	in := taskInput(t, limits, `{"items":[`+strings.Join(items, ",")+`]}`)
	x := compileT(t, env, `has(payload.items) && payload.items.all(a, payload.items.all(b, a == b))`)
	start := time.Now()
	if _, err := x.Eval(context.Background(), in); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("timeout took %v", d)
	}
}

func TestHookLimits(t *testing.T) {
	// The spec's hook target is 25 ms at p95 for the whole hook.
	l := HookLimits()
	if l.Budget <= 0 || l.Budget >= 25*time.Millisecond || l.EvalTimeout <= 0 || l.EvalTimeout > l.Budget {
		t.Fatalf("hook limits %+v", l)
	}
	if l.MaxInputBytes >= DefaultLimits().MaxInputBytes || l.MaxInputBytes != HookMaxInputBytes {
		t.Fatalf("hook input cap %d", l.MaxInputBytes)
	}
	if DefaultLimits().Budget != 0 {
		t.Fatal("scans have a total budget")
	}
}

// TestHookWorstCaseRegex bounds the uninterruptible case: one matches()
// over an input at the hook cap. The timeout cannot stop it, so the cap
// must. It measures about 4 ms; the bound is loose for slow CI
// machines, the point being that it stays well under the 45 ms a
// 900 KB input took.
func TestHookWorstCaseRegex(t *testing.T) {
	env, err := NewEnv(HookLimits())
	if err != nil {
		t.Fatal(err)
	}
	cmd := strings.Repeat("a", HookMaxInputBytes-200)
	ev := model.Event{Schema: model.SchemaEvent, ID: "e", Command: cmd}
	in, err := EventInput(ev, env.Limits())
	if err != nil {
		t.Fatal(err)
	}
	x := compileT(t, env, `event.command.matches("(a|aa)*(b|c|d)$")`)
	start := time.Now()
	_, _ = x.Eval(context.Background(), in)
	if d := time.Since(start); d > 20*time.Millisecond*timingScale {
		t.Fatalf("worst-case regex at the hook cap took %v", d)
	}
	ev.Command = strings.Repeat("a", HookMaxInputBytes)
	if _, err := EventInput(ev, env.Limits()); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("err = %v, want ErrInputLimit", err)
	}
}

func TestBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.Budget = time.Millisecond
	env, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	in := taskInput(t, limits, `{}`)
	x := compileT(t, env, `true`)
	ctx, cancel := limits.WithBudget(context.Background())
	defer cancel()
	<-ctx.Done()
	if _, err := x.Eval(ctx, in); !errors.Is(err, ErrBudget) {
		t.Fatalf("err = %v, want ErrBudget", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := x.Eval(ctx, in); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestMissingKeyIsFalse pins the Eval fallback that the guard check
// exists for: an unguarded read of a missing field makes the whole
// expression false, even under a negation.
func TestMissingKeyIsFalse(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"list":[]}`)
	for _, src := range []string{
		`task.missing.deep == "a"`,
		`!(task.missing.deep == "a")`,
		`payload.list[3] == 1`,
	} {
		x, err := env.compile(src, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := x.Eval(context.Background(), in); err != nil || got {
			t.Errorf("%s = %v, %v", src, got, err)
		}
		if _, err := env.Compile(src); err == nil {
			t.Errorf("%s compiled without a guard", src)
		}
	}
}

func TestEventInputFillsOptionalFields(t *testing.T) {
	env := testEnv(t)
	in, err := EventInput(model.Event{Schema: model.SchemaEvent, ID: "e", Kind: model.EventKindToolCall}, env.Limits())
	if err != nil {
		t.Fatal(err)
	}
	x := compileT(t, env, `event.tool == "" && event.command == "" && event.source.surface == "" && event.session.repo == "" && config.kind == ""`)
	if got, err := x.Eval(context.Background(), in); err != nil || !got {
		t.Fatalf("got %v, %v", got, err)
	}
	// A fully populated event has no fields outside eventFields.
	full := model.Event{
		Schema: model.SchemaEvent, ID: "e", TS: time.Unix(1, 0), Kind: model.EventKindToolCall,
		Source:  model.Source{Harness: model.HarnessClaude, Surface: "s", Version: "v", Origin: "o"},
		Session: model.EventSession{ID: "s", Repo: "r", Branch: "b", Actor: "a"},
		Tool:    "t", Command: "c", RawRef: "r",
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for k, v := range m {
		paths = append(paths, k)
		if sub, ok := v.(map[string]any); ok {
			for sk := range sub {
				paths = append(paths, k+"."+sk)
			}
		}
	}
	slices.Sort(paths)
	want := slices.Sorted(slices.Values(eventFields))
	if !slices.Equal(paths, want) {
		t.Fatalf("event paths %v, eventFields %v", paths, want)
	}
}

func TestEvalNotBool(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"flag":"yes"}`)
	// dyn == bool type-checks, but a dyn value used as the whole result does not.
	if _, err := env.Compile(`payload.flag`); err == nil {
		t.Fatal("dyn result compiled")
	}
	x := compileT(t, env, `has(payload.flag) && (payload.flag == true || payload.flag == "yes")`)
	if got, err := x.Eval(context.Background(), in); err != nil || !got {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestEvalRuntimeErrorIsError(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"n":"text"}`)
	if _, err := compileT(t, env, `has(payload.n) && payload.n > 3`).Eval(context.Background(), in); err == nil {
		t.Fatal("type error was not reported")
	}
	if _, err := compileT(t, env, `has(payload.n) && payload.n.matches(payload.n + "(")`).Eval(context.Background(), in); err == nil {
		t.Fatal("bad runtime regex was not reported")
	}
}

func TestCompileExpressionLimit(t *testing.T) {
	env := testEnv(t)
	src := `payload.a == "` + strings.Repeat("x", env.Limits().MaxExpressionBytes) + `"`
	if _, err := env.Compile(src); err == nil {
		t.Fatal("long expression compiled")
	}
	deep := strings.Repeat("(", 200) + "true" + strings.Repeat(")", 200)
	if _, err := env.Compile(deep); err == nil {
		t.Fatal("deeply nested expression compiled")
	}
	if _, err := env.Compile("  "); err == nil {
		t.Fatal("empty expression compiled")
	}
}

func TestInputSizeLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxInputBytes = 64
	big := `{"a":"` + strings.Repeat("x", 100) + `"}`
	_, err := ConfigInput(model.ConfigItem{
		Harness: model.HarnessClaude, Scope: model.ScopeRepo, Path: ".mcp.json",
		Kind: model.ConfigKindMCPServer, Payload: json.RawMessage(big),
	}, limits)
	if !errors.Is(err, ErrInputLimit) {
		t.Fatalf("err = %v", err)
	}
	_, err = EventInput(model.Event{Schema: model.SchemaEvent, ID: "e", Command: strings.Repeat("x", 100)}, limits)
	if !errors.Is(err, ErrInputLimit) {
		t.Fatalf("event err = %v", err)
	}
}

// TestFunctionAllowlist pins the CEL functions available to rules.
// A new function must be reviewed for I/O, clock, or environment access
// before the golden file is updated with -update.
func TestFunctionAllowlist(t *testing.T) {
	got := strings.Join(testEnv(t).FunctionNames(), "\n") + "\n"
	const golden = "testdata/cel-functions.golden"
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("CEL function set changed; review it and run go test ./internal/rules -run TestFunctionAllowlist -update\ngot:\n%s", got)
	}
	for _, name := range strings.Fields(got) {
		lower := strings.ToLower(name)
		for _, bad := range []string{"file", "read", "http", "exec", "env", "now", "net"} {
			if strings.Contains(lower, bad) {
				t.Errorf("function %q looks like I/O", name)
			}
		}
	}
}
