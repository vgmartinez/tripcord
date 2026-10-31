package rules

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
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
		`task.runOptions.runOn == "folderOpen"`: true,
		`payload.label == "x"`:                  true,
		`config.kind == "task"`:                 true,
		`config.path.endsWith("tasks.json")`:    true,
		`config.harness == "vscode"`:            true,
		`payload.n == 3`:                        true,
		`payload.label.lowerAscii() == "x"`:     true,
		`has(task.runOptions) && !has(task.x)`:  true,
		`event.size() == 0`:                     true,
		`task.missing.deep == "a"`:              false,
		`event.kind == "tool_call"`:             false,
		`payload.list[3] == 1`:                  false,
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
	got, err := compileT(t, env, `task.runOptions.runOn == "folderOpen"`).Eval(context.Background(), in)
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
	x := compileT(t, env, `payload.items.all(a, payload.items.all(b, a == b))`)
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
	x := compileT(t, env, `payload.items.all(a, payload.items.all(b, a == b))`)
	start := time.Now()
	if _, err := x.Eval(context.Background(), in); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("timeout took %v", d)
	}
}

func TestDefaultTimeoutBelowHookBudget(t *testing.T) {
	// The spec's cold-start hook target is 25 ms at p95.
	if d := DefaultLimits().EvalTimeout; d <= 0 || d >= 25*time.Millisecond {
		t.Fatalf("EvalTimeout = %v", d)
	}
}

func TestEvalNotBool(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"flag":"yes"}`)
	// dyn == bool type-checks, but a dyn value used as the whole result does not.
	if _, err := env.Compile(`payload.flag`); err == nil {
		t.Fatal("dyn result compiled")
	}
	x := compileT(t, env, `payload.flag == true || payload.flag == "yes"`)
	if got, err := x.Eval(context.Background(), in); err != nil || !got {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestEvalRuntimeErrorIsError(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"n":"text"}`)
	if _, err := compileT(t, env, `payload.n > 3`).Eval(context.Background(), in); err == nil {
		t.Fatal("type error was not reported")
	}
	if _, err := compileT(t, env, `payload.n.matches(payload.n + "(")`).Eval(context.Background(), in); err == nil {
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
