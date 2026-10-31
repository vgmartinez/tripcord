package rules

import (
	"strings"
	"testing"
)

func TestGuardsAccept(t *testing.T) {
	env := testEnv(t)
	for _, src := range []string{
		`has(payload.a) && payload.a == 1`,
		`has(payload.a) && has(payload.a.b) && payload.a.b == 1`,
		`!has(payload.a) || payload.a == 1`,
		`!(has(payload.a) && payload.a == 1)`,
		`has(payload.a) ? payload.a == 1 : false`,
		`!has(payload.a) ? true : payload.a == 1`,
		`"a" in payload && payload.a == 1`,
		`"a" in payload && payload["a"] == 1`,
		`has(payload.a) && "b" in payload.a && payload.a.b == 1`,
		`(has(payload.a) && has(payload.b)) && payload.a == payload.b`,
		`has(payload.xs) && payload.xs.exists(x, has(x.name) && x.name == "n")`,
		`has(payload.xs) && payload.xs.all(x, x.startsWith("a"))`,
		`has(payload.env) && payload.env.exists(k, k == "TOKEN")`,
		`config.kind == "task" && config.path.endsWith(".json")`,
		`event.command.contains("rm") && event.source.harness == "claude"`,
		`event.net.exists(n, has(n.host) && n.host == "x")`,
		`has(event.extra) && event.extra == 1`,
		`size(payload) == 0`,
		// dyn() is transparent: a guarded field behind it is accepted
		// the same as without it.
		`has(payload.tools) && dyn(payload).tools.size() == 0`,
		`has(payload.a) && dyn(payload).a == 1`,
		`has(payload.a) && has(payload.a.b) && dyn(dyn(payload).a).b == 1`,
	} {
		if _, err := env.Compile(src); err != nil {
			t.Errorf("%s: %v", src, err)
		}
	}
}

func TestGuardsReject(t *testing.T) {
	env := testEnv(t)
	for src, want := range map[string]string{
		`payload.a == 1`:                                         "has(payload.a)",
		`!(payload.a == 1)`:                                      "has(payload.a)",
		`has(payload.a.b) && payload.a.b == 1`:                   "has(payload.a)",
		`has(payload.a) || payload.a == 1`:                       "has(payload.a)",
		`payload.a == 1 && has(payload.a)`:                       "has(payload.a)",
		`has(payload.a) ? false : payload.a == 1`:                "has(payload.a)",
		`!has(payload.a) && payload.a == 1`:                      "has(payload.a)",
		`has(payload.b) && payload.a == 1`:                       "has(payload.a)",
		`task.runOptions.runOn == "folderOpen"`:                  "has(task.runOptions)",
		`payload["a"] == 1`:                                      "has(payload.a)",
		`has(payload.xs) && payload.xs[0] == 1`:                  "constant string key",
		`has(payload.m) && payload.m[config.path] == 1`:          "constant string key",
		`has(payload.xs) && payload.xs.exists(x, x.name == "n")`: "has(x.name)",
		`event.extra == 1`:                                       "has(event.extra)",
		`event.source.x == ""`:                                   "has(event.source.x)",
		`config.content == ""`:                                   "config has only",
		`[1, 2][0] == 1`:                                         "constant string key",
		// dyn() does not excuse the has() guard: it is transparent, so
		// dyn(payload).tools is the same unguarded read as payload.tools.
		`dyn(payload).tools.size() == 0`:          "has(payload.tools)",
		`dyn(event).extra == 1`:                   "has(event.extra)",
		`dyn(dyn(payload)).a == 1`:                "has(payload.a)",
		`has(payload.a) && dyn(payload.a.b) == 1`: "has(payload.a.b)",
		// Selecting a field off any other function's result cannot be
		// traced to a variable, so has() cannot guard it either, even
		// when each branch alone would be fine.
		`(has(payload.a) ? payload : task).b == 1`: "another function's result",
		// A field read off a literal cannot be traced to a variable, so
		// has() cannot guard it. dyn() inside the literal does not
		// change that: the chain still ends at the literal.
		`{"a": task}.a.runOptions.runOn == "never"`:      "literal",
		`{"a": dyn(task)}.a.runOptions.runOn == "never"`: "literal",
		`[task][0].runOptions.runOn == "never"`:          "literal",
		`[dyn(task)][0].runOptions.runOn == "never"`:     "literal",
		`!({"a": task}.a.runOptions.runOn == "never")`:   "literal",
	} {
		_, err := env.Compile(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", src, err, want)
		}
	}
}
