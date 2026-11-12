package scriptcheck

import (
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestAnnotateFetchNotRun(t *testing.T) {
	const copilot = ".github/workflows/copilot-setup-steps.yml"
	const fetch = `{"setting":"step","name":"Fetch tool","key":"tool.tar.gz","run":"curl -fsSL https://x.invalid/t.tar.gz -o tool.tar.gz && tar -xzf tool.tar.gz -C tool"}`
	cases := []struct {
		name     string
		siblings []string
		want     bool
	}{
		{"alone", nil, true},
		{"unrelated step", []string{`{"setting":"step","run":"npm ci"}`}, true},
		{"hashFiles key", []string{`{"setting":"step","uses":"actions/cache@v4","with":{"key":"k-${{ hashFiles('tool.tar.gz') }}"}}`}, true},
		{"label names it", []string{`{"setting":"step","name":"after tool","run":"npm ci"}`}, true},
		{"later step runs it", []string{`{"setting":"step","run":"./tool/install.sh"}`}, false},
		{"uses the directory", []string{`{"setting":"step","uses":"./tool"}`}, false},
		{"working directory", []string{`{"setting":"step","working-directory":"tool","run":"make"}`}, false},
		{"job env", []string{`{"setting":"job","env":{"BASH_ENV":"tool/env.sh"}}`}, false},
		{"glob in a command", []string{`{"setting":"step","run":"sh t*/i.sh"}`}, false},
	}
	for _, c := range cases {
		items := []model.ConfigItem{envSetup(model.HarnessCopilot, copilot, fetch)}
		for _, s := range c.siblings {
			items = append(items, envSetup(model.HarnessCopilot, copilot, s))
		}
		items = append(items, envSetup(model.HarnessCopilot, ".github/workflows/other.yml", `{"setting":"step","run":"./tool/install.sh"}`))
		annotateFetchNotRun(items)
		if got := items[0].FetchNotRun; got != c.want {
			t.Errorf("%s: FetchNotRun = %v, want %v", c.name, got, c.want)
		}
	}
	user := envSetup(model.HarnessCopilot, copilot, fetch)
	user.Scope = model.ScopeUser
	items := []model.ConfigItem{user}
	annotateFetchNotRun(items)
	if items[0].FetchNotRun {
		t.Error("user scope entry got FetchNotRun")
	}
}
