package rules

import (
	"context"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Engine evaluates compiled rules against config items.
type Engine struct {
	env   *Env
	rules []*Rule
}

// NewEngine returns an engine for rules, which must have been compiled
// in env.
func NewEngine(env *Env, rules []*Rule) *Engine {
	return &Engine{env: env, rules: append([]*Rule(nil), rules...)}
}

// Match is a rule whose when expression was true for a config item.
type Match struct {
	Rule *Rule
	Item model.ConfigItem
}

// EvalError is a rule that could not be evaluated for an item. Rule is
// empty when the item itself was rejected, for example by a size limit.
type EvalError struct {
	Rule string
	Path string
	Err  error
}

func (e EvalError) Error() string {
	if e.Rule == "" {
		return e.Path + ": " + e.Err.Error()
	}
	return e.Rule + ": " + e.Path + ": " + e.Err.Error()
}

// Result holds the matches and the evaluation failures of one scan.
// Failures are never reported as matches.
type Result struct {
	Matches []Match
	Errors  []EvalError
}

// ScanConfig evaluates every applicable rule against every item, in
// item order and then rule order. A rule applies when the item's
// harness is listed and its path matches one of the rule's globs.
func (e *Engine) ScanConfig(ctx context.Context, items []model.ConfigItem) Result {
	var res Result
	for _, item := range items {
		var in *Input
		for _, r := range e.rules {
			if !r.Applies(item) {
				continue
			}
			if err := ctx.Err(); err != nil {
				res.Errors = append(res.Errors, EvalError{Rule: r.ID, Path: item.Path, Err: err})
				return res
			}
			if in == nil {
				var err error
				in, err = ConfigInput(item, e.env.Limits())
				if err != nil {
					res.Errors = append(res.Errors, EvalError{Path: item.Path, Err: err})
					break
				}
			}
			ok, err := r.When.Eval(ctx, in)
			switch {
			case err != nil:
				res.Errors = append(res.Errors, EvalError{Rule: r.ID, Path: item.Path, Err: err})
			case ok:
				res.Matches = append(res.Matches, Match{Rule: r, Item: item})
			}
		}
	}
	return res
}
