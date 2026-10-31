package rules

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"
)

// CEL variables. Every variable is bound on every evaluation. Variables
// that do not apply to the input are empty maps, so a config rule that
// reads event fields evaluates to false instead of failing.
const (
	VarConfig  = "config"
	VarPayload = "payload"
	VarTask    = "task"
	VarEvent   = "event"
)

// Limits bound compilation and evaluation. Rules and policy expressions
// are untrusted data; these limits keep a hook inside its time budget.
type Limits struct {
	// MaxExpressionBytes caps the source length of one expression.
	MaxExpressionBytes int
	// MaxNesting caps parser recursion.
	MaxNesting int
	// CostLimit is the cel-go runtime cost budget for one evaluation.
	CostLimit uint64
	// EvalTimeout cancels one evaluation. It is well below the hook
	// latency target, so a bad expression cannot hold a tool call.
	EvalTimeout time.Duration
	// MaxInputBytes caps the JSON size of one config payload or event.
	MaxInputBytes int
}

// DefaultLimits returns the limits used by the loader and the engine.
func DefaultLimits() Limits {
	return Limits{
		MaxExpressionBytes: 4 << 10,
		MaxNesting:         64,
		CostLimit:          100_000,
		EvalTimeout:        10 * time.Millisecond,
		MaxInputBytes:      1 << 20,
	}
}

// Evaluation failures that are not "the expression is false".
var (
	ErrCostLimit  = errors.New("cel cost limit exceeded")
	ErrTimeout    = errors.New("cel evaluation timed out")
	ErrNotBool    = errors.New("cel expression did not return a bool")
	ErrInputLimit = errors.New("input exceeds size limit")
)

// Env compiles expressions against the Tripcord variables. It has the
// CEL standard library and the cel-go strings extension only. Neither
// can read files, the network, the clock, or the environment, and
// matches() uses Go's RE2 engine, which runs in linear time.
type Env struct {
	env    *cel.Env
	limits Limits
}

// NewEnv returns an environment with the given limits.
func NewEnv(limits Limits) (*Env, error) {
	env, err := cel.NewEnv(
		cel.Variable(VarConfig, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(VarPayload, cel.DynType),
		cel.Variable(VarTask, cel.DynType),
		cel.Variable(VarEvent, cel.MapType(cel.StringType, cel.DynType)),
		ext.Strings(),
		cel.ParserExpressionSizeLimit(limits.MaxExpressionBytes),
		cel.ParserRecursionLimit(limits.MaxNesting),
	)
	if err != nil {
		return nil, err
	}
	return &Env{env: env, limits: limits}, nil
}

// Limits returns the limits this environment enforces.
func (e *Env) Limits() Limits { return e.limits }

// FunctionNames returns the declared function and operator names, sorted.
func (e *Env) FunctionNames() []string {
	names := make([]string, 0, len(e.env.Functions()))
	for name := range e.env.Functions() {
		names = append(names, name)
	}
	return sortedStrings(names)
}

// Expr is a compiled boolean expression.
type Expr struct {
	src    string
	prg    cel.Program
	limits Limits
}

// Compile parses, type-checks, and plans src. The result type must be
// bool. Constant regular expressions are compiled here, so an invalid
// or non-RE2 pattern fails at load time.
func (e *Env) Compile(src string) (*Expr, error) {
	if strings.TrimSpace(src) == "" {
		return nil, errors.New("empty expression")
	}
	if len(src) > e.limits.MaxExpressionBytes {
		return nil, fmt.Errorf("expression is %d bytes, limit %d", len(src), e.limits.MaxExpressionBytes)
	}
	ast, iss := e.env.Compile(src)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("expression type is %s, want bool", ast.OutputType())
	}
	prg, err := e.env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(e.limits.CostLimit),
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		return nil, err
	}
	return &Expr{src: src, prg: prg, limits: e.limits}, nil
}

// Source returns the expression text.
func (x *Expr) Source() string { return x.src }

// Eval runs the expression. A missing map key or list index is false,
// so `task.runOptions.runOn == "folderOpen"` does not fail on a task
// without runOptions. Cost, timeout, and type failures are errors.
func (x *Expr) Eval(ctx context.Context, in *Input) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, x.limits.EvalTimeout)
	defer cancel()
	out, _, err := x.prg.ContextEval(ctx, in.vars)
	if err != nil {
		var cancelled interpreter.EvalCancelledError
		switch {
		case errors.As(err, &cancelled) && cancelled.Cause == interpreter.CostLimitExceeded:
			return false, ErrCostLimit
		case ctx.Err() != nil:
			return false, ErrTimeout
		case isAbsent(err):
			return false, nil
		default:
			return false, err
		}
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, ErrNotBool
	}
	return bool(b), nil
}

// isAbsent reports a lookup of a key or index that is not in the input.
// cel-go reports these as *types.Err without a sentinel, so the message
// prefix is the only signal.
func isAbsent(err error) bool {
	var celErr *types.Err
	if !errors.As(err, &celErr) {
		return false
	}
	msg := celErr.Error()
	return strings.HasPrefix(msg, "no such key: ") || strings.HasPrefix(msg, "index out of bounds: ")
}
