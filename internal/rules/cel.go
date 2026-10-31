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

// CEL variables. Every variable is bound on every evaluation. On a
// config item, event has every event field set to ""; on an event,
// config has every key set to "" and payload and task are empty maps.
const (
	VarConfig  = "config"
	VarPayload = "payload"
	VarTask    = "task"
	VarEvent   = "event"
)

// Limits bound compilation and evaluation. Rules and policy expressions
// are untrusted data; these limits keep a hook inside its time budget.
//
// The timeouts are cooperative. cel-go checks for cancellation between
// steps (every InterruptCheckFrequency comprehension iterations), not
// inside a builtin, so one matches() or contains() call on a large
// string runs to completion past its deadline. The input caps are what
// bound that worst case; the timeouts bound the number of steps.
type Limits struct {
	// MaxExpressionBytes caps the source length of one expression.
	MaxExpressionBytes int
	// MaxNesting caps parser recursion.
	MaxNesting int
	// CostLimit is the cel-go runtime cost budget for one evaluation.
	CostLimit uint64
	// EvalTimeout cancels one evaluation.
	EvalTimeout time.Duration
	// Budget bounds every evaluation for one scan or one hook event
	// together; zero means no total bound. See WithBudget.
	Budget time.Duration
	// MaxInputBytes caps the JSON size of one config payload or event.
	MaxInputBytes int
}

// Hook path limits. The spec's hook latency target is p95 under 25 ms
// for the whole hook. HookBudget is the share for rule evaluation; the
// rest is process start, parsing, and output. HookMaxInputBytes keeps
// the longest uninterruptible builtin call, a regular expression over
// the whole input, to a few milliseconds.
const (
	HookBudget        = 15 * time.Millisecond
	HookEvalTimeout   = 5 * time.Millisecond
	HookMaxInputBytes = 64 << 10
)

// DefaultLimits returns the limits for scans: the loader, the engine,
// and the rule test runner.
func DefaultLimits() Limits {
	return Limits{
		MaxExpressionBytes: 4 << 10,
		MaxNesting:         64,
		CostLimit:          100_000,
		EvalTimeout:        10 * time.Millisecond,
		MaxInputBytes:      1 << 20,
	}
}

// HookLimits returns DefaultLimits with the hook path's per-evaluation
// timeout, total budget, and input cap.
func HookLimits() Limits {
	l := DefaultLimits()
	l.EvalTimeout = HookEvalTimeout
	l.Budget = HookBudget
	l.MaxInputBytes = HookMaxInputBytes
	return l
}

// WithBudget returns a context that ends when l.Budget has elapsed.
// Evaluate one scan or one hook event's rules under it: each Eval is
// capped by what is left, and once it is spent every Eval returns
// ErrBudget. Like EvalTimeout it is cooperative, so the overshoot is at
// most one uninterruptible builtin call.
func (l Limits) WithBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	if l.Budget <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeoutCause(ctx, l.Budget, ErrBudget)
}

// Evaluation failures that are not "the expression is false".
var (
	ErrCostLimit  = errors.New("cel cost limit exceeded")
	ErrTimeout    = errors.New("cel evaluation timed out")
	ErrBudget     = errors.New("rule evaluation budget exhausted")
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
// bool, and reads of optional fields must be guarded (checkGuards).
// Constant regular expressions are compiled here, so an invalid or
// non-RE2 pattern fails at load time.
func (e *Env) Compile(src string) (*Expr, error) {
	return e.compile(src, true)
}

// compile is Compile with the guard check optional, so tests can reach
// the missing-key handling in Eval.
func (e *Env) compile(src string, guarded bool) (*Expr, error) {
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
	if guarded {
		if err := checkGuards(ast.NativeRep().Expr()); err != nil {
			return nil, err
		}
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

// Eval runs the expression. Cost, timeout, budget, and type failures
// are errors.
//
// A missing map key or list index makes the whole expression false,
// not an error. That fails open for a negation: on a task without
// runOptions, `!(task.runOptions.runOn == "never")` is false, not
// true. Compile therefore rejects reading an optional field without a
// has() guard; see checkGuards.
func (x *Expr) Eval(ctx context.Context, in *Input) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, ctxError(ctx)
	}
	ectx, cancel := context.WithTimeout(ctx, x.limits.EvalTimeout)
	defer cancel()
	out, _, err := x.prg.ContextEval(ectx, in.vars)
	if err != nil {
		var cancelled interpreter.EvalCancelledError
		switch {
		case errors.As(err, &cancelled) && cancelled.Cause == interpreter.CostLimitExceeded:
			return false, ErrCostLimit
		case ctx.Err() != nil:
			return false, ctxError(ctx)
		case ectx.Err() != nil:
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

// ctxError is the error for a done caller context: ErrBudget when
// WithBudget ended it, else the cancellation cause.
func ctxError(ctx context.Context) error {
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, ErrBudget):
		return ErrBudget
	case cause != nil:
		return cause
	default:
		return ctx.Err()
	}
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
