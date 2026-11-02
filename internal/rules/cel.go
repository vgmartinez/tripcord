package rules

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"

	"github.com/vgmartinez/tripcord/internal/advisory"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules/mcppkg"
	"github.com/vgmartinez/tripcord/internal/rules/shellcmd"
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
// are untrusted data.
//
// CostLimit is what decides that an evaluation is too expensive: cost
// is counted, not timed, so the same input gives the same result on a
// loaded machine. The timeouts are a safety net far above what the
// cost limit allows, for a rule whose cost model underestimates it.
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
// for the whole hook. The input cap and the cost limit are what keep a
// hook inside it: HookMaxInputBytes keeps the longest uninterruptible
// builtin call, a regular expression over the whole input, to a few
// milliseconds, and HookCostLimit bounds the steps. The timeout and the
// budget are only safety nets, so CPU load cannot change a decision.
const (
	HookCostLimit     = 2_000_000
	HookBudget        = 5 * time.Second
	HookEvalTimeout   = time.Second
	HookMaxInputBytes = 64 << 10
)

// DefaultLimits returns the limits for scans: the loader, the engine,
// and the rule test runner.
func DefaultLimits() Limits {
	return Limits{
		MaxExpressionBytes: 4 << 10,
		MaxNesting:         64,
		// Every core rule on a config file at the adapters' 1 MiB cap
		// costs under 10M (a 36,000-entry allow list about 3.4M). A unit
		// takes 8 to 160 ns on an idle machine, the slow end being
		// regular expressions inside nested comprehensions and
		// shell.risks on pathological input, and about 300 ns under
		// load: 20M is up to 6 s, so the timeout sits well past it and
		// the cost limit, not the clock, ends an expensive evaluation.
		CostLimit:     20_000_000,
		EvalTimeout:   15 * time.Second,
		MaxInputBytes: 1 << 20,
	}
}

// HookLimits returns DefaultLimits with the hook path's cost limit,
// per-evaluation timeout, total budget, and input cap.
func HookLimits() Limits {
	l := DefaultLimits()
	l.CostLimit = HookCostLimit
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
	// ErrHookArgs is hook.argv on args that are not a list of strings,
	// numbers, and bools.
	ErrHookArgs = errors.New("hook args are not strings, numbers, or bools")
)

// Env compiles expressions against the Tripcord variables. It has the
// CEL standard library, the cel-go strings extension, shell.risks,
// shell.unpinned, shell.locations, hook.commands, hook.argv,
// mcp.packages, and mcp.vulns. None can read files, the network, the
// clock, or the environment. matches() uses Go's RE2 engine and the
// shell functions a single pass of the shellcmd reader; the MCP
// functions compare an argv with the offline advisory list. All run in
// linear time.
type Env struct {
	env        *cel.Env
	limits     Limits
	advisories *advisory.DB
}

// EnvOption configures an environment.
type EnvOption func(*Env)

// WithAdvisories attaches the offline advisory list mcp.vulns consults.
// Without one, mcp.vulns returns an empty list.
func WithAdvisories(db *advisory.DB) EnvOption {
	return func(e *Env) { e.SetAdvisories(db) }
}

// SetAdvisories replaces the advisory list. LoadPack calls it after
// NewEnv, so the CEL functions, which close over this environment, see
// the list on the next evaluation.
func (e *Env) SetAdvisories(db *advisory.DB) {
	if e != nil {
		e.advisories = db
	}
}

// Advisories returns the list attached to e, or nil.
func (e *Env) Advisories() *advisory.DB {
	if e == nil {
		return nil
	}
	return e.advisories
}

// NewEnv returns an environment with the given limits.
func NewEnv(limits Limits, opts ...EnvOption) (*Env, error) {
	e := &Env{limits: limits}
	env, err := cel.NewEnv(
		cel.Variable(VarConfig, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(VarPayload, cel.DynType),
		cel.Variable(VarTask, cel.DynType),
		cel.Variable(VarEvent, cel.MapType(cel.StringType, cel.DynType)),
		ext.Strings(),
		shellRisks,
		shellUnpinned,
		shellLocations,
		hookCommands,
		hookArgs,
		hookArgv,
		instructionFirstMatchLine,
		e.mcpPackages(),
		e.mcpVulns(),
		cel.ParserExpressionSizeLimit(limits.MaxExpressionBytes),
		cel.ParserRecursionLimit(limits.MaxNesting),
	)
	if err != nil {
		return nil, err
	}
	e.env = env
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// shell.risks(command) and shell.risks([program, arg, ...]) return what a
// hook command does that runs code from the network: "fetch", "pipe",
// "encoded", and "nested" (see shellcmd). The list form is an argument
// vector no shell splits, such as exec and args.
var shellRisks = cel.Function(shellRisksName,
	cel.Overload(overloadShellRisksString, []*cel.Type{cel.StringType}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			s, ok := v.(types.String)
			if !ok {
				return types.MaybeNoSuchOverloadErr(v)
			}
			return newRisksList(shellcmd.Analyze(string(s)))
		})),
	cel.Overload(overloadShellRisksList, []*cel.Type{cel.ListType(cel.DynType)}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			argv, err := stringList(shellRisksName, v)
			if err != nil {
				return types.WrapErr(err)
			}
			return newRisksList(shellcmd.AnalyzeArgv(argv))
		})),
)

// shell.unpinned(command) and shell.unpinned([program, arg, ...]) are
// shell.risks, or an empty list when every fetch in the command is
// pinned by an immutable URL or a checksum check (see
// shellcmd.Unpinned). The two-argument form takes config.checksum_files,
// the committed sums files a sha256sum -c <file> check may cover; without
// it such a check covers nothing. The three-argument form additionally
// takes config.checksum_symlinks, which has no checksum credit.
var shellUnpinned = cel.Function(shellUnpinnedName,
	cel.Overload(overloadShellUnpinnedString, []*cel.Type{cel.StringType}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			s, ok := v.(types.String)
			if !ok {
				return types.MaybeNoSuchOverloadErr(v)
			}
			return newRisksList(shellcmd.Unpinned(string(s)))
		})),
	cel.Overload(overloadShellUnpinnedList, []*cel.Type{cel.ListType(cel.DynType)}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			argv, err := stringList(shellUnpinnedName, v)
			if err != nil {
				return types.WrapErr(err)
			}
			return newRisksList(shellcmd.UnpinnedArgv(argv))
		})),
	cel.Overload(overloadShellUnpinnedStringSums, []*cel.Type{cel.StringType, cel.DynType}, cel.ListType(cel.StringType),
		cel.BinaryBinding(func(v, sumsVal ref.Val) ref.Val {
			s, ok := v.(types.String)
			if !ok {
				return types.MaybeNoSuchOverloadErr(v)
			}
			sums, err := sumsMap(sumsVal)
			if err != nil {
				return types.WrapErr(err)
			}
			return newRisksList(shellcmd.UnpinnedSums(string(s), sums))
		})),
	cel.Overload(overloadShellUnpinnedListSums, []*cel.Type{cel.ListType(cel.DynType), cel.DynType}, cel.ListType(cel.StringType),
		cel.BinaryBinding(func(v, sumsVal ref.Val) ref.Val {
			argv, err := stringList(shellUnpinnedName, v)
			if err != nil {
				return types.WrapErr(err)
			}
			sums, err := sumsMap(sumsVal)
			if err != nil {
				return types.WrapErr(err)
			}
			return newRisksList(shellcmd.UnpinnedArgvSums(argv, sums))
		})),
	cel.Overload(overloadShellUnpinnedStringSumsTargets, []*cel.Type{cel.StringType, cel.DynType, cel.DynType}, cel.ListType(cel.StringType),
		cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			s, ok := args[0].(types.String)
			if !ok {
				return types.MaybeNoSuchOverloadErr(args[0])
			}
			sums, err := sumsMap(args[1])
			if err != nil {
				return types.WrapErr(err)
			}
			targets, err := targetMap(args[2])
			if err != nil {
				return types.WrapErr(err)
			}
			return newRisksList(shellcmd.UnpinnedSumsTargets(string(s), sums, targets))
		})),
	cel.Overload(overloadShellUnpinnedListSumsTargets, []*cel.Type{cel.ListType(cel.DynType), cel.DynType, cel.DynType}, cel.ListType(cel.StringType),
		cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			argv, err := stringList(shellUnpinnedName, args[0])
			if err != nil {
				return types.WrapErr(err)
			}
			sums, err := sumsMap(args[1])
			if err != nil {
				return types.WrapErr(err)
			}
			targets, err := targetMap(args[2])
			if err != nil {
				return types.WrapErr(err)
			}
			return newRisksList(shellcmd.UnpinnedArgvSumsTargets(argv, sums, targets))
		})),
)

// sumsMap reads config.checksum_files: sums file names to the names
// each lists.
func sumsMap(v ref.Val) (shellcmd.Sums, error) {
	m, ok := v.(traits.Mapper)
	if !ok {
		return nil, errors.New(shellUnpinnedName + ": checksum files are not a map")
	}
	sums := shellcmd.Sums{}
	for it := m.Iterator(); it.HasNext() == types.True; {
		k := it.Next()
		name, ok := k.(types.String)
		if !ok {
			return nil, errors.New(shellUnpinnedName + ": checksum file name is not a string")
		}
		listed, err := stringList(shellUnpinnedName, m.Get(k))
		if err != nil {
			return nil, err
		}
		sums[string(name)] = listed
	}
	return sums, nil
}

func targetMap(v ref.Val) (map[string]bool, error) {
	targets, err := stringList(shellUnpinnedName, v)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(targets))
	for _, target := range targets {
		out[target] = true
	}
	return out, nil
}

// shell.locations(command) and shell.locations([program, arg, ...])
// return where the programs and scripts a hook command runs live:
// "network", "home", "temp", "absolute", and "parent" (see
// shellcmd.Locate). A program on PATH or inside the project has none.
var shellLocations = cel.Function(shellLocationsName,
	cel.Overload(overloadShellLocationsString, []*cel.Type{cel.StringType}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			s, ok := v.(types.String)
			if !ok {
				return types.MaybeNoSuchOverloadErr(v)
			}
			r := shellcmd.Locate(string(s))
			return newWorkList(r.Locations, r.Work)
		})),
	cel.Overload(overloadShellLocationsList, []*cel.Type{cel.ListType(cel.DynType)}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			argv, err := stringList(shellLocationsName, v)
			if err != nil {
				return types.WrapErr(err)
			}
			r := shellcmd.LocateArgv(argv)
			return newWorkList(r.Locations, r.Work)
		})),
)

// instruction.first_match_line returns the first 1-based line in an
// instruction body that TC-CFG-012 recognizes, or zero when none does. The
// function returns only a coordinate, never matching text.
var instructionFirstMatchLine = cel.Function(instructionFirstMatchLineName,
	cel.Overload(overloadInstructionFirstMatchLine, []*cel.Type{cel.StringType}, cel.IntType,
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			s, ok := v.(types.String)
			if !ok {
				return types.MaybeNoSuchOverloadErr(v)
			}
			return types.Int(instructionMatchLine(string(s)))
		})),
)

// hook.commands(payload) returns the string values of a hook payload's
// command fields (model.HookCommandFields); a missing or non-string field is
// skipped. hook.args(payload) returns args, and hook.argv(payload) returns
// [exec or command] + args. Number and bool args become their text; either is
// an evaluation error when args is not a list or holds an object, list, or
// null (see argvList). They let a rule read every command field without
// restating the list in each clause.
var hookCommands = cel.Function(hookCommandsName,
	cel.Overload(overloadHookCommands, []*cel.Type{cel.DynType}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			m, ok := v.(traits.Mapper)
			if !ok {
				return types.NewStringList(types.DefaultTypeAdapter, nil)
			}
			var out []string
			for _, k := range model.HookCommandFields {
				if s, ok := mapString(m, k); ok {
					out = append(out, s)
				}
			}
			return types.NewStringList(types.DefaultTypeAdapter, out)
		})),
)

var hookArgv = cel.Function(hookArgvName,
	cel.Overload(overloadHookArgv, []*cel.Type{cel.DynType}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			empty := types.NewStringList(types.DefaultTypeAdapter, nil)
			m, ok := v.(traits.Mapper)
			if !ok {
				return empty
			}
			args, found := m.Find(types.String("args"))
			if !found {
				return empty
			}
			list, err := argvList(args)
			if err != nil {
				return types.WrapErr(err)
			}
			program, ok := mapString(m, "exec")
			if !ok {
				program, _ = mapString(m, "command")
			}
			return types.NewStringList(types.DefaultTypeAdapter, append([]string{program}, list...))
		})),
)

var hookArgs = cel.Function(hookArgsName,
	cel.Overload(overloadHookArgs, []*cel.Type{cel.DynType}, cel.ListType(cel.StringType),
		cel.UnaryBinding(func(v ref.Val) ref.Val {
			empty := types.NewStringList(types.DefaultTypeAdapter, nil)
			m, ok := v.(traits.Mapper)
			if !ok {
				return empty
			}
			args, found := m.Find(types.String("args"))
			if !found {
				return empty
			}
			list, err := argvList(args)
			if err != nil {
				return types.WrapErr(err)
			}
			return types.NewStringList(types.DefaultTypeAdapter, list)
		})),
)

// argvList returns a hook's args as strings. A number or bool is passed
// to the program as its text, so it is stringified; an object, list, or
// null element, or args that is not a list, is an error rather than an
// empty argv, so a rule cannot pass over a hook it could not read.
func argvList(v ref.Val) ([]string, error) {
	list, ok := v.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("%s: args is %s, not a list: %w", hookArgvName, v.Type().TypeName(), ErrHookArgs)
	}
	var out []string
	i := 0
	for it := list.Iterator(); it.HasNext() == types.True; i++ {
		switch e := it.Next().(type) {
		case types.String:
			out = append(out, string(e))
		case types.Bool:
			out = append(out, strconv.FormatBool(bool(e)))
		case types.Int:
			out = append(out, strconv.FormatInt(int64(e), 10))
		case types.Uint:
			out = append(out, strconv.FormatUint(uint64(e), 10))
		case types.Double:
			out = append(out, strconv.FormatFloat(float64(e), 'f', -1, 64))
		default:
			return nil, fmt.Errorf("%s: args element %d is %s: %w", hookArgvName, i, e.Type().TypeName(), ErrHookArgs)
		}
	}
	return out, nil
}

func mapString(m traits.Mapper, key string) (string, bool) {
	v, found := m.Find(types.String(key))
	if !found {
		return "", false
	}
	s, ok := v.(types.String)
	return string(s), ok
}

const (
	hookCommandsName                       = "hook.commands"
	overloadHookCommands                   = "hook_commands_dyn"
	hookArgsName                           = "hook.args"
	overloadHookArgs                       = "hook_args_dyn"
	hookArgvName                           = "hook.argv"
	overloadHookArgv                       = "hook_argv_dyn"
	mcpPackagesName                        = "mcp.packages"
	overloadMCPPackages                    = "mcp_packages_dyn"
	mcpVulnsName                           = "mcp.vulns"
	overloadMCPVulns                       = "mcp_vulns_dyn"
	instructionFirstMatchLineName          = "instruction.first_match_line"
	overloadInstructionFirstMatchLine      = "instruction_first_match_line_string"
	shellRisksName                         = "shell.risks"
	overloadShellRisksString               = "shell_risks_string"
	overloadShellRisksList                 = "shell_risks_list"
	shellUnpinnedName                      = "shell.unpinned"
	overloadShellUnpinnedString            = "shell_unpinned_string"
	overloadShellUnpinnedList              = "shell_unpinned_list"
	overloadShellUnpinnedStringSums        = "shell_unpinned_string_sums"
	overloadShellUnpinnedListSums          = "shell_unpinned_list_sums"
	overloadShellUnpinnedStringSumsTargets = "shell_unpinned_string_sums_targets"
	overloadShellUnpinnedListSumsTargets   = "shell_unpinned_list_sums_targets"
	shellLocationsName                     = "shell.locations"
	overloadShellLocationsString           = "shell_locations_string"
	overloadShellLocationsList             = "shell_locations_list"
)

// risksList is the list a shell function returns, carrying the work the
// reader did so shellCost can charge it.
type risksList struct {
	traits.Lister
	work uint64
}

func newRisksList(r shellcmd.Result) risksList {
	return newWorkList(r.Risks, r.Work)
}

func newWorkList(items []string, work int) risksList {
	return risksList{Lister: types.NewStringList(types.DefaultTypeAdapter, items), work: uint64(work)}
}

// workList is a list whose construction read work bytes. mcp.packages
// and mcp.vulns return one so the cost limit can charge the argv.
type workList struct {
	traits.Lister
	work uint64
}

// shellCost charges shell.risks and shell.locations one unit per byte
// the reader read, at every nesting level it read it: about
// len × (depth + 1). The reader takes a few nanoseconds a byte, so this
// is the same rate or slower than the rest of CEL, and the cost limit,
// not the clock, decides when a long command is too much.
func shellCost(result ref.Val) *uint64 {
	n := uint64(1)
	switch r := result.(type) {
	case risksList:
		n += r.work
	case workList:
		n += r.work
	}
	return &n
}

// costEstimator charges the shell functions by name: with a dyn
// argument the checker cannot pick one overload, so the call has no
// overload id an overload tracker could match. Other functions keep
// the standard costs.
type costEstimator struct{}

func (costEstimator) CallCost(function, _ string, _ []ref.Val, result ref.Val) *uint64 {
	switch function {
	case shellRisksName, shellUnpinnedName, shellLocationsName, mcpPackagesName, mcpVulnsName:
		return shellCost(result)
	default:
		return nil
	}
}

func stringList(function string, v ref.Val) ([]string, error) {
	list, ok := v.(traits.Lister)
	if !ok {
		return nil, errors.New(function + ": argument is not a list")
	}
	var out []string
	for it := list.Iterator(); it.HasNext() == types.True; {
		s, ok := it.Next().(types.String)
		if !ok {
			return nil, errors.New(function + ": list element is not a string")
		}
		out = append(out, string(s))
	}
	return out, nil
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
		cel.CostTracking(costEstimator{}),
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
// mcp.packages(payload) lists the packages a known launcher would
// install. mcp.vulns(payload) lists the embedded advisories those
// packages match. Both fail like hook.args when an argument is not a
// string, number, or bool. With no advisory list, mcp.vulns is empty.
func (e *Env) mcpPackages() cel.EnvOption {
	return cel.Function(mcpPackagesName,
		cel.Overload(overloadMCPPackages, []*cel.Type{cel.DynType}, cel.ListType(cel.DynType),
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				return e.mcpCall(v, false)
			})))
}

func (e *Env) mcpVulns() cel.EnvOption {
	return cel.Function(mcpVulnsName,
		cel.Overload(overloadMCPVulns, []*cel.Type{cel.DynType}, cel.ListType(cel.DynType),
			cel.UnaryBinding(func(v ref.Val) ref.Val {
				return e.mcpCall(v, true)
			})))
}

func (e *Env) mcpCall(v ref.Val, vulns bool) ref.Val {
	payload, err := nativePayload(v)
	if err != nil {
		return types.WrapErr(err)
	}
	refs, work, err := mcppkg.ParsePayload(payload)
	if err != nil {
		return types.WrapErr(fmt.Errorf("mcp: %w", ErrHookArgs))
	}
	var items []map[string]any
	if vulns {
		var hits []advisory.Hit
		if e != nil && e.advisories != nil {
			hits, err = e.advisories.Match(refs)
			if err != nil {
				return types.WrapErr(err)
			}
		}
		items = hitMaps(hits)
	} else {
		items = refMaps(refs)
	}
	return newMapList(items, work)
}

var payloadMapType = reflect.TypeOf(map[string]any{})

func nativePayload(v ref.Val) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	if _, ok := v.(types.Null); ok {
		return map[string]any{}, nil
	}
	got, err := v.ConvertToNative(payloadMapType)
	if err != nil {
		return map[string]any{}, nil
	}
	m, ok := got.(map[string]any)
	if !ok || m == nil {
		return map[string]any{}, nil
	}
	return m, nil
}

func refMaps(refs []advisory.PackageRef) []map[string]any {
	out := make([]map[string]any, len(refs))
	for i, r := range refs {
		out[i] = map[string]any{
			"ecosystem": r.Ecosystem,
			"name":      r.Name,
			"spec":      r.Spec,
			"kind":      r.Kind,
			"version":   r.Version,
		}
	}
	return out
}

func hitMaps(hits []advisory.Hit) []map[string]any {
	out := make([]map[string]any, len(hits))
	for i, h := range hits {
		aliases := h.Aliases
		if aliases == nil {
			aliases = []string{}
		}
		out[i] = map[string]any{
			"id":        h.ID,
			"aliases":   aliases,
			"severity":  h.Severity,
			"ecosystem": h.Ecosystem,
			"name":      h.Name,
			"spec":      h.Spec,
			"kind":      h.Kind,
			"fixed":     h.Fixed,
		}
	}
	return out
}

func newMapList(items []map[string]any, work int) ref.Val {
	native := make([]any, len(items))
	for i, m := range items {
		native[i] = m
	}
	val := types.DefaultTypeAdapter.NativeToValue(native)
	list, ok := val.(traits.Lister)
	if !ok {
		return types.WrapErr(errors.New("mcp result is not a list"))
	}
	return workList{Lister: list, work: uint64(work)}
}

func isAbsent(err error) bool {
	var celErr *types.Err
	if !errors.As(err, &celErr) {
		return false
	}
	msg := celErr.Error()
	return strings.HasPrefix(msg, "no such key: ") || strings.HasPrefix(msg, "index out of bounds: ")
}
