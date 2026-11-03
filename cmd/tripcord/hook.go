package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/hook/hookpolicy"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/policy"
	"github.com/vgmartinez/tripcord/internal/rules"
	corepack "github.com/vgmartinez/tripcord/rules"
)

const hookUsage = `tripcord hook --harness <claude|cursor|copilot> --event <e> [--on-failure block|error]

Reads one hook event as the harness's JSON on stdin, evaluates the
policy's custom event rules (.tripcord/policy.yaml and the org layers,
surface hook), and writes the decision in the harness's format. Exit 0
allows, 2 blocks, 3 is invalid flags, input, or policy, and 4 is an
internal error. With --on-failure block, a run that cannot decide
blocks (exit 2) instead of exiting 3 or 4. See docs/hook.md.

Events: claude pre-tool; cursor pre-tool, before-shell, before-read;
copilot pre-tool.

`

// hookAdapter is one harness's ParseHookInput and RenderDecision.
type hookAdapter struct {
	events []string
	parse  func(event string, data []byte, now time.Time) (model.Event, error)
	render func(event string, v hook.Verdict) hook.Output
	// projectDirEnv names the variable the harness sets to the project
	// directory, whose .tripcord/policy.yaml applies. Without it, the
	// working directory is the project.
	projectDirEnv string
}

var hookAdapters = map[model.Harness]hookAdapter{
	model.HarnessClaude:  {events: claude.HookEvents, parse: claude.ParseHookInput, render: claude.RenderDecision, projectDirEnv: "CLAUDE_PROJECT_DIR"},
	model.HarnessCursor:  {events: cursor.HookEvents, parse: cursor.ParseHookInput, render: cursor.RenderDecision, projectDirEnv: "CURSOR_PROJECT_DIR"},
	model.HarnessCopilot: {events: copilot.HookEvents, parse: copilot.ParseHookInput, render: copilot.RenderDecision},
}

// hookStdin and hookTimeout are variables so tests can feed input and
// shorten the deadline.
var (
	hookStdin   io.Reader = os.Stdin
	hookTimeout           = hook.Timeout
)

func runHook(args []string, stdout, stderr io.Writer) int {
	var harness, event, onFailure string
	flags := flag.NewFlagSet("hook", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&harness, "harness", "", "claude, cursor, or copilot")
	flags.StringVar(&event, "event", "", "hook event: pre-tool, before-shell, or before-read")
	flags.StringVar(&onFailure, "on-failure", string(hook.OnFailureError), "block or error: what a run that cannot decide does")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			var b strings.Builder
			b.WriteString(hookUsage)
			flags.SetOutput(&b)
			flags.PrintDefaults()
			return writeString(stdout, b.String())
		}
		return hookFailure(stdout, stderr, nil, "", failClosedRequested(args), hook.Inputf("%v", err))
	}
	mode, err := hook.ParseOnFailure(onFailure)
	if err != nil {
		return hookFailure(stdout, stderr, nil, "", failClosedRequested(args), &hook.InputError{Err: err})
	}
	failClosed := mode == hook.OnFailureBlock
	if flags.NArg() > 0 {
		return hookFailure(stdout, stderr, nil, "", failClosed, hook.Inputf("unexpected argument %q", flags.Arg(0)))
	}
	ad, ok := hookAdapters[model.Harness(harness)]
	if !ok {
		return hookFailure(stdout, stderr, nil, "", failClosed, hook.Inputf("--harness %q: want claude, cursor, or copilot", harness))
	}
	if !slices.Contains(ad.events, event) {
		return hookFailure(stdout, stderr, &ad, "", failClosed, hook.Inputf("--event %q: %s takes %s", event, harness, strings.Join(ad.events, ", ")))
	}

	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()
	type result struct {
		v   hook.Verdict
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := decideHook(ctx, ad, event)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return hookFailure(stdout, stderr, &ad, event, failClosed, r.err)
		}
		return writeHookOutput(stdout, stderr, ad.render(event, r.v))
	case <-ctx.Done():
		return hookFailure(stdout, stderr, &ad, event, failClosed, fmt.Errorf("no decision within %v", hookTimeout))
	}
}

// decideHook reads the event, loads the policy, and evaluates it.
func decideHook(ctx context.Context, ad hookAdapter, event string) (hook.Verdict, error) {
	data, err := readHookStdin(hookStdin)
	if err != nil {
		return hook.Verdict{}, err
	}
	ev, err := ad.parse(event, data, time.Now())
	if err != nil {
		return hook.Verdict{}, err
	}
	root, err := hookProjectDir(ad)
	if err != nil {
		return hook.Verdict{}, err
	}
	limits := rules.HookLimits()
	eff, err := loadHookPolicy(root, limits)
	if err != nil {
		return hook.Verdict{}, err
	}
	return hookpolicy.Evaluate(ctx, eff, ev, limits)
}

func readHookStdin(r io.Reader) ([]byte, error) {
	if f, ok := r.(*os.File); ok {
		if info, err := f.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			return nil, hook.Inputf("stdin is a terminal or device; the harness pipes its hook JSON to tripcord hook")
		}
	}
	data, err := io.ReadAll(io.LimitReader(r, hook.MaxStdinBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(data) > hook.MaxStdinBytes {
		return nil, hook.Inputf("stdin is over the %d byte limit", hook.MaxStdinBytes)
	}
	return data, nil
}

func hookProjectDir(ad hookAdapter) (string, error) {
	if ad.projectDirEnv != "" {
		if dir := os.Getenv(ad.projectDirEnv); dir != "" {
			if !filepath.IsAbs(dir) {
				return "", hook.Inputf("%s %q is not an absolute path", ad.projectDirEnv, dir)
			}
			return dir, nil
		}
	}
	return os.Getwd()
}

// loadHookPolicy loads the hook surface policy without compiling the
// core pack, which would take most of the hook's latency budget. Merge
// needs the pack's catalog only for rule locks and to reject a custom
// rule that reuses a pack rule id; with any of those, or when the load
// without it fails, the policy is loaded again with the catalog so the
// result is the one scan gets.
func loadHookPolicy(root string, limits rules.Limits) (*policy.Effective, error) {
	env, err := rules.NewEnv(limits)
	if err != nil {
		return nil, err
	}
	opts := policy.Options{RepoRoot: root, Surface: policy.SurfaceHook, Env: env}
	eff, err := policy.Load(opts)
	if err == nil {
		needs, rerr := hookNeedsCatalog(eff)
		if rerr != nil {
			return nil, rerr
		}
		if !needs {
			return eff, nil
		}
	}
	env, catalog, err := loadRules(limits)
	if err != nil {
		return nil, err
	}
	opts.Env, opts.Catalog = env, catalog
	return policy.Load(opts)
}

func hookNeedsCatalog(eff *policy.Effective) (bool, error) {
	if len(eff.RuleLocks) > 0 || len(eff.ExemptionLocks) > 0 {
		return true, nil
	}
	if len(eff.Custom) == 0 {
		return false, nil
	}
	raw, err := corepack.FS.ReadFile(rules.RegistryFile)
	if err != nil {
		return false, err
	}
	reg, err := rules.ParseRegistry(raw)
	if err != nil {
		return false, err
	}
	for _, c := range eff.Custom {
		if _, ok := reg.Lookup(c.ID); ok {
			return true, nil
		}
	}
	return false, nil
}

// hookFailure reports a run that reached no decision. With failClosed
// the tool call is denied in the harness's format (or, before the
// harness is known, with exit 2 and the reason on stderr); otherwise it
// exits 3 or 4 with the error on stderr and nothing on stdout.
func hookFailure(stdout, stderr io.Writer, ad *hookAdapter, event string, failClosed bool, err error) int {
	msg := redactHomeFromError(err)
	if !failClosed {
		writeString(stderr, "tripcord hook: "+msg+"\n")
		return int(hookpolicy.FailureCode(err))
	}
	v := hook.Failed(errors.New(msg))
	if ad == nil || event == "" {
		return writeHookOutput(stdout, stderr, hook.Output{Stderr: v.Reason + "\n", Exit: exitcode.Block})
	}
	return writeHookOutput(stdout, stderr, ad.render(event, v))
}

// failClosedRequested reports whether args ask for --on-failure block,
// for a failure before the flags parse.
func failClosedRequested(args []string) bool {
	for i, a := range args {
		if a == "--on-failure=block" || a == "-on-failure=block" {
			return true
		}
		if (a == "--on-failure" || a == "-on-failure") && i+1 < len(args) && args[i+1] == "block" {
			return true
		}
	}
	return false
}

// writeHookOutput writes o. A failed write is exit 4, except that a
// block stays exit 2: the harness blocks on the status alone.
func writeHookOutput(stdout, stderr io.Writer, o hook.Output) int {
	code := o.Exit
	if len(o.Stdout) > 0 {
		if _, err := stdout.Write(o.Stdout); err != nil && code != exitcode.Block {
			code = exitcode.Internal
		}
	}
	if o.Stderr != "" {
		writeString(stderr, o.Stderr)
	}
	return int(code)
}
