// Package hookpolicy evaluates a hook event against the hook surface
// policy: the policy's custom event rules, which can call every CEL
// detector the rule engine has (shell.risks, shell.unpinned,
// hook.argv, mcp.packages, ...).
package hookpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/hook"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/policy"
	"github.com/vgmartinez/tripcord/internal/rules"
)

// FailureCode is the exit status for err without --on-failure block:
// 3 for invalid input or policy, 4 for a policy read failure or
// anything else.
func FailureCode(err error) exitcode.Code {
	var input *hook.InputError
	if errors.As(err, &input) {
		return exitcode.Config
	}
	var pol *policy.Error
	if errors.As(err, &pol) {
		return pol.ExitCode()
	}
	return exitcode.Internal
}

// hit is one custom rule that denied the event.
type hit struct {
	ID       string
	Severity model.Severity
	Message  string
	Blocks   bool
}

func (h hit) String() string {
	return fmt.Sprintf("%s (%s): %s", h.ID, h.Severity, strings.TrimSpace(h.Message))
}

// Evaluate runs the policy's custom event rules on ev. A rule that
// denies is a hit; a hit at or above fail-on under mode enforce blocks
// (deny). Otherwise hits warn (mode warn) or are only audited (mode
// audit), and the tool call is allowed. A harness the policy does not
// enable is allowed without evaluation. An evaluation error is returned
// as is: the caller fails closed or exits 4.
func Evaluate(ctx context.Context, eff *policy.Effective, ev model.Event, limits rules.Limits) (hook.Verdict, error) {
	if !eff.HarnessEnabled(ev.Source.Harness) || len(eff.Custom) == 0 {
		return hook.Verdict{Decision: model.DecisionAllow}, nil
	}
	in, err := rules.EventInput(ev, limits)
	if err != nil {
		return hook.Verdict{}, err
	}
	ctx, cancel := limits.WithBudget(ctx)
	defer cancel()
	var hits []hit
	for _, c := range eff.Custom {
		if !eff.Selected(c.ID) {
			continue
		}
		deny, err := c.Deny(ctx, in)
		if err != nil {
			return hook.Verdict{}, fmt.Errorf("custom %s: %w", c.ID, err)
		}
		if !deny {
			continue
		}
		sev := eff.Severity(c.ID, c.Severity)
		blocks, err := eff.Fails(sev)
		if err != nil {
			return hook.Verdict{}, fmt.Errorf("custom %s: %w", c.ID, err)
		}
		hits = append(hits, hit{ID: c.ID, Severity: sev, Message: c.Message, Blocks: blocks})
	}
	return verdictFor(eff.Mode, hits), nil
}

func verdictFor(mode policy.Mode, hits []hit) hook.Verdict {
	if len(hits) == 0 {
		return hook.Verdict{Decision: model.DecisionAllow}
	}
	var blocking []string
	all := make([]string, len(hits))
	for i, h := range hits {
		all[i] = h.String()
		if h.Blocks {
			blocking = append(blocking, h.String())
		}
	}
	switch {
	case len(blocking) > 0:
		return hook.Verdict{Decision: model.DecisionDeny, Reason: "tripcord blocked this tool call: " + strings.Join(blocking, "; ")}
	case mode == policy.ModeAudit:
		return hook.Verdict{Decision: model.DecisionAudit, Reason: "tripcord audit: " + strings.Join(all, "; ")}
	default:
		return hook.Verdict{Decision: model.DecisionWarn, Reason: "tripcord warning: " + strings.Join(all, "; ")}
	}
}
