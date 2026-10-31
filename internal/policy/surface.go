package policy

import (
	"fmt"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Surface is the command surface that consumes a policy. The CLI passes
// it to Load; this package does not run the commands.
type Surface string

const (
	SurfaceScan      Surface = "scan"
	SurfacePreopen   Surface = "preopen"
	SurfacePRContext Surface = "pr-context"
	SurfaceAction    Surface = "action"
	SurfaceHook      Surface = "hook"
)

// Surfaces returns the surfaces in a stable order.
func Surfaces() []Surface {
	return []Surface{SurfaceScan, SurfacePreopen, SurfacePRContext, SurfaceAction, SurfaceHook}
}

// No-policy defaults. Non-hook surfaces fail the run on high and
// critical findings. The hook shows findings and does not block.
const (
	nonHookMode   Mode           = ModeEnforce
	nonHookFailOn model.Severity = model.SeverityHigh
	hookMode      Mode           = ModeWarn
)

// Defaults is the mode and fail-on used when no policy layer sets them.
type Defaults struct {
	Mode Mode
	// FailOn is the lowest severity that fails the run (exit 1).
	// The zero value never fails: findings are shown and the run does
	// not block, whatever the severity.
	FailOn model.Severity
}

// DefaultsFor returns the no-policy defaults for surface. An explicit
// policy mode or fail-on replaces them; see Merge.
func DefaultsFor(surface Surface) (Defaults, error) {
	switch surface {
	case SurfaceScan, SurfacePreopen, SurfacePRContext, SurfaceAction:
		return Defaults{Mode: nonHookMode, FailOn: nonHookFailOn}, nil
	case SurfaceHook:
		return Defaults{Mode: hookMode}, nil
	default:
		return Defaults{}, fmt.Errorf("surface %q: want scan, preopen, pr-context, action, or hook", surface)
	}
}

// Fails reports whether sev is at or above d.FailOn. high means high and
// critical. A zero FailOn never fails.
func (d Defaults) Fails(sev model.Severity) (bool, error) {
	if !sev.Valid() {
		return false, fmt.Errorf("severity %q: unknown", sev)
	}
	if d.FailOn == "" {
		return false, nil
	}
	c, err := sev.Compare(d.FailOn)
	if err != nil {
		return false, err
	}
	return c >= 0, nil
}
