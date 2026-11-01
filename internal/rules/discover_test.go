package rules

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/opencode"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
	"github.com/vgmartinez/tripcord/internal/model"
)

// adapterDiscover runs every adapter on the repository scope of root,
// autodetected as `tripcord scan` does. A blocking diagnostic fails the
// fixture: a sanitized config that the adapters cannot fully read does
// not test the rule.
func adapterDiscover(ctx context.Context, root string) ([]model.ConfigItem, error) {
	reg, err := adapters.NewRegistry(
		claude.New(claude.Options{}),
		codex.New(codex.Options{}),
		copilot.New(copilot.Options{}),
		cursor.New(cursor.Options{}),
		gemini.New(gemini.Options{}),
		opencode.New(opencode.Options{}),
		windsurf.New(windsurf.Options{}),
		devcontainer.New(devcontainer.Options{}),
		generic.New(generic.Options{}),
	)
	if err != nil {
		return nil, err
	}
	selected, err := reg.Select(root, nil)
	if err != nil {
		return nil, err
	}
	var items []model.ConfigItem
	var blocking []string
	for _, a := range selected {
		found, err := a.Discover(ctx, root)
		var diag *adapters.DiagnosticError
		switch {
		case errors.As(err, &diag):
			for _, d := range diag.Diagnostics {
				if !d.Informational {
					blocking = append(blocking, d.String())
				}
			}
		case err != nil:
			return nil, fmt.Errorf("%s: %w", a.Harness(), err)
		}
		items = append(items, found...)
	}
	if len(blocking) > 0 {
		return nil, fmt.Errorf("config not fully read: %s", strings.Join(blocking, "; "))
	}
	return items, nil
}
