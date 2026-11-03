package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/devin"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/opencode"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
	"github.com/vgmartinez/tripcord/internal/embedded"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/scriptcheck"
)

// adapterDiscover runs every adapter on the repository scope of root,
// autodetected as `tripcord scan` does. A blocking diagnostic fails the
// fixture: a sanitized config that the adapters cannot fully read does
// not test the rule.
func adapterDiscover(ctx context.Context, root string) ([]model.ConfigItem, error) {
	// _home is a user home beside the repository files. It is how a
	// fixture reaches user-scope config (Windsurf mcp_config.json,
	// Copilot mcp-config.json) through the real adapters. Repository
	// walks do not read it: their matchers only accept harness paths.
	home := ""
	user := false
	var getenv func(string) string
	if st, err := os.Stat(filepath.Join(root, "_home")); err == nil && st.IsDir() {
		home = filepath.Join(root, "_home")
		user = true
		// Empty environment: a host COPILOT_HOME or XDG_CONFIG_HOME must
		// not redirect the fixture's user files. Inlined so this test
		// file does not import kittest (that package imports rules).
		getenv = func(string) string { return "" }
	}
	reg, err := adapters.NewRegistry(
		claude.New(claude.Options{IncludeUser: user, HomeDir: home, Getenv: getenv}),
		codex.New(codex.Options{IncludeUser: user, HomeDir: home, Getenv: getenv}),
		copilot.New(copilot.Options{IncludeUser: user, HomeDir: home, Getenv: getenv}),
		cursor.New(cursor.Options{IncludeUser: user, HomeDir: home}),
		gemini.New(gemini.Options{IncludeUser: user, HomeDir: home, Getenv: getenv}),
		opencode.New(opencode.Options{IncludeUser: user, HomeDir: home, Getenv: getenv}),
		windsurf.New(windsurf.Options{IncludeUser: user, HomeDir: home, Getenv: getenv}),
		devin.New(devin.Options{}),
		devcontainer.New(devcontainer.Options{}),
		generic.New(generic.Options{IncludeUser: user, HomeDir: home}),
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
	if err := scriptcheck.Annotate(root, items); err != nil {
		return nil, err
	}
	guards, err := embedded.Check(root, embedded.CheckOptions{})
	if err != nil {
		return nil, err
	}
	return append(items, guards...), nil
}
