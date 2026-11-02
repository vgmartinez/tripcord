// Package devcontainer discovers Dev Container configuration without
// executing it: .devcontainer/devcontainer.json, the named configurations
// in .devcontainer/<name>/devcontainer.json, and the root
// .devcontainer.json. Lifecycle commands, Features, environment maps, and
// the settings that decide which image runs and with what privileges
// become env-setup items. Any harness that opens the repository in a dev
// container (Codespaces, Copilot cloud agents, VS Code, Cursor) runs these
// commands, so the surface has its own harness.
package devcontainer

import (
	"context"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
)

const product = "Dev Containers"

// Options controls discovery. Dev Container configuration lives only in
// the repository, so there is no user or managed scope.
type Options struct {
	SkipRepo bool
	Limits   *kit.Limits
	// FingerprintKey selects the keyed k1 "sig:" discriminator for
	// entries that lost a secret to redaction; nil selects s1.
	FingerprintKey *fpkey.Key
}

// Adapter discovers Dev Container config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns a Dev Container adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.SurfaceDevcontainer }

// Classifies reports whether rel is a Dev Container file this adapter reads.
func (*Adapter) Classifies(rel string) bool { return isConfig(rel) }

// Detect reports whether the repository holds a Dev Container
// configuration, or a config path that cannot be read safely.
func (a *Adapter) Detect(repoRoot string) bool {
	if a.options.SkipRepo {
		return false
	}
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		return false
	}
	defer func() { _ = reader.Close() }()
	c := kit.NewCollector(model.SurfaceDevcontainer, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every Dev Container configuration in the repository. It
// never builds an image, installs a Feature, or runs a lifecycle command.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.SurfaceDevcontainer, product)
	c.SetFingerprintKey(a.options.FingerprintKey)
	if a.options.SkipRepo {
		return c.Result()
	}
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		c.Warn(model.ScopeRepo, "", "cannot open repository: %v", err)
		return c.Result()
	}
	defer func() { _ = reader.Close() }()
	files, err := kit.Walk(ctx, reader, a.limits, c, matcher)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c.Warn(model.ScopeRepo, "", "cannot list repository: %v", err)
		return c.Result()
	}
	r := kit.NewRepoReader(reader, a.limits, c)
	for _, rel := range files {
		raw, ok := r.Read(rel)
		if !ok {
			continue
		}
		(&file{Source: c.Source(model.ScopeRepo, rel, raw)}).config(raw)
	}
	return c.Result()
}

// isConfig reports whether rel is a configuration the Dev Containers
// tooling offers: .devcontainer/devcontainer.json,
// .devcontainer/<name>/devcontainer.json (one level deep), or
// .devcontainer.json, all at the repository root. Matching is
// case-insensitive: macOS and Windows resolve
// ".DevContainer/devcontainer.json" to the same file.
func isConfig(rel string) bool {
	segments := kit.Segments(rel)
	switch len(segments) {
	case 1:
		return segments[0] == ".devcontainer.json"
	case 2, 3:
		return segments[0] == ".devcontainer" && segments[len(segments)-1] == "devcontainer.json"
	}
	return false
}

var matcher = kit.Matcher{
	Candidate: isConfig,
	Relevant: func(rel string) bool {
		segments := kit.Segments(rel)
		return segments[0] == ".devcontainer" || (len(segments) == 1 && segments[0] == ".devcontainer.json")
	},
}
