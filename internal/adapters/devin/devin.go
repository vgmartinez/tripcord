// Package devin discovers Devin configuration without executing it.
// v0 reads the git-backed blueprint .devin/blueprint.yaml. Devin runs
// initialize and maintenance while building a snapshot, and surfaces
// maintenance commands and knowledge to the agent at session start.
// .devin/hooks.json stays on the Windsurf adapter.
//
// Source: https://docs.devin.ai/onboard-devin/environment/blueprints
package devin

import (
	"context"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/fpkey"
	"github.com/vgmartinez/tripcord/internal/model"
)

const product = "Devin"

// Options controls discovery. A blueprint lives only in the repository.
type Options struct {
	SkipRepo bool
	Limits   *kit.Limits
	// FingerprintKey selects the keyed k1 "sig:" discriminator for
	// entries that lost a secret to redaction; nil selects s1.
	FingerprintKey *fpkey.Key
}

// Adapter discovers Devin blueprint config.
type Adapter struct {
	options Options
	limits  kit.Limits
}

// New returns a Devin adapter.
func New(options Options) *Adapter {
	limits := kit.DefaultLimits()
	if options.Limits != nil {
		limits = *options.Limits
	}
	return &Adapter{options: options, limits: limits}
}

// Harness implements adapters.Adapter.
func (*Adapter) Harness() model.Harness { return model.HarnessDevin }

// Detect reports whether the repository holds a blueprint, or a blueprint
// path that cannot be read safely.
func (a *Adapter) Detect(repoRoot string) bool {
	if a.options.SkipRepo {
		return false
	}
	reader, err := adapters.NewSafeReader(repoRoot)
	if err != nil {
		return false
	}
	defer func() { _ = reader.Close() }()
	c := kit.NewCollector(model.HarnessDevin, product)
	files, err := kit.Walk(context.Background(), reader, a.limits, c, matcher)
	return err == nil && (len(files) > 0 || len(c.Diagnostics()) > 0)
}

// Discover reads every .devin/blueprint.yaml. It never runs a command,
// starts a build, or calls the sync API.
func (a *Adapter) Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := kit.NewCollector(model.HarnessDevin, product)
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
		(&file{Source: c.Source(model.ScopeRepo, rel, raw), elsewhere: rel != rootBlueprint}).blueprint(raw)
	}
	return c.Result()
}

// rootBlueprint is the exact path Devin v0 documents: the repository's
// own .devin/blueprint.yaml. isBlueprint also matches a nested path, or
// one reached only by a case-insensitive match, which this adapter
// still reads, but whose current directory at build time it cannot
// resolve; see file.elsewhere.
const rootBlueprint = ".devin/blueprint.yaml"

// isBlueprint reports whether rel is .devin/blueprint.yaml at any depth.
// Matching is case-insensitive.
func isBlueprint(rel string) bool {
	segments := kit.Segments(rel)
	n := len(segments)
	return n >= 2 && segments[n-2] == ".devin" && segments[n-1] == "blueprint.yaml"
}

var matcher = kit.Matcher{
	Candidate: isBlueprint,
	Relevant:  func(rel string) bool { return kit.HasSegment(kit.Segments(rel), ".devin") },
}
