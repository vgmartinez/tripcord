// Package adapters defines the boundary between harness-specific discovery
// and the shared config rule engine.
package adapters

import (
	"context"
	"fmt"
	"sort"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Adapter discovers normalized configuration items for one harness.
// Repository reads must go through SafeReader. Implementations must never
// execute config, invoke hooks, start a harness, or run git or any other
// external binary.
//
// Discover returns a *DiagnosticError alongside the items it could still
// produce when some inputs could not be read or parsed. Any other error is
// fatal and its items are discarded.
type Adapter interface {
	Harness() model.Harness
	Detect(repoRoot string) bool
	Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error)
}

// AdapterHarness reports whether h can name an installed adapter.
// The seven product harnesses can. generic can: it is the shared adapter
// for skill files that more than one product reads. vscode and
// devcontainer are finding surfaces, not adapters.
func AdapterHarness(h model.Harness) bool {
	return h.IsProduct() || h == model.SurfaceGeneric
}

// Registry holds adapters in deterministic harness order.
type Registry struct {
	adapters map[model.Harness]Adapter
}

// NewRegistry validates and registers adapters.
func NewRegistry(adapters ...Adapter) (*Registry, error) {
	r := &Registry{adapters: make(map[model.Harness]Adapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, fmt.Errorf("adapter is nil")
		}
		harness := adapter.Harness()
		if !AdapterHarness(harness) {
			return nil, fmt.Errorf("adapter harness %q is not a supported adapter harness", harness)
		}
		if _, exists := r.adapters[harness]; exists {
			return nil, fmt.Errorf("adapter harness %q is registered twice", harness)
		}
		r.adapters[harness] = adapter
	}
	return r, nil
}

// Select returns explicitly named adapters, or every adapter whose Detect
// hook recognizes the repository when requested is empty.
func (r *Registry) Select(repoRoot string, requested []model.Harness) ([]Adapter, error) {
	if len(requested) > 0 {
		out := make([]Adapter, 0, len(requested))
		seen := map[model.Harness]bool{}
		for _, harness := range requested {
			if seen[harness] {
				continue
			}
			seen[harness] = true
			adapter, ok := r.adapters[harness]
			if !ok {
				return nil, fmt.Errorf("harness %q has no installed adapter", harness)
			}
			out = append(out, adapter)
		}
		return out, nil
	}
	var out []Adapter
	for _, adapter := range r.adapters {
		if adapter.Detect(repoRoot) {
			out = append(out, adapter)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Harness() < out[j].Harness() })
	return out, nil
}
