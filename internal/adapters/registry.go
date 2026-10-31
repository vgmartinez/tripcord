// Package adapters defines the boundary between harness-specific discovery
// and the shared config rule engine.
package adapters

import (
	"context"
	"fmt"
	"sort"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Adapter discovers normalized configuration items for one harness. It must
// only read files below RepoRoot; implementations must never execute config,
// invoke hooks, or start a harness.
type Adapter interface {
	Harness() model.Harness
	Detect(repoRoot string) bool
	Discover(ctx context.Context, repoRoot string) ([]model.ConfigItem, error)
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
		if !harness.IsProduct() {
			return nil, fmt.Errorf("adapter harness %q is not a product harness", harness)
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
