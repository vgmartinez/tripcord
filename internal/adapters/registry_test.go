package adapters

import (
	"context"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

type fixtureAdapter struct {
	harness model.Harness
	detect  bool
}

func (a fixtureAdapter) Harness() model.Harness { return a.harness }
func (a fixtureAdapter) Detect(string) bool     { return a.detect }
func (a fixtureAdapter) Discover(context.Context, string) ([]model.ConfigItem, error) {
	return nil, nil
}

func TestRegistrySelect(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry(
		fixtureAdapter{harness: model.HarnessClaude, detect: true},
		fixtureAdapter{harness: model.HarnessCursor, detect: false},
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		requested []model.Harness
		want      []model.Harness
		wantErr   string
	}{
		{"autodetect", nil, []model.Harness{model.HarnessClaude}, ""},
		{"explicit", []model.Harness{model.HarnessCursor}, []model.Harness{model.HarnessCursor}, ""},
		{"deduplicate", []model.Harness{model.HarnessClaude, model.HarnessClaude}, []model.Harness{model.HarnessClaude}, ""},
		{"unavailable", []model.Harness{model.HarnessCodex}, nil, `no installed adapter`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := registry.Select(t.TempDir(), tc.requested)
			if tc.wantErr != "" {
				if err == nil || !contains(err.Error(), tc.wantErr) {
					t.Fatalf("Select error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("adapters = %d, want %d", len(got), len(tc.want))
			}
			for i, adapter := range got {
				if adapter.Harness() != tc.want[i] {
					t.Fatalf("adapter %d = %s, want %s", i, adapter.Harness(), tc.want[i])
				}
			}
		})
	}
}

func contains(s, part string) bool {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
