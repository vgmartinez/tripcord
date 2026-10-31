package rules

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
)

// TestConfigInputExtremeNumberFallsBackToString is the repro for the
// scanner-blinding bug: a plain json.Unmarshal into any errors on a
// number too large for float64 ("json: cannot unmarshal number 1e999
// into Go value of type float64"), which used to make ConfigInput fail
// for the whole item, not just the field that carries the odd value.
func TestConfigInputExtremeNumberFallsBackToString(t *testing.T) {
	it := item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, `{"command":"sh","huge":1e999,"ok":5}`)
	in, err := ConfigInput(it, DefaultLimits())
	if err != nil {
		t.Fatalf("ConfigInput: %v", err)
	}
	payload, ok := in.vars[VarPayload].(map[string]any)
	if !ok {
		t.Fatalf("payload = %v, want map", in.vars[VarPayload])
	}
	if payload["huge"] != "1e999" {
		t.Fatalf("huge = %#v, want the literal text \"1e999\"", payload["huge"])
	}
	if payload["ok"] != float64(5) {
		t.Fatalf("ok = %#v, want float64(5): a normal number must decode exactly as json.Unmarshal would", payload["ok"])
	}
}

// TestConfigInputExtremeNumberAcrossHarnesses is the "test across
// adapters" half of the repro: ConfigInput does not branch on
// item.Harness, so every adapter (Claude, Codex, Cursor, Copilot, and
// the shared generic/VS Code surface) that ever emits a config item
// whose payload carries an out-of-range number must decode it the same
// way, without turning one odd value into a scan-wide failure.
func TestConfigInputExtremeNumberAcrossHarnesses(t *testing.T) {
	for _, h := range []model.Harness{
		model.HarnessClaude, model.HarnessCodex, model.HarnessCursor,
		model.HarnessCopilot, model.SurfaceVSCode, model.SurfaceGeneric,
	} {
		t.Run(string(h), func(t *testing.T) {
			it := model.ConfigItem{
				Harness: h, Scope: model.ScopeRepo, Path: "x.json", Kind: model.ConfigKindMCPServer,
				SHA256:  "a", // not validated by ConfigInput
				Payload: json.RawMessage(`{"n":1e999}`),
			}
			if _, err := ConfigInput(it, DefaultLimits()); err != nil {
				t.Fatalf("%s: ConfigInput: %v", h, err)
			}
		})
	}
}

// TestConfigInputNumbersMatchPlainUnmarshal checks that every ordinary
// number still decodes to the same float64 a plain json.Unmarshal would
// have produced, nested in objects and arrays, so the UseNumber switch
// in ConfigInput does not change behavior for any value rules already
// compare against.
func TestConfigInputNumbersMatchPlainUnmarshal(t *testing.T) {
	raw := `{"n":5,"neg":-3,"frac":1.5,"list":[1,2,3],"nested":{"n":42}}`
	it := item(model.HarnessClaude, ".mcp.json", model.ConfigKindMCPServer, raw)
	in, err := ConfigInput(it, DefaultLimits())
	if err != nil {
		t.Fatalf("ConfigInput: %v", err)
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(raw), &want); err != nil {
		t.Fatal(err)
	}
	got := in.vars[VarPayload]
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("payload = %s, want %s", gotJSON, wantJSON)
	}
}

func TestNormalizeNumbersFinite(t *testing.T) {
	cases := []struct {
		name string
		in   json.Number
		want any
	}{
		{"small int", json.Number("5"), float64(5)},
		{"negative", json.Number("-3"), float64(-3)},
		{"fraction", json.Number("1.5"), float64(1.5)},
		{"max float64", json.Number("1.7976931348623157e308"), math.MaxFloat64},
		{"overflow", json.Number("1e999"), "1e999"},
		{"overflow negative", json.Number("-1e999"), "-1e999"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeNumbers(c.in)
			if got != c.want {
				t.Fatalf("normalizeNumbers(%s) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}
