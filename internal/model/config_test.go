package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestConfigItemRoundTrip(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("hook-body"))
	item := ConfigItem{
		Harness: SurfaceDevcontainer,
		Scope:   ScopeRepo,
		Path:    ".devcontainer/devcontainer.json",
		SHA256:  hex.EncodeToString(sum[:]),
		Kind:    ConfigKindEnvSetup,
		Payload: json.RawMessage(`{"postCreateCommand":"true"}`),
	}
	if err := item.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var got ConfigItem
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	if got.Harness != item.Harness || got.Scope != item.Scope || got.Path != item.Path || got.Kind != item.Kind || got.SHA256 != item.SHA256 {
		t.Fatalf("round trip = %+v", got)
	}
	if string(got.Payload) != string(item.Payload) {
		t.Fatalf("payload = %s", got.Payload)
	}
	again, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(out) {
		t.Fatalf("remarshal = %s", again)
	}
}

func TestConfigItemValidate(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("x"))
	valid := ConfigItem{
		Harness: HarnessCursor,
		Scope:   ScopeUser,
		Path:    ".cursor/hooks.json",
		SHA256:  hex.EncodeToString(sum[:]),
		Kind:    ConfigKindHook,
		Payload: json.RawMessage(`{"version":1}`),
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []ConfigItem{
		{Scope: ScopeRepo, Path: "a", SHA256: valid.SHA256, Kind: ConfigKindHook},
		{Harness: HarnessClaude, Scope: "global", Path: "a", SHA256: valid.SHA256, Kind: ConfigKindHook},
		{Harness: HarnessClaude, Scope: ScopeRepo, SHA256: valid.SHA256, Kind: ConfigKindHook},
		{Harness: HarnessClaude, Scope: ScopeRepo, Path: "a", SHA256: "ABCD", Kind: ConfigKindHook},
		{Harness: HarnessClaude, Scope: ScopeRepo, Path: "a", SHA256: valid.SHA256, Kind: "script"},
		{Harness: HarnessClaude, Scope: ScopeRepo, Path: "a", SHA256: valid.SHA256, Kind: ConfigKindTask, Payload: json.RawMessage(`{`)},
	}
	for _, item := range cases {
		if err := item.Validate(); err == nil {
			t.Fatalf("validated %+v", item)
		}
	}
	for _, kind := range configKinds {
		item := valid
		item.Kind = kind
		if err := item.Validate(); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	for _, scope := range scopes {
		item := valid
		item.Scope = scope
		if err := item.Validate(); err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
	}
}
