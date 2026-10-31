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
		Scope:   ScopeRepo,
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
		// Scope and path shape must agree: an absolute path is not a
		// repo-relative config entry, and a user-scope path must be
		// rooted at "~/".
		{Harness: HarnessClaude, Scope: ScopeRepo, Path: "/etc/claude/settings.json", SHA256: valid.SHA256, Kind: ConfigKindHook},
		{Harness: HarnessClaude, Scope: ScopeUser, Path: ".claude/settings.json", SHA256: valid.SHA256, Kind: ConfigKindHook},
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

	pathByScope := map[Scope]string{
		ScopeRepo:    ".cursor/hooks.json",
		ScopeUser:    "~/.cursor/hooks.json",
		ScopeManaged: "/etc/cursor/hooks.json",
	}
	for _, scope := range scopes {
		item := valid
		item.Scope = scope
		item.Path = pathByScope[scope]
		if err := item.Validate(); err != nil {
			t.Fatalf("%s: %v", scope, err)
		}
	}
}

func TestConfigItemID(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("x"))
	item := ConfigItem{
		Harness: HarnessClaude,
		Scope:   ScopeRepo,
		Path:    ".claude/settings.json",
		SHA256:  hex.EncodeToString(sum[:]),
		Kind:    ConfigKindHook,
	}
	id, err := item.ID()
	if err != nil {
		t.Fatal(err)
	}
	if id != "claude:repo:.claude/settings.json" {
		t.Fatalf("id = %s", id)
	}

	// The id does not depend on sha256: the same config entry keeps the
	// same id across edits to its content.
	sumY := sha256.Sum256([]byte("y"))
	edited := item
	edited.SHA256 = hex.EncodeToString(sumY[:])
	editedID, err := edited.ID()
	if err != nil {
		t.Fatal(err)
	}
	if editedID != id {
		t.Fatalf("id changed with sha256: %s vs %s", editedID, id)
	}

	// Scope changes the id even when the path text is identical,
	// because the scope's path shape differs.
	userItem := ConfigItem{
		Harness: HarnessClaude,
		Scope:   ScopeUser,
		Path:    "~/.claude/settings.json",
		SHA256:  item.SHA256,
		Kind:    ConfigKindHook,
	}
	userID, err := userItem.ID()
	if err != nil {
		t.Fatal(err)
	}
	if userID == id {
		t.Fatalf("repo and user scope ids collided: %s", id)
	}
	if userID != "claude:user:~/.claude/settings.json" {
		t.Fatalf("user id = %s", userID)
	}

	managedItem := ConfigItem{
		Harness: HarnessCursor,
		Scope:   ScopeManaged,
		Path:    "/etc/cursor/hooks.json",
		SHA256:  item.SHA256,
		Kind:    ConfigKindHook,
	}
	managedID, err := managedItem.ID()
	if err != nil {
		t.Fatal(err)
	}
	if managedID != "cursor:managed:/etc/cursor/hooks.json" {
		t.Fatalf("managed id = %s", managedID)
	}
}

func TestConfigItemIDRejectsBadPath(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("x"))
	bad := ConfigItem{
		Harness: HarnessClaude,
		Scope:   ScopeRepo,
		Path:    "/home/runner/work/acme/acme/.claude/settings.json",
		SHA256:  hex.EncodeToString(sum[:]),
		Kind:    ConfigKindHook,
	}
	if _, err := bad.ID(); err == nil {
		t.Fatal("ID() accepted an absolute path for repo scope")
	}
}
