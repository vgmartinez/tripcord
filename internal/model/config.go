package model

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Scope is where a config file lives.
type Scope string

const (
	ScopeRepo    Scope = "repo"
	ScopeUser    Scope = "user"
	ScopeManaged Scope = "managed"
)

var scopes = []Scope{ScopeRepo, ScopeUser, ScopeManaged}

// ConfigKind classifies a parsed config entry.
type ConfigKind string

const (
	ConfigKindHook         ConfigKind = "hook"
	ConfigKindMCPServer    ConfigKind = "mcp-server"
	ConfigKindTask         ConfigKind = "task"
	ConfigKindInstructions ConfigKind = "instructions"
	ConfigKindPermissions  ConfigKind = "permissions"
	ConfigKindPlugin       ConfigKind = "plugin"
	ConfigKindSkill        ConfigKind = "skill"
	ConfigKindEnvSetup     ConfigKind = "env-setup"
)

var configKinds = []ConfigKind{
	ConfigKindHook,
	ConfigKindMCPServer,
	ConfigKindTask,
	ConfigKindInstructions,
	ConfigKindPermissions,
	ConfigKindPlugin,
	ConfigKindSkill,
	ConfigKindEnvSetup,
}

// sha256Hex is 64 lowercase hex characters.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ConfigItem is one config file or entry.
// The spec describes the fields and does not publish a sample document,
// so the JSON names are harness, scope, path, sha256, kind, and payload.
type ConfigItem struct {
	Harness Harness         `json:"harness"`
	Scope   Scope           `json:"scope"`
	Path    string          `json:"path"`
	SHA256  string          `json:"sha256"`
	Kind    ConfigKind      `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// String returns the wire value.
func (s Scope) String() string { return string(s) }

// Valid reports whether s is repo, user, or managed.
func (s Scope) Valid() bool {
	for _, item := range scopes {
		if item == s {
			return true
		}
	}
	return false
}

// ParseScope parses a wire value.
func ParseScope(s string) (Scope, error) {
	scope := Scope(s)
	if !scope.Valid() {
		return "", fmt.Errorf("scope %q: unknown", s)
	}
	return scope, nil
}

// String returns the wire value.
func (k ConfigKind) String() string { return string(k) }

// Valid reports whether k is a known config kind.
func (k ConfigKind) Valid() bool {
	for _, item := range configKinds {
		if item == k {
			return true
		}
	}
	return false
}

// ParseConfigKind parses a wire value.
func ParseConfigKind(s string) (ConfigKind, error) {
	k := ConfigKind(s)
	if !k.Valid() {
		return "", fmt.Errorf("config kind %q: unknown", s)
	}
	return k, nil
}

// Validate checks the closed vocabularies and the sha256 shape.
// Payload may be empty. When set, it must be one JSON value.
func (c ConfigItem) Validate() error {
	if !c.Harness.Valid() {
		return fmt.Errorf("config: harness %q: unknown", c.Harness)
	}
	if !c.Scope.Valid() {
		return fmt.Errorf("config: scope %q: unknown", c.Scope)
	}
	if c.Path == "" {
		return fmt.Errorf("config: empty path")
	}
	if !sha256Hex.MatchString(c.SHA256) {
		return fmt.Errorf("config: sha256 must be 64 lowercase hex characters")
	}
	if !c.Kind.Valid() {
		return fmt.Errorf("config: kind %q: unknown", c.Kind)
	}
	if len(c.Payload) > 0 && !json.Valid(c.Payload) {
		return fmt.Errorf("config: payload is not valid JSON")
	}
	return nil
}
