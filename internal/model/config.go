package model

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
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
// Path must match Scope: repo-relative for repo scope, rooted at "~/"
// for user scope, and absolute for managed scope. See
// normalizeScopedPath.
type ConfigItem struct {
	Harness Harness         `json:"harness"`
	Scope   Scope           `json:"scope"`
	Path    string          `json:"path"`
	SHA256  string          `json:"sha256"`
	Kind    ConfigKind      `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
	// Detect is the entry as the file wrote it, before sanitization,
	// for rule evaluation only: sanitizing can hide what follows a URL,
	// so rules match the raw text while every report, key, and
	// fingerprint is built from Payload. It is nil when the adapter
	// keeps no raw view, and rules then read Payload.
	Detect DetectPayload `json:"-"`
	// MissingScripts is how many project-relative scripts a repository
	// hook runs that are not in the scanned tree (see scriptcheck). It is
	// set after discovery, for rule evaluation only, and is a count so
	// that no path from the raw command is kept.
	MissingScripts ScriptCount `json:"-"`
	// ScriptLocations are the location classes of project scripts whose
	// symlink resolves outside the repository: "home", "temp", "absolute",
	// or "network". The target path is not kept.
	ScriptLocations []string `json:"-"`
	// ChecksumFiles maps each committed sums file a repository env-setup
	// command checks with sha256sum -c to the file names it lists (see
	// scriptcheck). It is set after discovery, for rule evaluation only;
	// a sums file that is missing, outside the repository, or malformed
	// has no entry.
	ChecksumFiles map[string][]string `json:"-"`
	// ChecksumSymlinks is the set of fetch and run file names in a
	// repository env-setup checksum script that exist as symlinks in the
	// repository. It is set after discovery, for rule evaluation only.
	ChecksumSymlinks []string `json:"-"`
	// Hidden is the invisible and direction-changing code points of an
	// instruction or skill file (see internal/hiddenchar): where each run
	// of them starts and its first code point, never the text around
	// or between them. It is set by the adapter, for rule evaluation and
	// the finding's excerpt only.
	Hidden HiddenChars `json:"-"`
	// Line is the 1-based line of this entry in Path. It is display-only:
	// fingerprints do not hash a finding's line. Zero means the adapter
	// did not record one.
	Line int `json:"-"`
	// SourcePaths are repository-relative paths, in addition to Path,
	// whose staged content a finding at this item depends on: every file
	// in Path's symlink chain, a plugin manifest this item was read
	// through and every other file that manifest names, and the hook
	// scripts or checksum files a rule reads from this item. It is set
	// for a --staged scan, to let the staged-paths filter report a
	// finding whose own Path is not among the paths pre-commit passed,
	// when one of these is. Adapters leave it nil; only items that are
	// derived from several files at once (embedded.Check) set it at
	// discovery. A normal scan never reads it: every file is present.
	SourcePaths []string `json:"-"`
}

// HiddenChars is what internal/hiddenchar found in one file. Runs holds
// the first runs, at most hiddenchar.MaxRuns; RunCount counts every run
// and Total every hidden code point in the file.
type HiddenChars struct {
	Runs     []HiddenRun
	Sequence []rune
	RunCount int
	Total    int
}

// String counts the hidden code points, so a formatted ConfigItem stays
// printable with %s.
func (h HiddenChars) String() string { return strconv.Itoa(h.Total) + " hidden code points" }

// HiddenRun is a run of consecutive hidden code points: the first one,
// its 1-based line and column (in code points), and the run's length.
type HiddenRun struct {
	CodePoint    rune
	Line, Column int
	Length       int
}

// ScriptCount is a number of scripts (see ConfigItem.MissingScripts).
type ScriptCount int

// String returns the count in decimal.
func (n ScriptCount) String() string { return strconv.Itoa(int(n)) }

// HookCommandFields are the payload fields an adapter puts a hook's
// command line in: Claude, Codex, Cursor, Windsurf, and Gemini use
// command; Copilot uses bash, powershell, or exec with args; the rest
// are per-platform variants.
var HookCommandFields = []string{"command", "exec", "bash", "powershell", "commandWindows", "command_windows", "windows", "linux", "osx"}

// DetectPayload is an unsanitized JSON payload (see ConfigItem.Detect).
// It has no JSON form and prints as a placeholder under every fmt verb,
// so formatting or encoding a ConfigItem cannot put it in a report, a
// log, or a diagnostic.
type DetectPayload []byte

// Format writes a placeholder, never the payload.
func (DetectPayload) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "[unsanitized payload]") }

// MarshalJSON encodes null, never the payload.
func (DetectPayload) MarshalJSON() ([]byte, error) { return []byte("null"), nil }

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

// ID returns a stable identifier for this config item: harness, scope,
// and the scope-normalized path, joined with ":". It does not include
// the sha256, so the id names the same config entry (for example,
// ".claude/settings.json" in the repo) across edits to its content.
// Finding.Evidence.Config.ID cites this id. A Key on that citation
// names one entry inside the file; it is not part of this id.
func (c ConfigItem) ID() (string, error) {
	if !c.Harness.Valid() {
		return "", fmt.Errorf("config id: harness %q: unknown", c.Harness)
	}
	if !c.Scope.Valid() {
		return "", fmt.Errorf("config id: scope %q: unknown", c.Scope)
	}
	path, err := normalizeScopedPath(c.Scope, c.Path)
	if err != nil {
		return "", fmt.Errorf("config id: %w", err)
	}
	return string(c.Harness) + ":" + string(c.Scope) + ":" + path, nil
}

// parseConfigID splits id into harness, scope, and path. id is
// "<harness>:<scope>:<normalized-path>", the form ConfigItem.ID returns.
// The path may contain colons (a Windows drive), so only the first two
// colons are separators. Each part is checked: harness and scope must be
// known, and the path must already be normalizeScopedPath's result for
// that scope.
func parseConfigID(id string) (Harness, Scope, string, error) {
	id = strings.TrimSpace(id)
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("config id %q: want harness:scope:path", id)
	}
	h := Harness(parts[0])
	if !h.Valid() {
		return "", "", "", fmt.Errorf("config id: harness %q: unknown", parts[0])
	}
	scope := Scope(parts[1])
	if !scope.Valid() {
		return "", "", "", fmt.Errorf("config id: scope %q: unknown", parts[1])
	}
	normalized, err := normalizeScopedPath(scope, parts[2])
	if err != nil {
		return "", "", "", fmt.Errorf("config id: %w", err)
	}
	if normalized != parts[2] {
		return "", "", "", fmt.Errorf("config id: path %q is not normalized", parts[2])
	}
	return h, scope, normalized, nil
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
	if _, err := normalizeScopedPath(c.Scope, c.Path); err != nil {
		return fmt.Errorf("config: %w", err)
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
	if len(c.Detect) > 0 && !json.Valid(c.Detect) {
		return fmt.Errorf("config: detect payload is not valid JSON")
	}
	return nil
}
