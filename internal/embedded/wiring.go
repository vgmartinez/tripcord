// Package embedded implements repo-embedded mode: the files
// `tripcord init --embed` writes, and the single-tree TC-CFG-016 check
// that Tripcord's own hook wiring is still in place.
//
// Tripcord's hooks are identified by the SHA-256 of their canonical JSON
// (keys sorted, no whitespace), prefixed by the hook event. init records
// those digests in .tripcord/embed.json, together with the harnesses it
// wired, and the check compares each wiring file against them.
package embedded

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Paths init writes, relative to the repository root.
const (
	PolicyPath            = ".tripcord/policy.yaml"
	BootstrapPath         = ".tripcord/bootstrap.sh"
	ManifestPath          = ".tripcord/embed.json"
	WorkflowPath          = ".github/workflows/tripcord.yml"
	ClaudeSettingsPath    = ".claude/settings.json"
	CursorHooksPath       = ".cursor/hooks.json"
	CursorEnvironmentPath = ".cursor/environment.json"
	CopilotHooksPath      = ".github/hooks/tripcord.json"
	CopilotSetupStepsPath = ".github/workflows/copilot-setup-steps.yml"
	DevinBlueprintPath    = ".devin/blueprint.yaml"
	AgentsPath            = "AGENTS.md"
)

// ManifestSchema is the schema id of .tripcord/embed.json.
const ManifestSchema = "tripcord.embed/v1"

// GuardSetting is the payload setting of a TC-CFG-016 guard item.
const GuardSetting = "tripcordGuard"

// bootstrapCommand is how every harness runs the bootstrap script from
// the repository root. Claude Code passes the script as an argument.
const bootstrapCommand = "bash " + BootstrapPath

// Harnesses are the harnesses init can wire, in the order it writes them.
// codex stands for every agent that reads AGENTS.md and has no
// repository hook file (Codex, Jules).
var Harnesses = []model.Harness{
	model.HarnessClaude,
	model.HarnessCursor,
	model.HarnessCopilot,
	model.HarnessDevin,
	model.HarnessCodex,
}

// HookHarnesses are the harnesses whose wiring includes hooks, and so
// the ones TC-CFG-016 checks.
var HookHarnesses = []model.Harness{model.HarnessClaude, model.HarnessCursor, model.HarnessCopilot}

// HookEvent is the event every Tripcord pre-tool hook passes to
// `tripcord hook`.
const HookEvent = "pre-tool"

// HookArgs is the argv after "tripcord" that the pre-tool hook of h runs.
func HookArgs(h model.Harness) []string {
	return []string{"hook", "--harness", string(h), "--event", HookEvent}
}

// HookCommandLine is HookArgs as one command line.
func HookCommandLine(h model.Harness) string {
	return "tripcord " + strings.Join(HookArgs(h), " ")
}

// HookEntry is one hook init writes: an element of the array under
// hooks.<Event> in Path.
type HookEntry struct {
	Harness model.Harness
	Path    string
	Event   string
	entry   *node
}

// SHA256 identifies the entry: the digest of its event, a NUL, and its
// canonical JSON.
func (e HookEntry) SHA256() string {
	sum := sha256.Sum256(append([]byte(e.Event+"\x00"), e.entry.canonical()...))
	return hex.EncodeToString(sum[:])
}

// HookPath is the wiring file of a hook harness.
func HookPath(h model.Harness) string {
	switch h {
	case model.HarnessClaude:
		return ClaudeSettingsPath
	case model.HarnessCursor:
		return CursorHooksPath
	case model.HarnessCopilot:
		return CopilotHooksPath
	default:
		return ""
	}
}

// HookEntries returns the hooks init writes for h, or nil when h has no
// hook wiring.
func HookEntries(h model.Harness) []HookEntry {
	path := HookPath(h)
	switch h {
	case model.HarnessClaude:
		args := make([]any, 0, 5)
		for _, a := range HookArgs(h) {
			args = append(args, a)
		}
		return []HookEntry{
			{Harness: h, Path: path, Event: "SessionStart", entry: object(
				"matcher", "startup|resume",
				"hooks", array(object(
					"type", "command",
					"command", "bash",
					"args", array("${CLAUDE_PROJECT_DIR}/"+BootstrapPath, "session-start"),
				)),
			)},
			{Harness: h, Path: path, Event: "PreToolUse", entry: object(
				"matcher", "*",
				"hooks", array(object(
					"type", "command",
					"command", "tripcord",
					"args", array(args...),
					"onFailure", "block",
				)),
			)},
		}
	case model.HarnessCursor:
		return []HookEntry{
			{Harness: h, Path: path, Event: "sessionStart", entry: object(
				"command", bootstrapCommand+" session-start",
			)},
			{Harness: h, Path: path, Event: "preToolUse", entry: object(
				"command", HookCommandLine(h),
				"failClosed", true,
			)},
		}
	case model.HarnessCopilot:
		return []HookEntry{
			{Harness: h, Path: path, Event: "sessionStart", entry: object(
				"type", "command",
				"bash", bootstrapCommand+" session-start",
				"cwd", ".",
			)},
			{Harness: h, Path: path, Event: "preToolUse", entry: object(
				"type", "command",
				"bash", HookCommandLine(h),
				"cwd", ".",
			)},
		}
	default:
		return nil
	}
}

// Manifest is .tripcord/embed.json: the harnesses init wired and the
// digests of the hooks it wrote.
type Manifest struct {
	Schema    string         `json:"schema"`
	Version   string         `json:"version"`
	Harnesses []string       `json:"harnesses"`
	Hooks     []ManifestHook `json:"hooks"`
}

// ManifestHook records one HookEntry.
type ManifestHook struct {
	Harness string `json:"harness"`
	Path    string `json:"path"`
	Event   string `json:"event"`
	SHA256  string `json:"sha256"`
}

func newManifest(version string, harnesses []model.Harness) Manifest {
	m := Manifest{Schema: ManifestSchema, Version: version, Harnesses: []string{}, Hooks: []ManifestHook{}}
	for _, h := range Harnesses {
		if !slices.Contains(harnesses, h) {
			continue
		}
		m.Harnesses = append(m.Harnesses, string(h))
		for _, e := range HookEntries(h) {
			m.Hooks = append(m.Hooks, ManifestHook{Harness: string(h), Path: e.Path, Event: e.Event, SHA256: e.SHA256()})
		}
	}
	return m
}

func (m Manifest) node() *node {
	harnesses := make([]any, len(m.Harnesses))
	for i, h := range m.Harnesses {
		harnesses[i] = h
	}
	hooks := make([]any, len(m.Hooks))
	for i, h := range m.Hooks {
		hooks[i] = object("harness", h.Harness, "path", h.Path, "event", h.Event, "sha256", h.SHA256)
	}
	return object(
		"schema", m.Schema,
		"version", m.Version,
		"harnesses", array(harnesses...),
		"hooks", array(hooks...),
	)
}
