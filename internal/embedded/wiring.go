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
	"maps"
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
	GitattributesPath     = ".gitattributes"
	// PolicyLocalPath is the per-checkout policy layer (policy.LocalFile
	// in internal/policy, duplicated here the same way PolicyPath
	// duplicates policy.RepoFile) that a tracked copy weakens for
	// everyone; see TC-CFG-016.
	PolicyLocalPath = ".tripcord/policy.local.yaml"
	// GitignorePath is where init --embed adds PolicyLocalPath so a
	// fresh checkout does not accidentally track it.
	GitignorePath = ".gitignore"
)

// ManifestSchema is the schema id of .tripcord/embed.json.
const ManifestSchema = "tripcord.embed/v1"

// GuardSetting is the payload setting of a TC-CFG-016 guard item.
const GuardSetting = "tripcordGuard"

// bootstrapCommand is how setup steps run the bootstrap script from the
// repository root.
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

// HookArgs is the argv after the tripcord binary that the pre-tool hook
// of h runs. bootstrap.sh passes it to the verified binary unchanged.
// --on-failure block makes a run that cannot decide deny the call in the
// harness's format rather than exit 3 or 4.
func HookArgs(h model.Harness) []string {
	return []string{"hook", "--harness", string(h), "--event", HookEvent, "--on-failure", "block"}
}

// projectBootstrap is how a hook of h names bootstrap.sh. Claude Code
// and Cursor set a project directory variable. Copilot sets none; its
// hooks run with cwd "." (the repository root). The Copilot CLI also
// runs the hooks in .claude/settings.json, without CLAUDE_PROJECT_DIR,
// so the Claude Code hooks fall back to the working directory.
func projectBootstrap(h model.Harness) string {
	switch h {
	case model.HarnessClaude:
		return `"${CLAUDE_PROJECT_DIR:-.}/` + BootstrapPath + `"`
	case model.HarnessCursor:
		return `"${CURSOR_PROJECT_DIR}/` + BootstrapPath + `"`
	default:
		return BootstrapPath
	}
}

// HookCommandLine is the command the pre-tool hook of h runs: the
// bootstrap script in hook mode, which execs the verified binary with
// HookArgs. Hooks never run tripcord from PATH.
func HookCommandLine(h model.Harness) string {
	return "bash " + projectBootstrap(h) + " " + strings.Join(HookArgs(h), " ")
}

// sessionCommandLine is the command the session-start hook of h runs.
func sessionCommandLine(h model.Harness) string {
	return "bash " + projectBootstrap(h) + " session-start --harness " + string(h)
}

// Copilot command-hook timeouts, in seconds. A timed-out Copilot
// command hook fails open, so these leave room for a cold install
// (session start) and for checksumming the cached binary (pre-tool).
const (
	copilotSessionTimeoutSec = 300
	copilotHookTimeoutSec    = 60
)

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
		return []HookEntry{
			{Harness: h, Path: path, Event: "SessionStart", entry: object(
				"matcher", "startup|resume",
				"hooks", array(object(
					"type", "command",
					"command", sessionCommandLine(h),
				)),
			)},
			{Harness: h, Path: path, Event: "PreToolUse", entry: object(
				"matcher", "*",
				"hooks", array(object(
					"type", "command",
					"command", HookCommandLine(h),
					"onFailure", "block",
				)),
			)},
		}
	case model.HarnessCursor:
		return []HookEntry{
			{Harness: h, Path: path, Event: "sessionStart", entry: object(
				"command", sessionCommandLine(h),
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
				"bash", sessionCommandLine(h),
				"cwd", ".",
				"timeoutSec", copilotSessionTimeoutSec,
			)},
			{Harness: h, Path: path, Event: "preToolUse", entry: object(
				"type", "command",
				"bash", HookCommandLine(h),
				"cwd", ".",
				"timeoutSec", copilotHookTimeoutSec,
			)},
		}
	default:
		return nil
	}
}

// Manifest is .tripcord/embed.json: the pin bootstrap.sh was rendered
// from, the harnesses init wired, and the digests of what it wrote.
type Manifest struct {
	Schema    string            `json:"schema"`
	Version   string            `json:"version"`
	SHA256    map[string]string `json:"sha256"`
	Harnesses []string          `json:"harnesses"`
	Files     []ManifestFile    `json:"files"`
	Hooks     []ManifestHook    `json:"hooks"`
}

// ManifestFile records the SHA-256 of a generated file, or of the step
// init adds to a file it merges into (Step names it).
type ManifestFile struct {
	Path   string `json:"path"`
	Step   string `json:"step,omitempty"`
	SHA256 string `json:"sha256"`
}

// ManifestHook records one HookEntry.
type ManifestHook struct {
	Harness string `json:"harness"`
	Path    string `json:"path"`
	Event   string `json:"event"`
	SHA256  string `json:"sha256"`
}

// Pin is the release the manifest records.
func (m Manifest) Pin() Pin { return Pin{Version: m.Version, SHA256: m.SHA256} }

func newManifest(pin Pin, harnesses []model.Harness, cloudSetup bool) Manifest {
	m := Manifest{
		Schema:    ManifestSchema,
		Version:   pin.Version,
		SHA256:    maps.Clone(pin.SHA256),
		Harnesses: []string{},
		Files: []ManifestFile{
			{Path: BootstrapPath, SHA256: digest(Bootstrap(pin))},
			{Path: WorkflowPath, SHA256: digest(Workflow())},
		},
		Hooks: []ManifestHook{},
	}
	for _, h := range Harnesses {
		if !slices.Contains(harnesses, h) {
			continue
		}
		m.Harnesses = append(m.Harnesses, string(h))
		// The setup step is part of the guard only when --cloud-setup
		// wrote it. Default init does not record a file it does not write.
		if cloudSetup && h == model.HarnessCopilot {
			m.Files = append(m.Files, ManifestFile{Path: CopilotSetupStepsPath, Step: copilotStepName, SHA256: copilotStep().digest()})
		}
		for _, e := range HookEntries(h) {
			m.Hooks = append(m.Hooks, ManifestHook{Harness: string(h), Path: e.Path, Event: e.Event, SHA256: e.SHA256()})
		}
	}
	return m
}

// recordedFile is the digest the manifest records for path (and step).
func (m Manifest) recordedFile(path, step string) string {
	for _, f := range m.Files {
		if f.Path == path && f.Step == step {
			return f.SHA256
		}
	}
	return ""
}

func (m Manifest) node() *node {
	harnesses := make([]any, len(m.Harnesses))
	for i, h := range m.Harnesses {
		harnesses[i] = h
	}
	platforms := slices.Sorted(maps.Keys(m.SHA256))
	sums := make([]any, 0, 2*len(platforms))
	for _, p := range platforms {
		sums = append(sums, p, m.SHA256[p])
	}
	files := make([]any, len(m.Files))
	for i, f := range m.Files {
		if f.Step != "" {
			files[i] = object("path", f.Path, "step", f.Step, "sha256", f.SHA256)
		} else {
			files[i] = object("path", f.Path, "sha256", f.SHA256)
		}
	}
	hooks := make([]any, len(m.Hooks))
	for i, h := range m.Hooks {
		hooks[i] = object("harness", h.Harness, "path", h.Path, "event", h.Event, "sha256", h.SHA256)
	}
	return object(
		"schema", m.Schema,
		"version", m.Version,
		"sha256", object(sums...),
		"harnesses", array(harnesses...),
		"files", array(files...),
		"hooks", array(hooks...),
	)
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
