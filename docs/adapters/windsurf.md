# Windsurf adapter

The Windsurf adapter (harness `windsurf`) discovers Windsurf (Cascade)
configuration statically. It never starts Windsurf, runs a hook, starts
an MCP server, expands `${env:...}` or `${file:...}` placeholders, or
invokes git. Every repository file is treated as attacker-controlled.

Cascade also loads `AGENTS.md`, which is reported by the
[generic](generic.md) adapter; `--harness windsurf` runs it too.

## Locations

### Repository (`--scope repo`, the default)

| Location | Normalized kinds |
| --- | --- |
| `.devin/hooks.json` (any depth) | `hook` (legacy compatibility path; it does not suppress other hooks files) |
| `.windsurf/hooks.json` (any depth) | `hook` |
| `.windsurf/rules/**/*.md` (any depth) | `instructions` (role `rule`) |
| `.windsurf/global_rules.md` (any depth) | `instructions` (role `global`) |
| `.windsurfrules` (repository root) | `instructions` (role `rules`, legacy) |

Cascade discovers `.windsurf/` directories in subdirectories of the
workspace too, so they are matched at any depth. Path matching is
case-insensitive.

### User (`--scope user`)

| Location | Normalized kinds |
| --- | --- |
| `~/.codeium/windsurf/hooks.json` | `hook` |
| `~/.codeium/windsurf/mcp_config.json` | `mcp-server` |
| `~/.codeium/windsurf/memories/global_rules.md` | `instructions` (role `global`) |
| `~/.codeium/windsurf-next/` and `~/.codeium/windsurf-insiders/` | the same three files, for the Next and Insiders channels |
| `~/.codeium/hooks.json` (the JetBrains plugin's user hooks) | `hook` |

Windsurf has no environment override for these paths.

### Managed (`--scope managed`)

The system-level `hooks.json`, deployed by an administrator for every
user of the machine. Devin Local can override the Windsurf file at
runtime, but both files are reported; an informational note marks the
Windsurf file as overridden when both are present.

| OS | Devin | Windsurf |
| --- | --- | --- |
| macOS | `/Library/Application Support/Devin/hooks.json` | `/Library/Application Support/Windsurf/hooks.json` |
| Linux | `/etc/devin/hooks.json` | `/etc/windsurf/hooks.json` |
| Windows | `%ProgramData%\Devin\hooks.json` | `%ProgramData%\Windsurf\hooks.json` |

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, and, when sanitizing removed anything, a
[secret discriminator](../fingerprint.md#secret-discriminator) (`sig:k1:` with a
fingerprint key, `sig:s1:` without one); see
[fingerprint.md](../fingerprint.md#input).

- Hooks: `{"hooks": {"<event>": [{"command", "powershell",
  "show_output", "working_directory"}]}}`. One `hook` item per handler,
  with every field sanitized, plus `event` and an empty `matcher`. The
  key is `["hook", event, "", "", action]`, where the action is
  `command`, or `powershell` when only that is set. Every handler is
  reported whatever its event, since a `pre_*` hook that exits 2 blocks
  the action. An event outside the documented list (`pre_read_code`,
  `post_read_code`, `pre_write_code`, `post_write_code`,
  `pre_run_command`, `post_run_command`, `pre_mcp_tool_use`,
  `post_mcp_tool_use`, `pre_user_prompt`, `post_cascade_response`,
  `post_cascade_response_with_transcript`, `post_setup_worktree`) is
  still emitted, and reported. A file without a `hooks` object, an event
  that is not an array, or a handler that is not an object is reported.
- MCP servers (`mcpServers` in `mcp_config.json`): one item per server
  with every field (`command`, `args`, `serverUrl`, `url`, `disabled`,
  `disabledTools`, ...), sanitized, as for
  [Codex](codex.md#normalized-payloads). `env` and `headers` values are
  redacted, with names in `env_keys` and `header_keys`.
- Rules: the Markdown body as `content` (URL userinfo, query, and
  fragment removed; the home directory rewritten in user scope) and the
  frontmatter (`trigger`, `globs`, `description`), read leniently.

## Parsing

`hooks.json` and `mcp_config.json` are parsed as JSONC (comments and
trailing commas are accepted). Duplicate keys use the last value and are
reported; keys that differ only by case are reported. Nesting deeper than
64 levels, and files larger than 1 MiB, fail closed with a diagnostic.

Reads, symlink handling, limits, and diagnostics are those of the
[Claude adapter](claude.md#safe-reads). An escaping symlink at a
`.windsurf/` path or at `.windsurfrules` is reported once, by this
adapter.

## Not scanned in v0

- Workflows (`.windsurf/workflows/`, `~/.codeium/windsurf/global_workflows/`)
  and skills (`.windsurf/skills/`).
- Memories other than `global_rules.md` (`~/.codeium/windsurf/memories/`)
  and Cascade's auto-generated memories.
- Team- and enterprise-managed rules and MCP allow lists set in the
  Windsurf admin dashboard, which live server-side.
- The documented Devin Local hook locations (`.devin/hooks.v1.json`,
  hooks in `.devin/config.json` and `.devin/config.local.json`) and the
  rest of the Devin Local configuration (rules, skills, MCP,
  `~/.config/devin/config.json`). `.devin/hooks.json` is only a legacy
  compatibility read. `.devin/blueprint.yaml` is the [Devin](devin.md)
  adapter.
- Windsurf editor settings (`settings.json`, terminal auto-execution
  allow and deny lists).

## Sources

- [Cascade hooks](https://docs.windsurf.com/windsurf/cascade/hooks)
- [Cascade MCP](https://docs.windsurf.com/windsurf/cascade/mcp)
- [Cascade memories and rules](https://docs.windsurf.com/windsurf/cascade/memories)
- [Devin Local customizations](https://docs.devin.ai/desktop/devin-local/customizations)
- [Devin hooks](https://docs.devin.ai/cli/extensibility/hooks)
- [Devin desktop controls](https://docs.devin.ai/desktop/controls)
