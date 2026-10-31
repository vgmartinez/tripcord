# Codex adapter

The Codex adapter (harness `codex`) discovers OpenAI Codex configuration
statically. It never starts Codex, runs a hook or `notify` program, starts
an MCP server, expands environment variables, or invokes git. Every
repository file is treated as attacker-controlled.

`AGENTS.md` is loaded by Codex but reported by the [generic](generic.md)
adapter; `.agents/skills` likewise, both in the repository and, at user
scope, `~/.agents/skills`. Codex's own, deprecated `~/.codex/skills` has
no other reader and is reported here. Codex session transcripts
(`~/.codex/sessions`, `history.jsonl`) are not read.

## Locations

### Repository (`--scope repo`, the default)

| Location | Normalized kinds |
| --- | --- |
| `.codex/config.toml` (any depth) | `mcp-server`, `hook`, `permissions`, `env-setup`, `plugin` |
| `.codex/hooks.json` (any depth) | `hook` |
| `AGENTS.override.md` (any depth) | `instructions` (role `agents-override`) |

Codex loads project `.codex/` layers from the project root down to the
working directory, so nested directories are scanned like the root. Path
matching is case-insensitive.

### User (`--scope user`)

`$CODEX_HOME`, default `~/.codex`:

| Location | Normalized kinds |
| --- | --- |
| `config.toml` | as above |
| `<profile>.config.toml` (at most 64) | as above |
| `hooks.json` | `hook` |
| `AGENTS.md`, `AGENTS.override.md` | `instructions` (roles `agents`, `agents-override`) |
| `skills/**/SKILL.md` | `skill` |

`skills` (`$CODEX_HOME/skills`, i.e. `~/.codex/skills` by default) is
Codex's deprecated user-skill location, kept for backward compatibility
alongside the current `~/.agents/skills` (shared with other harnesses,
reported by [generic](generic.md)). Requesting the `codex` harness
explicitly also runs `generic`, so both locations are scanned whenever
user scope is enabled.

A relative `CODEX_HOME` is reported and not scanned. A `CODEX_HOME` outside
the home directory is scanned; its paths are shown as `~/CODEX_HOME/...`,
but a blocking diagnostic is reported and the scan exits non-zero, the
same as Claude's `CLAUDE_CONFIG_DIR` outside home (see
[claude.md](claude.md)).

### Managed (`--scope managed`)

`/etc/codex/config.toml` and `/etc/codex/requirements.toml` on Linux and
macOS. Codex documents no system configuration path on Windows, so the
managed scope is empty there.

## Project trust

Codex loads a project `.codex/` layer only when the project is trusted
(`[projects."<absolute path>"] trust_level = "trusted"` in the user
`config.toml`). The adapter scans project files regardless and records
`project_trust` on every item from `.codex/config.toml` and
`.codex/hooks.json`:

| Value | Meaning |
| --- | --- |
| `trusted`, `untrusted` | The user config has an entry for the scanned root (paths compared after cleaning and resolving symlinks). |
| `unset` | The user config was read and has no entry, or does not exist. Codex asks before loading the layer. |
| `unknown` | User scope was not scanned (the default), or the user config could not be parsed. |

Codex also trusts hooks by hash. Where it stores those hashes is not
documented, so hook trust is not determined.

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, so two entries that match on the fields listed here but
differ elsewhere (a second hook with the same command but a different
`commandWindows`, say) still get distinct keys and fingerprints; see
[fingerprint.md](../fingerprint.md#input).

- MCP servers (`[mcp_servers.<name>]`): every field, sanitized. Values of
  `env`, `http_headers`, and `env_http_headers` are redacted when they look
  secret; their names are kept in `<field>_keys`. `bearer_token_env_var`
  names a variable and is kept. URLs lose userinfo, query, and fragment;
  the key is `["mcp", name]` plus a discriminator when that removed text.
- Hooks, from `hooks.json` (`{"description", "hooks": {...}}`) or the
  inline `[hooks]` table: one item per handler with every field, `event`,
  and `matcher`. The key is `["hook", event, matcher, type, action]`,
  where the action is the first of `command`, `commandWindows`,
  `command_windows`, `url`, `prompt`, `agent`, or the canonical JSON of an
  `mcp_tool` handler. Non-array members of `[hooks]` (`managed_dir`,
  `windows_managed_dir`, ...) become `permissions` settings named
  `hooks.<name>`.
- Settings: one item per present key, `{"setting", "value"}`, key
  `["setting", name]`:
  - `permissions`: `sandbox_mode`, `sandbox_workspace_write`,
    `approval_policy`, `approvals_reviewer`, `default_permissions`,
    `permissions`, `features`, `web_search`, `tools`, `windows`,
    `allow_managed_hooks_only`, `allowed_sandbox_modes`,
    `allowed_approval_policies`, `allowed_permission_profiles`,
    `experimental_network`, `remote_sandbox_config`
  - `env-setup`: `shell_environment_policy`, `notify`, `model_providers`,
    `model_provider`, `apps_mcp_product_sku`, `openai_base_url`,
    `chatgpt_base_url`, `experimental_realtime_ws_base_url`, `otel`
  - `plugin`: `plugins`, `marketplaces`
  - `permissions`: also `profile` (the active configuration profile name)
  - `instructions`: `project_doc_fallback_filenames`,
    `model_instructions_file`, `experimental_instructions_file` (the
    deprecated spelling of `model_instructions_file`) — these pick the
    file Codex loads as project instructions instead of `AGENTS.md`, and,
    unlike the keys below, Codex does honor them from a trusted project's
    own `.codex/config.toml`
- Profiles: one `permissions` item per `[profiles.<name>]`, key
  `["setting", "profiles", name]`.
- Keys Codex ignores in a project config (`openai_base_url`,
  `chatgpt_base_url`, `apps_mcp_product_sku`, `model_provider(s)`,
  `notify`, `profile(s)`, `experimental_realtime_ws_base_url`, `otel`) are
  still emitted from the repository with `ignored_in_project: true`.

Other keys are not emitted. The list was reviewed against the
configuration reference on 2026-10-31.

## Parsing

- TOML is decoded with `github.com/pelletier/go-toml/v2` (MIT). A
  byte-order mark is rejected. Duplicate keys and tables are TOML errors.
  Keys that differ only by case (`[mcp_servers.Docs]` and
  `[mcp_servers.docs]`) are reported, because Codex reads exact names.
- `hooks.json` is strict JSON: no byte-order mark, comments, or trailing
  commas. Duplicate keys use the last value and are reported, as are case
  variants. A file with no `hooks` object but other top-level members is
  reported.
- Nesting deeper than 64 levels fails closed.

Reads, symlink handling, limits, and diagnostics are those of the
[Claude adapter](claude.md#safe-reads): a `.codex` symlink that resolves
outside the repository is reported ("Codex may load its target, which was
not scanned").

## Not scanned in v0

- Codex session transcripts (`~/.codex/sessions`, `history.jsonl`).
- Hook trust by content hash: Codex also trusts hooks by hash, but where
  it stores those hashes is not documented, so this adapter cannot
  determine hook trust by hash (see [Project trust](#project-trust)).

## Sources

- [Codex hooks](https://developers.openai.com/codex/hooks)
- [Codex configuration reference](https://developers.openai.com/codex/config-reference)
- [Codex config basics](https://learn.chatgpt.com/docs/config-file/config-basic.md)
