# OpenCode adapter

The OpenCode adapter (harness `opencode`) discovers OpenCode configuration
statically. It never starts OpenCode, loads a plugin or custom tool,
installs an npm package, starts an MCP server, expands `{env:...}` or
`{file:...}` placeholders, or invokes git. Every repository file is
treated as attacker-controlled.

OpenCode also loads `AGENTS.md` and shared skills, which are reported by
the [generic](generic.md) adapter, and falls back to `CLAUDE.md` and
`.claude/skills`, which are reported by the [Claude](claude.md) adapter;
`--harness opencode` runs both.

## Locations

### Repository (`--scope repo`, the default)

| Location | Normalized kinds |
| --- | --- |
| `opencode.json`, `opencode.jsonc` (any depth) | `mcp-server`, `plugin`, `instructions`, `permissions`, `env-setup` |
| `.opencode/opencode.json`, `.opencode/opencode.jsonc` | as above |
| `.opencode/agents/**/*.md`, `.opencode/agent/**/*.md` | `instructions` (role `agent`) |
| `.opencode/commands/**/*.md`, `.opencode/command/**/*.md` | `instructions` (role `command`) |
| `.opencode/plugins/*.{js,ts,...}`, `.opencode/plugin/*` | `plugin` (role `plugin`, executable) |
| `.opencode/tools/*.{js,ts,...}`, `.opencode/tool/*` | `plugin` (role `tool`, executable) |

OpenCode looks for its config from the working directory up to the Git
root, so config files and `.opencode/` are matched at any depth. Both the
plural directory names and the older singular ones are read. Plugin and
tool files are the `.js`, `.ts`, `.mjs`, `.cjs`, `.mts`, `.cts`, `.jsx`,
and `.tsx` files directly inside the directory. A code file in a
subdirectory is a helper module: it is not reported as executable
configuration, and an informational note names it. `node_modules/` is
skipped. Path
matching is case-insensitive. `AGENTS.md`, inside `.opencode/` or
anywhere else in the repository, belongs to the generic adapter.

### User (`--scope user`)

| Location | Normalized kinds |
| --- | --- |
| `$XDG_CONFIG_HOME/opencode/` (default `~/.config/opencode/`) | as for `.opencode/`, plus `config.json` and `AGENTS.md` (role `agents`, OpenCode's global rules) |
| `$OPENCODE_CONFIG` (one config file) | config kinds |
| `$OPENCODE_CONFIG_DIR/` | as for `.opencode/` |
| `$XDG_DATA_HOME/opencode/auth.json`, `mcp-auth.json` (default `~/.local/share/opencode/`) | `env-setup` (credential reference) |

In user directories the agent and command trees are walked; plugin and
tool directories are listed (at most 256 files each) instead, because
OpenCode installs plugin dependencies under the config directory.

`OPENCODE_CONFIG` (its directory) and `OPENCODE_CONFIG_DIR` are handled
like [`CODEX_HOME`](codex.md#user---scope-user): a relative value is
reported and not scanned; a value outside the home directory is scanned,
its paths are shown as `~/<VAR>/...`, and a blocking diagnostic makes the
scan exit non-zero.

`XDG_CONFIG_HOME` and `XDG_DATA_HOME` follow the freedesktop
base-directory spec instead, because they relocate configuration for
every program and are not OpenCode-specific. A relative value is invalid
and ignored, and the default (`~/.config`, `~/.local/share`) is used. An
absolute value outside the home directory is scanned and shown as
`~/XDG_CONFIG_HOME/...` or `~/XDG_DATA_HOME/...`, with an informational
note that does not by itself make the scan exit non-zero.

### Managed (`--scope managed`)

`opencode.json` and `opencode.jsonc` in the managed config directory:

| OS | Path |
| --- | --- |
| macOS | `/Library/Application Support/opencode/` |
| Linux | `/etc/opencode/` |
| Windows | `%ProgramData%\opencode\` (default `C:\ProgramData`) |

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, and, when sanitizing removed anything, a discriminator
over the removed text; see [fingerprint.md](../fingerprint.md#input).

- MCP servers (`mcp`): one item per server with every field (`type`,
  `command`, `url`, `enabled`, `timeout`, `oauth`, ...), sanitized.
  A local server's `command` is an argv array; it is sanitized element by
  element and tool-specific credential flags (`docker login -p X`) are
  redacted with the shared tool-flag table. `environment` and `headers`
  values are redacted, with names in `env_keys` and `header_keys`. Key
  `["mcp", name]`.
- npm plugins (`plugin`): one `plugin` item per specifier,
  `{"setting": "plugin", "plugin"}`, key `["plugin", specifier]`.
  OpenCode installs and runs these at startup. A value that is not an
  array of strings is emitted whole and reported.
- Inline agents (`agent`, and the older `mode`) and commands (`command`):
  one `instructions` item per name, `{"setting", "role", "name", "value"}`,
  the value sanitized whole (prompt, model, per-agent `tools` and
  `permission` overrides). Key `[setting, name]`.
- Settings: one `{"setting", "value"}` item per present key:

  | Kind | Keys |
  | --- | --- |
  | `permissions` | `permission`, `tools`, `share`, `autoupdate` |
  | `instructions` | `instructions` (extra instruction files and globs) |
  | `env-setup` | `formatter`, `lsp`, `provider`, `experimental` (formatter and LSP entries run commands) |

  Other keys (`$schema`, `theme`, `model`, `keybinds`, ...) are not
  emitted.
- Agent and command Markdown files: the body as `content` and the
  frontmatter, sanitized. Agent frontmatter can grant tools and
  permissions, so it is parsed strictly and a malformed block is
  reported; command frontmatter is read leniently.
- Plugin and tool files: `{"role", "name", "language", "executable":
  true}`, key `[role, file name]`. The code is never parsed or copied into
  the item; the item's `sha256` is the file's digest, so a reviewer can
  pin a reviewed version.
- Credential files: `{"setting": "credentials", "file", "secret_bearing":
  true, "value": "[REDACTED]"}`, key `["credentials", file name]`. The file
  is never opened: only its existence is checked, and the item's `sha256`
  is the digest of empty input, so neither the secret nor a hash of it
  leaves the machine.

## Parsing

OpenCode reads both `opencode.json` and `opencode.jsonc` as JSONC, so
both accept comments and trailing commas. Duplicate keys use the last
value and are reported; keys that differ only by case are reported.
Nesting deeper than 64 levels, and files larger than 1 MiB, fail closed
with a diagnostic.

Reads, symlink handling, limits, and diagnostics are those of the
[Claude adapter](claude.md#safe-reads). An escaping symlink at a path
this adapter reads is reported once, by this adapter.

## Not scanned in v0

- The contents of `OPENCODE_CONFIG_CONTENT` (inline config in the
  environment). When the variable is set, an informational note says it
  was not scanned. Remote organization config (`.well-known/opencode`)
  is not read either.
- macOS managed preferences (`.mobileconfig` / `ai.opencode.managed`).
- Skills under `.opencode/skills/` and `~/.config/opencode/skills/`.
- Modes (`.opencode/modes/`) and themes.
- Files referenced from `instructions` or by `{file:...}`, and the
  `package.json` next to plugins. Nested helper modules are noted, not
  parsed.
- The contents of `auth.json` and `mcp-auth.json` (by design).

## Sources

- [OpenCode config](https://opencode.ai/docs/config/)
- [OpenCode plugins](https://opencode.ai/docs/plugins/)
- [OpenCode MCP servers](https://opencode.ai/docs/mcp-servers/)
- [OpenCode agents](https://opencode.ai/docs/agents/)
