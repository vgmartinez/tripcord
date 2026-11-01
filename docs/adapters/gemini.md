# Gemini CLI adapter

The Gemini CLI adapter (harness `gemini`) discovers Gemini CLI
configuration statically. It never starts Gemini CLI, runs a hook or a
tool discovery command, starts an MCP server, expands environment
variables, or invokes git. Every repository file is treated as
attacker-controlled.

Gemini CLI can also be pointed at `AGENTS.md` (`context.fileName`) and
reads shared skills; both are reported by the [generic](generic.md)
adapter, which `--harness gemini` also runs. Session files
(`~/.gemini/tmp/<project_hash>/chats/`) are not read.

## Locations

### Repository (`--scope repo`, the default)

| Location | Normalized kinds |
| --- | --- |
| `.gemini/settings.json` (any depth) | `mcp-server`, `hook`, `permissions`, `env-setup`, `instructions`, `plugin` |
| `GEMINI.md` (any depth) | `instructions` (role `gemini`) |

Gemini CLI reads workspace settings from `.gemini/` in the directory it
starts in, and loads `GEMINI.md` from every directory between the project
root and the working directory, so both are matched at any depth. Path
matching is case-insensitive. Gemini CLI applies workspace settings only
in a trusted folder when folder trust is enabled; that decision lives in
the user's trust store, which is not read, so workspace items carry no
trust status.

### User (`--scope user`)

`$GEMINI_CLI_HOME/.gemini`, default `~/.gemini`:

| Location | Normalized kinds |
| --- | --- |
| `settings.json` | as above |
| `GEMINI.md` | `instructions` (role `gemini`) |

`GEMINI_CLI_HOME` replaces the home directory Gemini CLI puts `.gemini`
under, and is handled like [`CODEX_HOME`](codex.md#user---scope-user): a
relative value is reported and not scanned; a value outside the home
directory is scanned, its paths are shown as `~/GEMINI_CLI_HOME/.gemini/...`,
and a blocking diagnostic makes the scan exit non-zero.

### Managed (`--scope managed`)

The system settings directory:

| OS | Path |
| --- | --- |
| macOS | `/Library/Application Support/GeminiCli/` |
| Linux | `/etc/gemini-cli/` |
| Windows | `%ProgramData%\gemini-cli\` (default `C:\ProgramData`) |

`settings.json` (overrides every other layer) and `system-defaults.json`
(overridden by every other layer) are read with the same normalization.
`GEMINI_CLI_SYSTEM_SETTINGS_PATH` and `GEMINI_CLI_SYSTEM_DEFAULTS_PATH`
move either file; a relative value is reported and that file is not
scanned.

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, so two entries that match on the fields listed here but
differ elsewhere still get distinct keys and fingerprints; see
[fingerprint.md](../fingerprint.md#input). When sanitizing removed
anything from the entry (a `--api-key` value in `args`, a redacted `env`
value, a URL query), the key also ends with a [secret discriminator](../fingerprint.md#secret-discriminator)
(`sig:k1:` with a fingerprint key, `sig:s1:` without one), so entries
that differ only in what redaction replaced with `[REDACTED]` stay
distinct too.

- MCP servers (`mcpServers`): one item per server with every field
  (`command`, `args`, `cwd`, `url`, `httpUrl`, `trust`, `includeTools`,
  `excludeTools`, `timeout`, ...), sanitized, as for
  [Codex](codex.md#normalized-payloads). `env` and `headers` values are
  redacted, with names in `env_keys` and `header_keys`. `trust: true`
  (no confirmation for the server's tools) is kept as written.
- Hooks: see [Hook schema](#hook-schema).
- Settings: one `{"setting", "value"}` item per present key of a curated
  list, the value sanitized and secret-looking members redacted. Both the
  nested schema and the older flat keys are read, because a file that
  predates Gemini CLI's settings migration can still carry the flat form:

  | Kind | Keys |
  | --- | --- |
  | `permissions` | `hooksConfig`, `tools`, `security`, `general`, `mcp`, `sandbox`, `coreTools`, `excludeTools`, `allowedTools`, `autoAccept`, `allowMCPServers`, `excludeMCPServers`, `folderTrust`, `folderTrustFeature` |
  | `env-setup` | `toolDiscoveryCommand`, `toolCallCommand`, `mcpServerCommand`, `telemetry`, `advanced`, `excludedProjectEnvVars`, `experimental` |
  | `instructions` | `context`, `contextFileName` (which file supplies the model's context) |
  | `plugin` | `extensions` |

  Other keys (`ui`, `model`, `$schema`, ...) are not emitted.
- `GEMINI.md`: the Markdown body as `content` (URL userinfo, query, and
  fragment removed; the home directory rewritten in user scope) and any
  frontmatter, read leniently. `@path` imports are not followed.

## Hook schema

The documented shape is:

```json
{"hooks": {"BeforeTool": [{"matcher": "run_shell_command", "sequential": true,
  "hooks": [{"type": "command", "command": "./guard.sh", "name": "guard", "timeout": 5000}]}]}}
```

- A matcher group with a `hooks` array yields one `hook` item per handler,
  with every handler field sanitized, `event`, `matcher`, and the group's
  `sequential` flag as `group_sequential`. The key is
  `["hook", event, matcher, type, command]`.
- `command` is the only documented handler type. A handler whose `type`
  is missing or is anything else is still emitted, and a blocking
  diagnostic is reported.
- An entry or handler of any other shape (a flat handler without a
  `hooks` array, a non-string `matcher`, a non-object entry, a `hooks`
  value that is not an object) is emitted whole as one opaque `hook` item,
  `{"event", "opaque": true, "value"}`, sanitized, keyed
  `["hook", event, "opaque"]`, and reported, so the scan exits non-zero.
- A non-array member of `hooks` (an inline flag from an older release) is
  emitted as a `permissions` setting named `hooks.<member>`.

`hooksConfig` is its own `permissions` setting. `hooksConfig.enabled`
set to false turns hooks off in that file and produces an informational
note while the hooks remain reported. `hooksConfig.disabled` is an array
of hook names: Gemini CLI matches a handler by its `name`, or by its
`command` when `name` is absent. An event name in the list does not
match. Each matching handler is still reported, with an informational
note that names it; the note is redacted. A higher-precedence settings
file can re-enable either form, so hook items are not marked disabled
and are not dropped.

## Parsing

Gemini CLI strips comments from `settings.json` before `JSON.parse`, so
the file is parsed as JSONC. A trailing comma, which `JSON.parse`
rejects, is reported as an informational note and the file is still
normalized rather than skipped. Duplicate keys use the last value and are
reported; keys that
differ only by case are reported. Nesting deeper than 64 levels, and files
larger than 1 MiB, fail closed with a diagnostic.

Reads, symlink handling, limits, and diagnostics are those of the
[Claude adapter](claude.md#safe-reads). An escaping symlink at a
`.gemini/` path or at `GEMINI.md` is reported once, by this adapter.

## Not scanned in v0

- Custom commands (`.gemini/commands/**/*.toml`, `~/.gemini/commands/`),
  whose prompts can run `!{shell}` snippets when invoked.
- Extensions (`~/.gemini/extensions/*/gemini-extension.json` and their
  bundled MCP servers and context files).
- `.gemini/.env` and `~/.gemini/.env`, which Gemini CLI loads into its
  environment.
- The system prompt override (`.gemini/system.md`, `GEMINI_SYSTEM_MD`).
- The folder trust store (`~/.gemini/trustedFolders.json`).
- Session files under `~/.gemini/tmp/`.
- `@path` imports inside `GEMINI.md`.

## Sources

- [Gemini CLI hooks reference](https://geminicli.com/docs/hooks/reference/)
- [Gemini CLI configuration](https://geminicli.com/docs/get-started/configuration/)
- [Gemini CLI session management](https://geminicli.com/docs/cli/session-management.md)
