# Cursor adapter

The Cursor adapter (harness `cursor`) discovers Cursor configuration
statically. It never starts Cursor, runs a hook, starts an MCP server, or
invokes git. Every repository file is treated as attacker-controlled.

Cursor also loads `AGENTS.md` and `.vscode/` files (reported by the
[generic](generic.md) adapter) and Claude Code hooks from
`.claude/settings.json` (reported by the [Claude](claude.md) adapter).
Agent transcripts are not read.

## Locations

### Repository (`--scope repo`, the default)

| Location | Normalized kinds |
| --- | --- |
| `.cursor/hooks.json` | `hook` |
| `.cursor/mcp.json` | `mcp-server` |
| `.cursor/rules/**/*.mdc`, `.cursor/rules/**/*.md` | `instructions` (role `rule`) |
| `.cursorrules` (legacy) | `instructions` (role `cursorrules`) |
| `.cursor/environment.json` (cloud agents) | `env-setup` |

All are matched at any depth and case-insensitively. Cursor runs project
hooks in any trusted workspace; Cursor cloud agents run the repository's
`.cursor/hooks.json` command hooks.

### User (`--scope user`)

`~/.cursor/hooks.json` and `~/.cursor/mcp.json`. Cursor documents no
variable that moves this directory. User hooks do not run in cloud agents.

### Managed (`--scope managed`)

The enterprise (MDM) hooks file:

| OS | Path |
| --- | --- |
| macOS | `/Library/Application Support/Cursor/hooks.json` |
| Linux, WSL | `/etc/cursor/hooks.json` |
| Windows | `%ProgramData%\Cursor\hooks.json` (default `C:\ProgramData`) |

Team hooks distributed from the dashboard are a separate mechanism; see
[Not scanned in v0](#not-scanned-in-v0).

## Not scanned in v0

- The Dockerfile named by `.cursor/environment.json` `build` (for example
  `.cursor/Dockerfile`). `build` is reported as an `env-setup` item, but
  the Dockerfile it names is not read, so its `RUN` instructions are not
  scanned. Reading that Dockerfile is planned for v0.1
  ([#32](https://github.com/vgmartinez/tripcord/issues/32)).
- Team hooks distributed from the Cursor dashboard
  (`~/.cursor/managed/team_*/hooks/`): these are scripts, not a
  `hooks.json`, and are not read.
- Agent transcripts.
- `.vscode/settings.json` (`task.allowAutomaticTasks`,
  `chat.tools.autoApprove`), which several Cursor surfaces also honor:
  see [generic.md](generic.md#not-read).

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, so two entries that match on the fields listed here but
differ elsewhere (two terminals with the same name and command but a
different `env.NODE_OPTIONS`, say) still get distinct keys and
fingerprints; see [fingerprint.md](../fingerprint.md#input). When sanitizing removed
anything from the entry, in any field (a `--token` value in
`commandWindows`, a redacted `env` value, a URL query), the key also
ends with a [secret discriminator](../fingerprint.md#secret-discriminator) (`sig:k1:` with a fingerprint
key, `sig:s1:` without one), so entries that differ only in what
redaction replaced with `[REDACTED]` stay distinct too.

- Hooks (`{"version": 1, "hooks": {"<event>": [{handler}, ...]}}`): one
  item per handler with every field (`command`, `type`, `prompt`, `model`,
  `matcher`, `timeout`, `failClosed`, `loop_limit`, ...) and `event`. The
  key is `["hook", event, matcher, type, action]`, where the action is
  `command` or, for a prompt hook, `prompt`. All events are accepted, including the
  documented `sessionStart`, `sessionEnd`, `preToolUse`, `postToolUse`,
  `postToolUseFailure`, `subagentStart`, `subagentStop`,
  `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`,
  `afterMCPExecution`, `beforeReadFile`, `afterFileEdit`,
  `beforeSubmitPrompt`, `preCompact`, `stop`, `afterAgentResponse`,
  `afterAgentThought`, `beforeTabFileRead`, `afterTabFileEdit`, and
  `workspaceOpen`.
- MCP servers (`mcpServers`): as for [Codex](codex.md#normalized-payloads).
- Rules: the Markdown body as `content` and the frontmatter
  (`description`, `globs`, `alwaysApply`, ...). Cursor parses rule
  frontmatter leniently (for example an unquoted `globs: *.ts`), so
  frontmatter that is not valid YAML is read as `key: value` lines without
  a diagnostic.
- `environment.json`: one `env-setup` item per top-level member
  (`install`, `start`, `build`, `snapshot`, ...), `{"setting", "value"}`,
  and one per entry of `terminals` (`name`, `command`, ...).

## Parsing

Cursor's JSON files are parsed as JSONC: a byte-order mark, comments, and
trailing commas are accepted. A `hooks.json` without a positive integer
`version` is reported and its hooks are still emitted. Duplicate keys use
the last value and are reported; keys that differ only by case are
reported. Nesting deeper than 64 levels fails closed.

Reads, symlink handling, limits, and diagnostics are those of the
[Claude adapter](claude.md#safe-reads).

## Sources

- [Cursor hooks](https://cursor.com/docs/hooks)
- [Cursor cloud agent setup](https://cursor.com/docs/cloud-agent/setup)
