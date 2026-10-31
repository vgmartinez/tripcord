# Shared-files adapter

Some files are read by more than one coding agent. Each is reported once,
by one owner adapter, so its items and fingerprints do not depend on which
harnesses a scan selected. The generic adapter owns the files no single
product owns:

| Location | Harness | Normalized kinds |
| --- | --- | --- |
| `.agents/skills/**/SKILL.md`, `.github/skills/**/SKILL.md` (repository) | `generic` | `skill`, plus frontmatter `hooks` and `mcpServers` |
| `~/.agents/skills/**/SKILL.md` (`--scope user`) | `generic` | `skill`, plus frontmatter `hooks` and `mcpServers` |
| `AGENTS.md` (any depth, any case) | `generic` | `instructions` (role `agents`) |
| `.vscode/tasks.json` (any depth) | `vscode` | `task` per task; `env-setup` for file-level `options` and `windows`/`linux`/`osx` |
| `.vscode/mcp.json` (any depth) | `vscode` | `mcp-server` per entry of `servers` |

Claude Code's own `.claude/skills/` files stay on the Claude adapter. See
[claude.md](claude.md). Codex's own, deprecated `~/.codex/skills` stays on
the [Codex adapter](codex.md), since nothing else reads it.

## Ownership

| File | Owner | Also loaded by |
| --- | --- | --- |
| `AGENTS.md` | generic | Codex, Cursor, Copilot, OpenCode, Windsurf, Gemini CLI (via `context.fileName`), and Jules |
| `.agents/skills`, `.github/skills` | generic | Codex, Copilot, Claude Code, OpenCode, Gemini CLI |
| `~/.agents/skills` | generic | Codex |
| `.vscode/tasks.json`, `.vscode/mcp.json` | generic (harness `vscode`) | VS Code with Copilot, Cursor, Windsurf |
| `.devin/hooks.json`, `.windsurf/hooks.json` | windsurf | Devin Local (`.devin/hooks.json` takes priority) |
| `.mcp.json` | claude | Copilot CLI |
| `.claude/settings.json`, `.claude/settings.local.json` | claude | Copilot CLI and Cursor (third-party hooks) |
| `CLAUDE.md`, `.claude/skills` | claude | OpenCode (fallback) |
| `.devcontainer/devcontainer.json` | devcontainer | Codespaces, Copilot cloud agents, VS Code, Cursor |
| `AGENTS.override.md` | codex | none |

`tripcord scan --harness codex|cursor|copilot|gemini|opencode|windsurf` also runs the owners of the
files that harness loads, and prints an informational note naming them.
`AGENTS.md` therefore appears once, as `generic:repo:AGENTS.md`, in every
scan that reads it.

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, so two entries that match on the fields listed here but
differ elsewhere (two tasks with the same label and command but
different `args`, say) still get distinct keys and fingerprints; see
[fingerprint.md](../fingerprint.md#input). When sanitizing removed
anything from the entry, in any field (a `--token` value in
`commandWindows`, a redacted `env` value, a URL query), the key also
ends with a discriminator over all of the removed text, so entries that
differ only in what redaction replaced with `[REDACTED]` stay distinct
too.

- `AGENTS.md`: the Markdown body as `content` (URL userinfo, query, and
  fragment removed) and any frontmatter. Frontmatter that is not valid YAML
  is read as `key: value` lines without a diagnostic, because agents treat
  `AGENTS.md` as plain Markdown.
- Tasks: every task field, sanitized; `options.env` values redacted with
  names kept in `env_keys`; `label` (falling back to `taskName` and then the
  npm `script`); `run_on`, the `runOptions.runOn` value (`default` when
  absent); and `folder_open`, true when VS Code starts the task as the
  folder opens. The key is `["task", label, command]`.
- MCP servers: every field, sanitized; `env`, `headers` values redacted.
  `inputs` only declare prompts and are not emitted. A top-level
  `mcpServers` member is not read: VS Code reads `servers`.

`tasks.json` and `mcp.json` are parsed as JSONC, as VS Code does: a
byte-order mark, comments, and trailing commas are accepted. Duplicate keys
and keys that differ only by case are reported, because VS Code reads exact
key names.

## Reads and limits

The adapter uses the shared safe reader: in-repository symlinks are
followed, a symlink that leaves the repository is reported, and special
files are not read. Matching of `AGENTS.md` and `.vscode/` paths is
case-insensitive, because macOS and Windows resolve case variants to the
same file. Limits match the Claude adapter. `tripcord scan` selects it by
autodetection, or with `--harness generic`. `--scope managed` skips it:
nothing shared is read from a managed location. `--scope user` reads only
`~/.agents/skills`; a missing directory is skipped silently, like any
other optional user-scope location.

## Not read

`.vscode/settings.json` (for example `task.allowAutomaticTasks`, which
decides whether `folderOpen` tasks start without a prompt, and
`chat.tools.autoApprove`), `.code-workspace` files, and VS Code user
settings and profiles.
