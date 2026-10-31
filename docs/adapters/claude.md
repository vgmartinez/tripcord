# Claude Code adapter

The Claude Code adapter discovers configuration statically. It never starts
Claude Code, runs a hook, starts an MCP server, expands environment variables,
or follows a symlink.

`tripcord scan` autodetects Claude Code when the repository contains one of:

- `.claude/settings.json` or `.claude/settings.local.json`
- `.mcp.json`
- `CLAUDE.md`
- a file in `.claude/rules/`, `.claude/skills/`, or `.claude/plugins/`

The repository inputs are normalized into `ConfigItem` values:

| Source | Normalized kinds |
| --- | --- |
| Settings files | `hook`, `permissions`, `mcp-server`, `env-setup` |
| `.mcp.json` | `mcp-server` |
| `CLAUDE.md`, rules | `instructions` with raw content |
| `SKILL.md` | `skill` with raw content, plus `hook` entries from YAML frontmatter |
| Plugin `hooks/hooks.json` | `hook` |

Hooks carry `event`, `matcher`, and `command`; MCP server payloads preserve
their name, command, args, env keys, and URL. `permissions` preserves allow,
deny, and `defaultMode`. `env-setup` preserves `env` and `apiKeyHelper`.
Entries use the model's stable `claude:<scope>:<path>` config ID. Hook keys
derive from `matcher|command`, and MCP keys derive from the server name, as
defined in [fingerprint.md](../fingerprint.md).

## Scopes

The CLI scans only repository scope by default. It never reads `~/` or
machine-managed files implicitly. The adapter supports injectable user and
managed paths for callers and tests:

- user: `~/.claude/settings.json` and `~/.claude.json`
- managed: `/etc/claude-code/managed-settings.json` (Linux),
  `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS),
  and `C:/ProgramData/ClaudeCode/managed-settings.json` (Windows)

There is no CLI scope-selection flag yet; adding one needs an explicit product
decision about consent and output handling.

## Parsing and limits

Claude Code documents settings as strict JSON: comments and trailing commas are
syntax errors. The adapter therefore rejects them instead of accepting a
different language than Claude Code. Each file is capped at 1 MiB. An invalid
or oversized configuration returns a configuration error without executing
any input. Repository symlinks are skipped so discovery cannot leave the
repository tree.
