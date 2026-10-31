# GitHub Copilot adapter

The Copilot adapter (harness `copilot`) discovers GitHub Copilot
configuration for Copilot CLI, the Copilot cloud agent, and the files
VS Code's Copilot reads from `.github/`. It never starts Copilot, runs a
hook or workflow, starts an MCP server, or invokes git. Every repository
file is treated as attacker-controlled.

Copilot also loads files other adapters report: `AGENTS.md`, shared
skills, `.vscode/mcp.json`, and `.vscode/tasks.json` ([generic](generic.md);
the VS Code files use harness `vscode`), and `.mcp.json` and
`.claude/settings.json` ([Claude](claude.md)). Session logs are not read.

## Locations

### Repository (`--scope repo`, the default)

Copilot reads `.github/` from the repository root only, so only the root
is scanned. Matching is case-insensitive.

| Location | Normalized kinds |
| --- | --- |
| `.github/hooks/*.json` | `hook`; `permissions` for `disableAllHooks` |
| `.github/copilot/settings.json`, `.github/copilot/settings.local.json` | `hook` (inline `hooks`); `permissions` for `disableAllHooks` |
| `.github/agents/*.agent.md` | `instructions` (role `agent`), plus frontmatter `hooks` and `mcp-servers` |
| `.github/copilot-instructions.md` | `instructions` (role `copilot-instructions`) |
| `.github/instructions/**/*.instructions.md` | `instructions` (role `instructions`) |
| `.github/workflows/copilot-setup-steps.yml` | `env-setup` |

### User (`--scope user`)

`$COPILOT_HOME`, default `~/.copilot`:

| Location | Normalized kinds |
| --- | --- |
| `mcp-config.json` | `mcp-server` (`mcpServers`) |
| `settings.json` | `hook` (inline `hooks`), `permissions` |
| `hooks/*.json` (at most 256) | `hook` |

`COPILOT_HOME` is handled like [`CODEX_HOME`](codex.md#user---scope-user).

### Managed (`--scope managed`)

Policy hook files, `*.json` in `/etc/github-copilot/policy.d/` (Linux,
macOS) or `%ProgramData%\GitHub\Copilot\policy.d\` (Windows), at most 256.
The Windows registry policy source
(`HKLM\Software\Policies\GitHub\Copilot`) is not read.

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, so two entries that match on the fields listed here but
differ elsewhere (two unnamed `uses: actions/github-script@v7` steps with
a different `with.script`, say) still get distinct keys and
fingerprints; see [fingerprint.md](../fingerprint.md#input). When sanitizing removed
anything from the entry, in any field (a `--token` value in
`commandWindows`, a redacted `env` value, a URL query), the key also
ends with a discriminator over all of the removed text, so entries that
differ only in what redaction replaced with `[REDACTED]` stay distinct
too.

- Hooks (`{"version": 1, "disableAllHooks": false, "hooks": {...}}`): one
  item per handler with every field (`type`, `bash`, `powershell`,
  `command`, `exec`, `args`, `cwd`, `url`, `prompt`, `timeoutSec`,
  `matcher`, `allowedEnvVars`, ...) and `event`. `env` and `headers`
  values are redacted, with names in `env_keys` and `header_keys`. A
  handler may also be a Claude-format matcher group
  (`{"matcher", "hooks": [...]}`). The key is
  `["hook", event, matcher, type, action]`, where the action is the first
  of `bash`, `powershell`, `command`, `exec`, `url`, `prompt`, `linux`,
  `osx`, `windows`. Items from a file with `disableAllHooks: true` carry
  `hooks_disabled: true`.
- Event names are kept as written. Copilot accepts camelCase
  (`preToolUse`) and PascalCase (`PreToolUse`) names and runs both, so
  case variants in a `hooks` object are not reported; exact duplicates
  are.
- Agents: frontmatter `hooks` as above, and `mcp-servers` (or
  `mcpServers`) as for [Codex](codex.md#normalized-payloads). The Markdown
  body is `content`. Both spellings are read independently: an agent that
  declares the same server name under both, with different definitions,
  gets one item per spelling, so one spelling can never shadow the other.
- `copilot-setup-steps.yml`: one item for the workflow (`on`,
  `permissions`, `env`, `defaults`), one for the `copilot-setup-steps`
  job without its steps (`runs-on`, `permissions`, `env`, `container`,
  ...), and one per step (`id`, `name`, `uses`, `run`, `with`, `env`, ...),
  keyed by the first present of `id`, `name`, `uses`, `run`, and the `run`
  script. `env` values are redacted; `with` inputs whose name looks secret
  are redacted. Other jobs are not emitted; a file with no
  `copilot-setup-steps` job gets an informational note.

## Parsing

Copilot CLI parses its JSON strictly: a byte-order mark, comments, and
trailing commas are errors. A hook file without `"version": 1` is
reported (Copilot rejects the whole file) and its hooks are still emitted.
Agent frontmatter is strict YAML because it can register hooks and
servers; instruction frontmatter (`applyTo`) is read leniently. The setup
workflow's YAML aliases and anchors are followed, as GitHub Actions
supports them, up to 100 aliases and 10,000 nodes after expansion; a
workflow whose anchors expand past either limit (an "alias bomb") is
reported and not normalized, as are merge keys, which remain unsupported.
Nesting deeper than 64 levels fails closed.

Reads, symlink handling, limits, and diagnostics are those of the
[Claude adapter](claude.md#safe-reads).

## Not scanned in v0

- The Windows registry policy source
  (`HKLM\Software\Policies\GitHub\Copilot`); only the `policy.d` file
  drop-in is read (see [Managed](#managed---scope-managed)).
- Prompt files (`.github/prompts/*.prompt.md`).
- User-level agents (`~/.copilot/agents/`).
- Plugin hooks under the plugin install directory.
- `~/.copilot/config.json` (no longer read for hooks).
- VS Code user settings, including `.vscode/settings.json`: see
  [generic.md](generic.md#not-read).

## Sources

- [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Customize the Copilot cloud agent environment](https://docs.github.com/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment)
- [Copilot cloud agent firewall](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-the-firewall)
