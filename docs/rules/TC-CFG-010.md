# TC-CFG-010: Repository ships an agent plugin, which runs arbitrary code

| | |
| --- | --- |
| Severity | medium |
| Harnesses | OpenCode, Claude Code |
| Files | `opencode.json`, `opencode.jsonc`, `.opencode/plugin/*`, `.opencode/plugins/*`, `.opencode/tool/*`, `.opencode/tools/*`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.claude/settings.json` (any depth, repository scope) |
| Rule | [`rules/TC-CFG-010.yaml`](../../rules/TC-CFG-010.yaml) |

## What it detects

A plugin is code the agent loads and runs with the user's privileges.
An OpenCode plugin is a JavaScript or TypeScript module imported when
OpenCode starts. A Claude Code plugin can bring hooks, MCP servers,
agents, and commands. A repository that ships or enables one asks every
contributor's agent to run it.

Reported, once per plugin entry:

- OpenCode: each entry of `plugin` in `opencode.json` or
  `opencode.jsonc` (an npm package OpenCode installs and loads), and
  each JS/TS file directly inside `.opencode/plugin/`,
  `.opencode/plugins/`, `.opencode/tool/`, or `.opencode/tools/`.
- Claude Code: a `.claude-plugin/plugin.json` manifest, each plugin
  listed in a `.claude-plugin/marketplace.json`, and in the shared
  `.claude/settings.json` an `enabledPlugins` object with at least one
  plugin set to `true`, or a non-empty `extraKnownMarketplaces`.

Not reported:

- `.claude/settings.local.json`, which is personal.
- `enabledPlugins` entries that are all `false`, and an empty
  `extraKnownMarketplaces`.
- OpenCode files nested below a plugin or tool directory, which
  OpenCode does not load.
- User-scope plugins.

## Why medium

Scan mode reads the repository as it is. It sees that a plugin is
there, not whether a change just added it, and not what the plugin's
code does. Shipping a reviewed plugin with a project is a legitimate
use, so a plugin's presence alone does not fail a scan at the default
fail-on (high); it is listed for review. Raising an addition in a pull
request is the job of a pull-request context, which is not implemented
yet.

## Examples

Reported:

```json
{"plugin": ["opencode-acme-notify@1.2.0"]}
```

```json
{"enabledPlugins": {"formatter@acme-tools": true}}
```

Not reported:

```json
{"enabledPlugins": {"formatter@acme-tools": false}}
```

## How to fix

Review the plugin's code and what it registers (hooks, MCP servers,
commands) before you keep it. Prefer a plugin pinned to a reviewed
version or commit, and remove plugins the project does not need. To
accept a reviewed plugin, add a policy exception for this rule and
file.

## References

- [OpenCode plugins](https://opencode.ai/docs/plugins/)
- [OpenCode config](https://opencode.ai/docs/config/)
- [Claude Code plugins](https://code.claude.com/docs/en/plugins)
- [Claude Code plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
