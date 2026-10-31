# Claude Code adapter

The Claude Code adapter discovers configuration statically. It never starts
Claude Code, runs a hook or helper, starts an MCP server, expands environment
variables, contacts a marketplace, or invokes git or any other external
binary. Every repository file is treated as attacker-controlled.

## Autodetection

`tripcord scan` autodetects Claude Code when the repository contains any file
the adapter would read (see below), for example `CLAUDE.md` at any depth,
`.claude/settings.json`, `.mcp.json`, a file under `.claude/agents/`, a
`SKILL.md` under `.claude/skills/`, or `.claude-plugin/plugin.json`.
`.agents/skills/` and `.github/skills/` are the [generic](generic.md)
adapter, not Claude.

## Scopes and locations

The CLI scans only repository scope. It never reads the home directory or
machine-managed files. There is no CLI scope-selection flag yet; adding one
needs a product decision about consent and output handling. The adapter
supports user and managed scope for library callers and tests.

### Repository

The whole repository tree is walked (sorted, `.git` skipped), so nested
directories are covered the same way as the root:

| Location | Normalized kinds |
| --- | --- |
| `.claude/settings.json`, `.claude/settings.local.json` (any depth) | `hook`, `permissions`, `plugin`, `mcp-server`, `env-setup` |
| `.mcp.json` (any depth) | `mcp-server` |
| `CLAUDE.md`, `CLAUDE.local.md` (any depth, including `.claude/CLAUDE.md`) | `instructions` |
| `.claude/rules/**/*.md` | `instructions` (role `rule`) |
| `.claude/agents/**/*.md` | `instructions` (role `agent`), plus frontmatter `hooks` and `mcpServers` |
| `.claude/commands/**/*.md` | `instructions` (role `command`), plus frontmatter `hooks` and `mcpServers` |
| `SKILL.md` under `.claude/skills/` | `skill`, plus frontmatter `hooks` and `mcpServers` |
| `.claude-plugin/marketplace.json` | `plugin` per entry; relative `source` paths (with `metadata.pluginRoot`) become plugin roots |
| `<plugin>/.claude-plugin/plugin.json` | `plugin`; inline or referenced `hooks` and `mcpServers` |
| `<plugin>/hooks/hooks.json`, `<plugin>/.mcp.json` | `hook`, `mcp-server` |
| `<plugin>/skills`, `<plugin>/agents`, `<plugin>/commands` | as above |

`hooks/hooks.json` is read only inside a plugin root, that is a directory
with `.claude-plugin/plugin.json` or a relative marketplace source. Plugin
`hooks.json` must use the `{"hooks": {...}}` wrapper. A missing wrapper or
any other shape is a diagnostic, so the scan exits 3; it is never skipped
silently. Plugin path references
that are absolute or contain `..` are reported and not read. Remote
marketplace sources are recorded but never fetched.

### User

- `~/.claude/settings.json` and `~/.claude.json`. `~/.claude` may be a
  symlink (for example a stow-managed dotfiles directory).
- `CLAUDE_CONFIG_DIR` relocates both files. A relative path is reported and
  not scanned. An absolute path outside the home directory is still scanned;
  its paths are shown as `~/CLAUDE_CONFIG_DIR/...` and the diagnostic makes
  the scan exit non-zero. The absolute path is not displayed.
- From `~/.claude.json`, only `mcpServers` and `projects.<path>.mcpServers`
  are kept; the rest (history, caches) is skipped while streaming. The file
  may be up to 256 MiB. Project paths under the home directory are rewritten
  as `~/...`.
- Diagnostics use `~`, never the absolute home directory.

### Managed

| OS | Directory |
| --- | --- |
| Linux | `/etc/claude-code` |
| macOS | `/Library/Application Support/ClaudeCode` |
| Windows | `C:\Program Files\ClaudeCode` |

The adapter reads `managed-settings.json`, `managed-mcp.json`, and
`managed-settings.d/*.json` (sorted, at most 256 drop-ins). A missing managed
directory is skipped silently. The legacy Windows location `C:\ProgramData\ClaudeCode` is not read. When
that directory exists, scan prints an informational diagnostic to stderr.
The note does not change the exit code and is not written into the report.

### Precedence

Claude Code applies settings in the order managed > command-line
`--settings` > local (`settings.local.json`) > project (`settings.json`) >
user. The adapter does not merge scopes or nested directories: every file is
emitted as its own items, with the scope and path in the `ConfigRef` ID, so
rules see every source that Claude Code might load.

## Not scanned in v0

Claude Code can load configuration from places this adapter does not read.
A clean scan says nothing about them:

- User-scope files other than `~/.claude/settings.json` and
  `~/.claude.json`: `~/.claude/CLAUDE.md`, and `~/.claude/agents`,
  `commands`, `skills`, `rules`, and `output-styles`.
- Installed plugins and marketplaces under `~/.claude/plugins`, and any
  remote marketplace or plugin source (recorded, never fetched).
- In `~/.claude.json`, everything except `mcpServers` and
  `projects.<path>.mcpServers`, such as a project's `allowedTools` or its
  accepted-trust flag.
- Session-only configuration: the `--settings`, `--mcp-config`,
  `--agents`, `--allowedTools`, and `--permission-mode` command-line flags,
  and environment variables other than `CLAUDE_CONFIG_DIR` (for example
  `ANTHROPIC_BASE_URL` or `CLAUDE_CODE_*`).
- Settings keys outside the curated list in
  [Normalized payloads](#normalized-payloads).
- What a configuration entry points at: the script a hook or
  `apiKeyHelper` runs, a file pulled into `CLAUDE.md` with an `@path`
  import, or the code of an MCP server. Only the entry itself is reported.
- Values that only exist after expansion: `${VAR}` in `.mcp.json` and
  `$VAR` in a hook command are kept as written, never expanded.
- The legacy managed directory `C:\ProgramData\ClaudeCode` (see
  [Managed](#managed)).

## Normalized payloads

Hooks keep every field (`type`, `command`, `url`, `headers`, `mcp_tool`,
`prompt`, `agent`, `timeout`, and any future fields), plus `event` and
`matcher`. Settings that can execute code or reach the network become
`setting` items with the raw value and, where applicable, the `command`:

- `permissions`: `permissions`, `sandbox`, `disableAllHooks`,
  `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `allowedMcpServers`,
  `deniedMcpServers`, `enableAllProjectMcpServers`, `enabledMcpjsonServers`,
  `disabledMcpjsonServers`, `strictKnownMarketplaces`
- `plugin`: `enabledPlugins`, `extraKnownMarketplaces`
- `env-setup`: `env`, `apiKeyHelper`, `statusLine`, `subagentStatusLine`,
  `otelHeadersHelper`, `awsAuthRefresh`, `awsCredentialExport`,
  `gcpAuthRefresh`, `fileSuggestion`

This list is curated from the Claude Code settings reference; other keys are
not emitted.

Values of `env` maps and HTTP `headers` (in settings, hooks, and MCP servers)
are kept when rules need them: URLs (userinfo, query, and fragment removed),
hosts, booleans, numbers, and other non-secrets. A value is replaced with
`[REDACTED]` when its name contains `token`, `key`, `secret`, `password`,
`authorization`, or `cookie` (any case), or when the value matches the
output redactor's credential patterns. Key names are kept in `env_keys` and
`header_keys`. Sinks redact again. The setting list above is curated; a
test pins it. Unknown settings keys are not emitted.

Markdown items keep the raw content and the frontmatter (minus `hooks` and
`mcpServers`, which become their own items).

### Keys

Each item uses the model's `claude:<scope>:<path>` config ID. The payload
carries a content-derived `key`, a JSON array such as
`["hook","PreToolUse","Bash","command","./check.sh"]` or
`["mcp","~/src/app","local"]`. It includes the hook event, then the same
trailing parts as the kit-based adapters (`kit.Source.EntrySignature`): a
digest of the entry as kit sanitizes it, so a value this adapter keeps
raw never feeds the fingerprint, and, when sanitizing removed anything
from any field, a discriminator over all of the removed text. Entries
that differ only by event, position, or a redacted value therefore do
not collide. The fingerprint algorithm in [fingerprint.md](../fingerprint.md)
is unchanged; only the key content is adapter-defined.

## Safe reads

All repository reads go through the shared `adapters.SafeReader`, which opens
the scan root with `os.Root`:

- Paths from configuration that are absolute or contain `..` are rejected.
- Symlinks are followed only when they resolve inside the scan root. A
  config-relevant symlink that resolves outside it is reported ("Claude Code
  may load its target, which was not scanned"), never silently skipped.
  Symlinked skill directories inside the repository are followed. Symlink
  cycles terminate.
- Each adapter's notion of "config-relevant" is deliberately broader than
  what it actually reads wherever its own location is not fully known in
  advance: Claude cannot tell a plugin's root directory name without
  following the symlink, which it does not do, so it also flags `skills`,
  `agents`, `commands`, and `hooks` directories outside `.claude`. When
  more than one requested adapter is run over the same repository and more
  than one independently flags the exact same escaping symlink, `tripcord
  scan` reports it once, keeping the report from the adapter whose own
  location it names, and dropping Claude's broader one (see
  `adapters.DedupeEscapingSymlinkDiagnostics`). A symlink only Claude
  flags is unaffected.
- Files are opened non-blocking and checked with `fstat` on the opened
  descriptor, so FIFOs, devices, and sockets are never read, even if a file is
  swapped after it was listed.
- Hardlinks are indistinguishable from regular files. A hardlink to a file
  outside the repository is read like any other file; it can only exist if
  the attacker already had write access to that file's filesystem.

User and managed scope read fixed locations with the same non-blocking,
regular-file, and size checks, but follow symlinks, because those paths are
controlled by the local user or administrator.

## Parsing

Claude Code documents its settings as strict JSON. The adapter decodes
strictly and fails closed on:

- a UTF-8 byte-order mark, comments (JSONC), and trailing commas
- nesting deeper than 64 levels
- YAML aliases and merge keys in frontmatter (no alias bombs)

Keys are decoded case-sensitively. Exact duplicate keys use the last value,
as Claude Code does, and are reported. Keys that differ only by case (for
example `hooks` and `Hooks`) are reported, because a case-insensitive decoder
would let one hide the other.

Frontmatter must open and close with exact `---` lines. A byte-order mark and
CRLF line endings are normalized first; a missing closing line is an error.

## Limits

| Limit | Default |
| --- | --- |
| Bytes per file | 1 MiB (`~/.claude.json`: 256 MiB) |
| Directory depth | 32 |
| Directory entries walked | 200,000 |
| Configuration files read | 2,000 |
| Total bytes read | 64 MiB |

When a walk limit is reached the adapter stops and reports "repository walk
truncated".

## Diagnostics

Malformed, oversized, unsafe, or unreadable files are reported per file and
never abort the scan: the remaining configuration is still normalized. The
CLI prints each diagnostic to stderr (sanitized and redacted), includes
blocking diagnostics in the JSON, Markdown, text, and SARIF reports, notes
that the scan is incomplete, and exits 3 after writing the findings. With
`--since`, repository diagnostics are limited to changed files. See
[scan.md](../scan.md).
