# TC-CFG-004: permissions.allow with a broad rule in shared config

| | |
| --- | --- |
| Severity | high (broad exec, or edit of the whole filesystem); medium (broad read, write, or fetch) |
| Harnesses | Claude Code |
| Files | `.claude/settings.json` (any depth, repository scope) |
| Rule | [`rules/TC-CFG-004.yaml`](../../rules/TC-CFG-004.yaml) |

## What it detects

An entry in `permissions.allow` is applied without asking. In shared
settings a broad entry pre-approves that tool for everyone who opens the
repository. Novee showed allow overriding ask in claude-code-action.

Paths follow Claude Code's permission syntax: `//path` is absolute from
the filesystem root (`///path` reads the same), `/path` is relative to
the project root, `~/path` is the home directory. Matching is
case-insensitive.

| Entry | Severity |
| --- | --- |
| Bare `Bash`, `Bash(*)`, `Bash(:*)`, `Bash(**)`, and the same for `PowerShell`, `pwsh`, `Shell`, `Cmd`, `Terminal`, `run_shell_command` | high |
| `*` and `mcp__*` | high |
| `Edit(//**)`, any number of leading slashes | high |
| Bare `Read`, `Edit`, `Write`, `WebFetch` | medium |
| `Read(*)`, `Read(/**)`, `Read(//**)`, `Read(~/**)`, the same for `Write`, and `Edit(*)`, `Edit(/**)`, `Edit(~/**)` | medium |
| `WebFetch(*)`, `WebFetch(domain:*)` | medium |

One permissions object is one finding, at the first matching severity,
so high wins when both are present.

Not reported:

- Narrow entries such as `Bash(go test ./...)` or `Read(./docs/**)`.
- `settings.local.json`, which is personal.

## Limits

- `deny` and `ask` entries are not weighed against the allow list.
- `Write` takes no path pattern of its own (Edit rules govern file
  writes), so `Write(...)` stays medium.

## Examples

Reported, high:

```json
{"permissions": {"allow": ["Bash(*)"]}}
```

Reported, medium:

```json
{"permissions": {"allow": ["Read(*)", "WebFetch(domain:*)"]}}
```

Not reported:

```json
{"permissions": {"allow": ["Bash(go test ./...)", "Read(./docs/**)"]}}
```

## How to fix

Replace the broad allow with the specific commands or paths the project
needs, for example `Bash(go test ./...)`.

## References

- [Novee: The Sandbox is a Suggestion](https://novee.security/blog/breaking-ai-agent-sandboxes/)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
