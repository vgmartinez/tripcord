# `tripcord hook`

```text
tripcord hook --harness <claude|cursor|copilot> --event <e> [--on-failure block|error]
```

`hook` is the hook mode a harness runs before a tool call. It reads one
hook event, the harness's own JSON, on stdin. It normalizes the event
to a `tripcord.event/v1` through that harness's adapter, evaluates the
policy's custom event rules, and writes the decision in the harness's
format. Each run handles one event in a new process and keeps no state.

## Events

| Harness | `--event` | Harness hook event | What rules see |
| --- | --- | --- | --- |
| `claude` | `pre-tool` | `PreToolUse` | `tool_name`, and `command`, the file path, and the URL from `tool_input` |
| `cursor` | `pre-tool` | `preToolUse` | `tool_name`, and `command`, the file path, and the URL from `tool_input` |
| `cursor` | `before-shell` | `beforeShellExecution` | `command` (tool `Shell`) |
| `cursor` | `before-read` | `beforeReadFile` | `file_path` (tool `Read`); the file content is dropped |
| `copilot` | `pre-tool` | `preToolUse` (`.github/hooks/*.json`, CLI and coding agent) | `toolName`, and `command`, the file path, and the URL from `toolArgs` |

The input must name the event that `--event` names: Claude Code's
`hook_event_name` must be `PreToolUse`, and Cursor's must be the one in
the table. Copilot's input names no event. The event's `session.id` is
Claude Code's `session_id`, Cursor's `conversation_id`, or Copilot's
`sessionId`, and `unknown` when the input has none. `event.kind` is
`tool_call` for a command, `read` or `write` for file tools, `net` for a
fetch, and `tool_call` otherwise.

## Policy

The policy is the hook surface's ([Policy](policy.md#surfaces)): the org
layers, then `.tripcord/policy.yaml` and `.tripcord/policy.local.yaml`
of the project. The project is `CLAUDE_PROJECT_DIR` for Claude Code and
`CURSOR_PROJECT_DIR` for Cursor, which must be absolute, and the working
directory when the variable is unset and for Copilot.

The decision comes from the policy's `custom` rules. `when` (optional)
and `deny_if` are CEL over `event.*` with the same functions and limits
as the core rules, including `shell.risks`, `shell.unpinned`,
`hook.argv`, and `mcp.packages`. `matches()` is RE2. For example:

```yaml
version: 1
mode: enforce
fail-on: high
custom:
  - id: ACME-001
    deny_if: 'event.command != "" && "pipe" in shell.risks(event.command)'
    message: piping a download into a shell is not allowed
  - id: ACME-002
    deny_if: 'event.paths.exists(p, p.endsWith("/.env"))'
    message: reading .env is not allowed
    severity: critical
```

A rule whose `deny_if` holds is a hit, with its `severity` (default
`high`) after `rules.severity_overrides`. A rule left out of
`rules.include`, or a harness left out of `harnesses`, is not evaluated.

| Mode | A hit at or above `fail-on` | A hit below `fail-on` |
| --- | --- | --- |
| `enforce` | deny | warn |
| `warn` (the hook default) | warn | warn |
| `audit` | audit | audit |

With no hit the decision is allow. Without a policy mode the hook warns
and never blocks, so write `mode: enforce` to block. `tripcord init`
writes that.

## Output

| Decision | Claude Code | Cursor | Copilot |
| --- | --- | --- | --- |
| deny | exit 2; stdout `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}`; the reason on stderr | exit 2; stdout `{"permission":"deny","user_message":"...","agent_message":"..."}`; the reason on stderr | exit 2; the reason on stderr |
| ask | exit 0; `permissionDecision` `ask` | exit 0; `{"permission":"ask",...}` on `before-shell`; a deny on the other events | a deny |
| warn | exit 0; `{"systemMessage":"..."}` | exit 0; `{"permission":"allow","user_message":"..."}` | exit 0; the reason on stderr |
| allow, audit | exit 0; `{}` | exit 0; `{"permission":"allow"}` | exit 0; nothing |

A deny exits 2 for every harness, so the call is blocked whether or not
the harness reads stdout. The Claude Code output never sets
`permissionDecision` to `allow`: that would skip Claude Code's own
permission prompts, so an allow leaves the decision to them. No custom
rule asks yet; `ask` is rendered for when one does.

The reason names the rules that decided, for example `tripcord blocked
this tool call: ACME-001 (high): piping a download into a shell is not
allowed`. It never includes the command or the input.

## Failures

A run that cannot decide is one of:

- invalid flags, or an `--event` the harness does not have;
- input that is empty, malformed, not a JSON object, for another event,
  or over the stdin limit;
- an invalid policy, including a `custom` rule that does not compile;
- an evaluation error or an exhausted CEL budget;
- no decision within the deadline.

By default (`--on-failure error`) it writes `tripcord hook: <error>` on
stderr and nothing on stdout, and exits 3, or 4 for an internal error.
With `--on-failure block` it fails closed instead: the tool call is
denied in the harness's format with `tripcord hook failed closed:
<error>` as the reason, and it exits 2.

## Limits

| Limit | Value |
| --- | --- |
| stdin | 4 MiB |
| Normalized event, as rules see it | 64 KiB |
| CEL cost | 2,000,000 per evaluation |
| CEL time | 1 s per evaluation, 5 s for every rule of an event |
| Whole run | 10 s, under Claude Code's default 60 s hook timeout and the 60 s `timeoutSec` `init --embed` sets for Copilot |

The core rule pack is compiled only when the policy needs its catalog
(a `locked` section, or a `custom` id that is also a core rule id, which
is rejected as in `scan`). Without that, a cold start is a few
milliseconds. The `e2e perf budget` CI job runs
`TestHookColdStartBudget`, which fails if the p95 of a new `tripcord
hook` process per event exceeds 25 ms.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Allowed: allow, ask, warn, or audit. `--help` also exits 0. |
| 2 | Blocked: deny, or any failure with `--on-failure block`. |
| 3 | Invalid flags, input, or policy. |
| 4 | Internal error, a policy read error, or no decision within the deadline. |

## With `init --embed`

The hooks `init --embed` writes run `bash .tripcord/bootstrap.sh hook
--harness <h> --event pre-tool`, which runs this command from the
verified binary. `init --embed` is not releasable yet: the wiring does
not pass `--on-failure block`, and `bootstrap.sh` has no published
package to install from. See [Init](init.md).
