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
of the project. The project is the Git root (the nearest directory
whose `.git`, after following symlinks, is a directory or a worktree's
file, the same check `init` makes) at or above `CLAUDE_PROJECT_DIR` for
Claude Code or `CURSOR_PROJECT_DIR` for Cursor, which must be absolute,
or at or above
the working directory when the variable is unset and for Copilot. The
variable may name a subdirectory or a directory that does not exist,
and symlinks in it are resolved first, so a link into a subdirectory of
the repository finds the repository's policy. With
no Git repository at or above it there is no project policy to apply, so
the run fails (see [Failures](#failures)) instead of allowing.

The decision comes from the policy's `custom` rules. `when` (optional)
and `deny_if` are CEL over `event.*` with the same functions and limits
as the core rules, including `shell.risks`, `shell.unpinned`,
`shell.mcp`, `hook.argv`, and `mcp.packages`. `matches()` is RE2. For example:

```yaml
version: 1
mode: enforce
fail-on: high
custom:
  - id: ACME-001
    deny_if: 'event.command != "" && "pipe" in shell.risks(event.command)'
    message: piping a download into a shell is not allowed
  - id: ACME-002
    deny_if: 'event.paths.exists(p, p.lowerAscii().endsWith("/.env"))'
    message: reading .env is not allowed
    severity: critical
```

Tool paths are cleaned and made absolute before the policy runs. Claude
Code and Copilot resolve a relative path against the process working
directory (`Getwd()`) when the hook JSON has no `cwd`; a `cwd` in that
JSON is used when the harness sends one. They do not use the project
directory. Cursor resolves a relative path against the hook JSON `cwd`,
or `workspace_roots[0]` when `cwd` is empty, and against the process
working directory when both are empty. A trailing slash is removed. The
cleaned path is the string a suffix check sees. That walk does not
follow symlinks, so a link named `notes` that points at `.env` does not
match `/.env`. On Windows the path is ASCII-case-folded. A Unix host
does not rewrite a Windows path: `\` stays a character and ASCII case
is kept, so `/.env` does not match `C:\repo\.ENV`. `lowerAscii()` matches
`.ENV` on a case-sensitive filesystem. It does not apply NFKC or fold
homoglyphs, so a lookalike letter in the suffix does not match.

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
| ask | exit 0; `permissionDecision` `ask` | exit 0; `{"permission":"ask",...}` on `before-shell`; a deny on the other events | a deny (see below) |
| warn | exit 0; `{"systemMessage":"..."}` | exit 0; `{"permission":"allow","user_message":"..."}` | exit 0; the reason on stderr |
| allow, audit | exit 0; `{}` | exit 0; `{"permission":"allow"}` | exit 0; nothing |

A deny exits 2 for every harness, so the call is blocked whether or not
the harness reads stdout. The Claude Code output never sets
`permissionDecision` to `allow`: that would skip Claude Code's own
permission prompts, so an allow leaves the decision to them. No custom
rule asks yet; `ask` is rendered for when one does. The Copilot CLI has
a native ask, but the coding agent, which runs without a person to ask,
treats it as a deny. Both send the same `preToolUse` input, so
`tripcord hook` cannot tell them apart and renders `ask` as a deny for
both.

The reason names the rules that decided, for example `tripcord blocked
this tool call: ACME-001 (high): piping a download into a shell is not
allowed`. It never includes the command or the input. A custom rule's
`message`, and every error below, is redacted, has the home directory
shown as `~`, and is cut at 4096 bytes; see [privacy.md](privacy.md).

## Failures

A run that cannot decide is one of:

- invalid flags, or an `--event` the harness does not have;
- input that is empty, malformed, not a JSON object, for another event,
  or over the stdin limit;
- no Git repository at or above the project directory;
- an invalid policy, including a `custom` rule that does not compile
  (exit 3, like the two failures above); a read failure, such as a
  policy file this process cannot open, exits 4 instead;
- an evaluation error, an exhausted CEL budget, or a normalized event
  over its cap: these exit 4, the same as the internal error below, not
  3, even though they come from the policy's own rules;
- an internal error, including a panic, which is reported as
  `internal error`, without the panic value or a stack trace;
- no decision within the deadline.

By default (`--on-failure error`) it writes `tripcord hook: <error>` on
stderr and nothing on stdout, and exits 3, or 4 for an internal error.
With `--on-failure block` it fails closed instead: the tool call is
denied in the harness's format with `tripcord hook failed closed:
<error>` as the reason, and it exits 2. The hooks `init --embed` writes
pass `--on-failure block`. It is a flag, not a policy setting, because
an invalid policy cannot be relied on to ask for it.

## Limits

| Limit | Value |
| --- | --- |
| stdin | 4 MiB |
| Normalized event, as rules see it | 4 MiB |
| CEL cost | 6,000,000 per evaluation |
| CEL time | 3 s per evaluation, 5 s for every rule of an event |
| Whole run | 10 s, under Claude Code's default 600 s command-hook timeout and the 60 s `timeoutSec` `init --embed` sets for Copilot |

Both size caps are 4 MiB, so a long heredoc in a command is decided like
any other; the adapter drops what rules do not read, such as the content
of a file being written or read, so the event is rarely larger than its
input. Over either cap the run fails and follows `--on-failure`. A
single regular expression over a command at the cap takes a few hundred
milliseconds, inside the deadline. The cost limit fits one
`shell.risks` or `shell.locations` call over a command at the cap (one
unit a byte); a rule that parses such a command twice exceeds it, and
the run follows `--on-failure` too.

The core rule pack's expressions are not compiled on this path. A
`locked.rules` or `locked.exceptions` entry, or a `custom` id that is
also a pack rule id (rejected as in `scan`), needs the pack's ids,
severities, and harnesses. Those are read from the pack index. A mode
lock alone does not. Without a lock, a cold start is a few
milliseconds. The `e2e perf budget` CI job runs
`TestHookColdStartBudget`, which fails if the p95 of a new `tripcord
hook` process per event exceeds 25 ms.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Allowed: allow, ask, warn, or audit. `--help` also exits 0. |
| 2 | Blocked: deny, or any failure with `--on-failure block`. |
| 3 | Invalid flags, input (including no Git repository), or an invalid policy (such as a `custom` rule that does not compile). |
| 4 | A CEL evaluation error, an exhausted CEL budget, a normalized event over its cap, a policy read error, an internal error, or no decision within the deadline. |

## With `init --embed`

The hooks `init --embed` writes run `bash .tripcord/bootstrap.sh hook
--harness <h> --event pre-tool --on-failure block`, which runs this
command from the verified binary, so a run that cannot decide denies
the tool call. After `install` or `session-start` (or the first hook)
has recorded the cached file's identity, later hooks compare that
record with one `stat` and do not copy or hash the binary. If the file
changed, is group- or world-writable, or the record is not a private
regular file, `bootstrap.sh` exits 2 and runs nothing. With no record,
`hook` verifies once, and a failed check exits 2 as well. Either
reason blocks the call. See [Init](init.md#bootstrap), including the
same-user residual (a binary and record rewritten together stay
attested) and the residual on filesystems with coarse ctime.

`scripts/hook-latency.sh` prints the p50, p95, and max of a locked
`tripcord hook`, of `bootstrap.sh hook`, and of the difference between
the two in the same run. It does not enforce a threshold.
