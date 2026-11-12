# Auto-run hook inventory

Opening a repository in a coding agent can run code the repository
commits, with no prompt or tool call: a hook on an event that fires when
a session starts. Tripcord lists those hooks in an informational
inventory, so a reviewer of an untrusted repository sees what would run.
The inventory is not a rule and not a finding.

## What it lists

One entry per hook and committed file it runs:

| Harness | File | Events |
| --- | --- | --- |
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json` (any depth) | `SessionStart`, `Setup` |
| Cursor | `.cursor/hooks.json` (any depth) | `sessionStart` |

A hook is listed when its command runs a file that exists in the
repository: a program written as a path (`./scripts/setup.sh`,
`"$CLAUDE_PROJECT_DIR"/.claude/hooks/start.sh`) or the script an
interpreter is given (`bash scripts/init.sh`, `node .cursor/hooks/start.mjs`).
Scripts are found and resolved the same way [TC-CFG-006](rules/TC-CFG-006.md)
finds them, from the directory that holds `.claude` or `.cursor`. A hook
that runs two committed scripts is two entries.

It also lists the module of a Claude Code mod: a plugin's `hooks.json`
with a `modules` member, `{"modules": ["./register.tsx"]}`. The module is
a JS or TS file Claude Code loads with the plugin. Its event is shown as
`modules`, and the path is resolved from the directory of the
`hooks.json` that names it. See [Claude Code](adapters/claude.md#repository)
for which `modules` values are accepted.

Each entry has:

- the harness (`claude`, `cursor`);
- the configuration file, and the line of the command in it when it can
  be found (the line of the event otherwise, or none);
- the event (`SessionStart`, `Setup`, `sessionStart`, or `modules`);
- the command as reports show it, after the same redaction as finding
  text;
- the repository path of the file it runs or loads.

Not listed:

- a hook whose command runs no repository file (`echo hi`,
  `git status`), or whose script is missing or is a symlink that leaves
  the repository. TC-CFG-006 reports the missing script and the symlink;
- a hook on any other event, such as `PreToolUse`, `UserPromptSubmit`,
  or Cursor's `beforeShellExecution`, which needs a tool call or a
  prompt;
- a hook in a skill's or an agent's frontmatter (see
  [TC-CFG-007](rules/TC-CFG-007.md)), in a plugin's `hooks.json`, or in
  a user-scope file;
- other harnesses' session-start hooks. They may be added later.

What the script does is not read.

## Why it is not a finding

TC-CFG-006 reports a hook whose script is not committed, and its fix tells
the user to commit the script, so a hook that runs a committed script is
quiet by design. [TC-CFG-002](rules/TC-CFG-002.md), however, reports a
`folderOpen` task that runs the same committed script as high. In both
cases opening the repository runs code the repository controls. The
inventory shows the hook case without turning a documented, recommended
setup into a finding.

The inventory never changes the exit code and is not affected by
`--fail-on`, policy mode, rules, or exceptions. A low-severity rule, for
example "hook runs repository code on an auto-run event", may come in v1,
informed by what the inventory shows.

## Where it appears

| Output | Inventory |
| --- | --- |
| `preopen`, text | By default, under `auto-run hooks (informational, not findings):`, one line per entry, before the `-v` hint. |
| `scan`, text | Only with `-v`: one `auto-run hook (informational, not a finding):` line per entry, with the command. |
| JSON and JSONL | Always: one `tripcord.autorun_hook/v1` document per entry, after the findings and diagnostics. It is not a finding document. |
| SARIF | Always: one `note` in `runs[0].invocations[0].toolExecutionNotifications` per entry. It is never a result, so it does not create a code scanning alert. |
| Markdown, GitHub Actions | Not included. |

A repository with no entry produces the same output as before. With
`--since`, only entries in changed files are listed; with `--staged`,
only entries of the staged paths.

A JSON document looks like this:

```json
{"schema":"tripcord.autorun_hook/v1","informational":true,"harness":"claude","path":".claude/settings.json","line":6,"event":"SessionStart","command":"./scripts/setup.sh","target":"scripts/setup.sh"}
```

`line` is omitted when it is not known. Every string field is redacted and
capped like finding text (see [Output sinks](output.md#limits)).

Tripcord's own wiring (`tripcord init --embed`) adds a Cursor
`sessionStart` hook that runs the committed `.tripcord/bootstrap.sh`, so an
embedded repository lists that entry.
