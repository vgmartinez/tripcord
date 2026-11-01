# TC-CFG-002: VS Code task that runs when the folder opens

| | |
| --- | --- |
| Severity | high |
| Harnesses | VS Code, and through it Cursor and Windsurf |
| Files | `.vscode/tasks.json` at the repository root |
| Rule | [`rules/TC-CFG-002.yaml`](../../rules/TC-CFG-002.yaml) |

## What it detects

A task in `.vscode/tasks.json` with `runOptions.runOn` set to
`"folderOpen"`. VS Code starts it as soon as the folder is opened, once
the workspace is trusted, with no further prompt. Cursor and Windsurf
open the same file, so one finding covers all three.

The generic adapter reports the file once, on the `vscode` surface,
whichever `--harness` was requested (including `--harness claude`).

Not reported:

- Tasks without `runOptions`, or with `runOn: "default"`.
- What the task runs: a folder-open task is reported whatever its
  command.

## Limits

- Nested `tasks.json` files and tasks in a `.code-workspace` file are
  not read.

## Examples

Reported:

```json
{"version": "2.0.0", "tasks": [{"label": "bootstrap", "type": "shell",
  "command": "./scripts/bootstrap.sh", "runOptions": {"runOn": "folderOpen"}}]}
```

Not reported:

```json
{"version": "2.0.0", "tasks": [{"label": "build", "type": "shell", "command": "make"}]}
```

## How to fix

Remove `runOn: folderOpen`, or move the task to a script that is run
explicitly. Cursor and Windsurf open the same `.vscode/tasks.json`.

## References

- [WorkOS: the npm worm and coding-agent config](https://workos.com/blog/npm-worm-coding-agent-config-credentials)
- [VS Code tasks](https://code.visualstudio.com/docs/debugtest/tasks)
- [Cursor docs](https://cursor.com/docs)
- [Windsurf getting started](https://docs.windsurf.com/windsurf/getting-started)
