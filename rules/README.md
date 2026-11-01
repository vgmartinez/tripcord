# Rules

This directory is the built-in core pack, `tripcord/core`. It is
embedded in the binary.

- `pack.yaml` names the pack and its version.
- `REGISTRY` lists every rule id ever allocated. It is append-only.
- `<ID>.yaml` is one rule, and `<ID>.test/` holds its `positivos/` and `negativos/` fixtures.

| Rule | Detects |
| --- | --- |
| TC-CFG-001 | SessionStart or Setup hook, in shared config, that downloads or runs code from the network. The downloader has to be in command position and have a non-loopback URL or other network target. The payload of `bash -c`, `sh -c`, `powershell -Command`, and `cmd /c` is read too. Any unquoted pipe to a shell counts on its own, except `./script.sh \| sh`. |
| TC-CFG-002 | `.vscode/tasks.json` task with `runOptions.runOn: folderOpen`. Reported once, on the vscode surface, under any `--harness`, because Cursor and Windsurf open the same file. A harness-limited scan reads that one file, not AGENTS.md or the shared skills. |
| TC-CFG-003 | MCP server normalized by any adapter whose command is a shell (sh, bash, zsh, dash, ksh, ash, csh, tcsh, fish, cmd, PowerShell), a pipe to a shell, or an inline interpreter (`python -c`, `node -e`/`--eval`, `perl -e`, `ruby -e`, `deno eval`). The inline flag counts only before any script or `-m`, so `python -m srv -c conf.yaml` does not match. |
| TC-CFG-004 | `permissions.allow` in shared Claude settings. A broad exec wildcard, `Read(//**)`, or `Edit(//**)` (the filesystem root) is high. A broad read or write, including bare `Write` and the project-relative `Read(/**)`, is medium. One permissions object is one finding, at the first matching severity. |

`severity` is the catalog severity and the floor a policy lock uses.
`severity_when`, when a rule has it, is tried in order once `when` is
true. The first true clause is the severity of that match, and an item
no clause accepts is not a match. A policy severity override replaces
the per-match result.

Static matching does not expand `$VAR`, `$(echo cur)l`, or `c''url`,
and it does not unwrap an `env`, `busybox`, or `$SHELL` wrapper around
an MCP command. Nested `.vscode/tasks.json` files and `.code-workspace`
tasks are out of scope.

The format, the id registry, and fixtures are described in
[CONTRIBUTING.md](../CONTRIBUTING.md#rules).

```sh
make test-rule ID=TC-CFG-001
```
