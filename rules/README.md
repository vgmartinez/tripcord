# Rules

This directory is the built-in core pack, `tripcord/core`. It is
embedded in the binary.

- `pack.yaml` names the pack and its version.
- `REGISTRY` lists every rule id ever allocated. It is append-only.
- `<ID>.yaml` is one rule, and `<ID>.test/` holds its `positivos/` and `negativos/` fixtures.

| Rule | Detects |
| --- | --- |
| TC-CFG-001 | SessionStart or Setup hook, in shared config, that downloads or runs code from the network. The command line is read by `shell.risks`, a shell tokenizer: a downloader has to be in command position with a non-loopback URL or other network target, any pipe into a shell counts on its own (except `./script.sh \| sh`), `powershell -EncodedCommand` counts on sight, and so does nesting deeper than eight levels of `$( )`, `-c`, or `eval`. A pipe into Invoke-Expression counts only when a command in that pipeline fetches, so `oh-my-posh init pwsh \| Invoke-Expression` is quiet. Decoded content into it (`base64 -d` or `--decode`, `FromBase64`, `[Text.Encoding]::GetString`) counts as encoded. `localhost`, `127.0.0.0/8`, and `[::1]` are loopback. Quoting is resolved per command, and the payloads of `bash -c` (after `-o`, `--`, and other wrapper flags), `powershell -Command` or a positional script block, `cmd /c`, `$( )`, backticks, and `eval` are read with the same exemptions. `-File` is a script path, not a payload. |
| TC-CFG-002 | `.vscode/tasks.json` task with `runOptions.runOn: folderOpen`. Reported once, on the vscode surface, under any `--harness`, because Cursor and Windsurf open the same file. A harness-limited scan reads that one file, not AGENTS.md or the shared skills. |
| TC-CFG-003 | MCP server normalized by any adapter whose command is a shell (sh, bash, zsh, dash, ksh, ash, csh, tcsh, fish, cmd, PowerShell), a pipe to a shell (read by `shell.risks`, so `./script.sh \| sh` is exempt as in TC-CFG-001), or an inline interpreter (`python -c`, `node -e`/`--eval`, `perl -e`, `ruby -e`, `deno eval`). The inline flag counts only before any script or `-m`, so `python -m srv -c conf.yaml` does not match. |
| TC-CFG-004 | `permissions.allow` in shared Claude settings. A broad exec wildcard or `Edit(//**)` (the filesystem root, with any number of leading slashes) is high. A broad read or write, including `Read(//**)`, bare `Write`, and the project-relative `Read(/**)`, is medium. One permissions object is one finding, at the first matching severity. |

`severity` is the catalog severity and the floor a policy lock uses.
`severity_when`, when a rule has it, is tried in order once `when` is
true. The first true clause is the severity of that match, and an item
no clause accepts is not a match. A policy severity override replaces
the per-match result.

Static matching does not expand `$VAR` or `$(echo cur)l`. Split quotes
such as `c''url` are joined as a shell would, and `LOCALHOST` is
loopback like `localhost`. It does not unwrap `nohup`, `xargs`,
`env -S`, `busybox`, or `start /b` in a hook, or an `env`, `busybox`,
or `$SHELL` wrapper around an MCP command. Nested `.vscode/tasks.json` files and `.code-workspace`
tasks are out of scope.

The format, the id registry, and fixtures are described in
[CONTRIBUTING.md](../CONTRIBUTING.md#rules).

```sh
make test-rule ID=TC-CFG-001
```
