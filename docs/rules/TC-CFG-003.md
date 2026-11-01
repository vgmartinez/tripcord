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

Not reported:

- Servers with a `type` other than stdio or local (`http`, `sse`).
- A server's own flags after a script or module:
  `python -m my_server -c config.yaml`, `node server.js -e production`.
- A pipe in a literal argument of a non-shell program:
  `node server.js --filter 'a|sh'`.

## Limits

- A flag that takes a separate value before the inline flag
  (`python -W ignore -c`) is not matched.
- Wrappers such as `npx`, `uvx`, or `docker run` are not unwrapped.

## Examples

Reported:

```json
{"mcpServers": {"helper": {"command": "bash", "args": ["-c", "node ./mcp/server.js"]}}}
```

Not reported:

```json
{"mcpServers": {"docs": {"command": "node", "args": ["./mcp/server.js"]}}}
```

## How to fix

Point `command` at the server binary and pass its arguments in `args`,
without a shell, an inline interpreter, or a downloaded script.

## References

- [Novee: The Sandbox is a Suggestion](https://novee.security/blog/breaking-ai-agent-sandboxes/)
- [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
