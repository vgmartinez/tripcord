# TC-CFG-006: hook runs a script outside the repository or at a remote URL

| | |
| --- | --- |
| Severity | high (home, temp, remote URL); medium (other absolute path, `..`) |
| Harnesses | Claude Code, Codex, Copilot, Cursor, Gemini CLI, Windsurf, shared skills (`generic`) |
| Files | every hook any adapter normalizes, repository scope, except `settings.local.json` |
| Rule | [`rules/TC-CFG-006.yaml`](../../rules/TC-CFG-006.yaml) |

## What it detects

A committed hook whose target is not committed with it. Review sees the
hook line, but what runs is whatever sits at the target when the hook
fires. The npm worm of August 2026 used this to persist: a hook in
shared config pointing at a script it had written elsewhere on the
machine.

Each command field (`command`, `bash`, `powershell`, `exec` and `args`,
`commandWindows`, `windows`, `linux`, `osx`) is read by
`shell.locations`, which follows the same wrappers as `shell.risks`
(`sudo`, `env`, `bash -c`, `pwsh -Command`, `cmd /c`, `eval`). It looks
at the program of every simple command and at the script an interpreter
is given: `bash x.sh`, `python x.py`, `node x.js`, `deno run x.ts`,
`pwsh -File x.ps1`, `source x`.

| Target | Severity |
| --- | --- |
| A hook `url` (HTTP hook) or program at a non-loopback URL, or a UNC share | high |
| Under the home directory: `~`, `$HOME`, `%USERPROFILE%`, `$env:APPDATA`, `XDG_*_HOME`, `/home/<user>`, `/Users/<user>`, `/root`, `C:\Users\<user>` | high |
| A temporary directory: `/tmp`, `/var/tmp`, `/dev/shm`, `/private/tmp`, `/var/folders`, `$TMPDIR`, `%TEMP%`, `$RUNNER_TEMP`, `C:\Windows\Temp` | high |
| Any other absolute path, such as `/opt/acme/hooks/check.sh` or `D:\tools\x.ps1` | medium |
| Above the project directory: `../x.sh`, `$CLAUDE_PROJECT_DIR/../x.sh` | medium |

Not reported:

- Relative paths inside the project, and paths under
  `$CLAUDE_PROJECT_DIR`, `$CLAUDE_PLUGIN_ROOT`, `$GEMINI_PROJECT_DIR`,
  `$CURSOR_PROJECT_DIR`, or `$PWD`.
- Programs found on `PATH` (`npx`, `tripcord`, `jq`), and binaries
  without a script extension under a system directory (`/usr`, `/bin`,
  `/opt`, `/nix`, `/Applications`, `C:\Program Files`, ...), such as
  `/usr/local/bin/tripcord`. A script there (`/opt/x/hook.sh`) is
  reported as medium.
- Paths in arguments: `cp {} /tmp/backup/` and `>> ~/.claude/audit.log`
  run `cp` and `echo`.
- HTTP hooks to `localhost`, `127.0.0.0/8`, or `[::1]`.
- `$VAR` paths for other variables (`$HOOKS_DIR/x.sh`) and command
  substitutions: their value is not known statically.
- `.claude/settings.local.json` and `.github/copilot/settings.local.json`,
  which are personal.

## Limits

- Whether a script inside the repository is committed. The scan does
  not run git, so a project-relative script that is untracked or
  gitignored is not reported. See the open question in the pull
  request.
- What the target script does. Only the hook entry is read.

## Examples

Reported:

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
  {"type": "command", "command": "~/.claude/hooks/guard.sh"}]}]}}
```

```json
{"version": 1, "hooks": {"postToolUse": [
  {"type": "command", "exec": "node", "args": ["/tmp/lint-hook/index.js"]}]}}
```

```json
{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
  {"type": "http", "url": "https://hooks.example.invalid/pre-tool"}]}]}}
```

Not reported:

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
  {"type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/guard.sh"},
  {"type": "command", "command": "/usr/local/bin/tripcord hook --harness claude --event pre-tool"}]}]}}
```

## How to fix

Commit the script and reference it by a project-relative path, for
example `"$CLAUDE_PROJECT_DIR"/.claude/hooks/check.sh` or
`.cursor/hooks/audit.sh`, so review covers what the hook runs. Replace
an HTTP hook to a remote host with a committed command hook. A hook
that only makes sense on one machine belongs in that user's own
settings, not in the repository.

## References

- [WorkOS: the npm worm and coding-agent config](https://workos.com/blog/npm-worm-coding-agent-config-credentials)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Windsurf Cascade hooks](https://docs.windsurf.com/windsurf/cascade/hooks)
