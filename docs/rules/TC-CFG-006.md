# TC-CFG-006: hook runs a script outside the repository or at a remote URL

| | |
| --- | --- |
| Severity | high (home, temp, remote URL); medium (other absolute path, `..`, referenced script missing from repo) |
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
| Any other absolute path, such as `/opt/vgmartinez/hooks/check.sh` or `D:\tools\x.ps1` | medium |
| Above the project directory: `../x.sh`, `$CLAUDE_PROJECT_DIR/../x.sh` | medium |
| A project script the hook runs that is not in the scanned tree | medium, titled "Referenced script missing from repo" |

When several apply, the first row in this order decides the severity and
title.

## Heuristics

The rule reads text, not a machine, so it decides some cases by rule of
thumb. These are the ones a reviewer should know.

**What counts as remote.** A hook `url`, or a program or script written
as an `http`, `https`, or `ftp` URL, whose host is not loopback
(`localhost`, `127.0.0.0/8`, `[::1]`), and a UNC path (`\\host\share`,
`//host/share`). A UNC path is high in every command field, bare,
quoted, or as a `-File` or interpreter script, including a Copilot
`powershell` field: a POSIX shell would read an unquoted `\\` as one
backslash, but cmd.exe and PowerShell run the file from the share, and
a hook does not say which shell runs it. A URL that is only an argument (`./notify.sh
https://...`) is not a target. A `curl` or `wget` inside the command is
not read by this rule: TC-CFG-001 reports it in session-start hooks and
TC-CFG-008 in Cursor, Copilot, and Windsurf hooks.

**Project variables.** `$CLAUDE_PROJECT_DIR`, `$CLAUDE_PLUGIN_ROOT`,
`$GEMINI_PROJECT_DIR`, `$CURSOR_PROJECT_DIR`, and `$PWD`, written
`$NAME`, `${NAME}`, `%NAME%`, or `$env:NAME`, are taken to be the
project, so a path under them is inside the repository. `../` after one
still climbs out and is medium. Any other variable (`$HOOKS_DIR/x.sh`)
and any command substitution has no known value and is not reported.

**System directories.** A program without a script extension under
`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`, `/nix`, `/snap`,
`/etc`, `/Applications`, `/System`, `/Library`, `C:\Windows`,
`C:\Program Files`, `C:\Program Files (x86)`, or `C:\ProgramData` is
taken to be an installed binary, such as `/usr/local/bin/tripcord` or
`/opt/homebrew/bin/prettier`, and is not reported. A script there (by
extension: `.sh`, `.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.rb`, `.pl`,
`.php`, `.lua`, `.ps1`, `.cmd`, `.bat`, ...) is reported as medium, for
example `/opt/vgmartinez/hooks/check.sh`.

**Programs on `PATH`.** A bare name (`npx`, `jq`, `tripcord`) is a
`PATH` lookup and has no location.

**Arguments.** Only the program and an interpreter's script are read:
`cp {} /tmp/backup/` and `>> ~/.claude/audit.log` run `cp` and `echo`.

**Missing scripts.** A project script is a program written as a path
(`./x.sh`, `scripts/x`, `"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh`) or an
interpreter's script (`bash x.sh`, `node .cursor/hooks/x.mjs`). It is
looked up relative to the hook's project directory: the directory that
holds the harness's config directory (`.claude`, `.cursor`, `.github`,
`.windsurf`, `.devin`, `.codex`, `.gemini`, `.agents`), so a hook in
`packages/web/.claude/settings.json` resolves `./x.sh` to
`packages/web/x.sh`. A Copilot hook's relative `cwd` is joined to it.
The lookup calls `os.Stat` and then `filepath.EvalSymlinks` on the whole
path, so a symlink in a parent directory counts as well as a symlink in
the last component. A target
outside the repository is reported as a script outside the repo, at the
severity of that target: home or a temporary directory is high, and any
other absolute path, including a system path such as `/etc/passwd`, is
medium. A symlink that does not resolve, including a broken link, counts
as missing, and so does any other error from the lookup. It is not checked:

- when the line contains a backslash, because POSIX and PowerShell
  split it differently (`.\scripts\x.ps1`);
- after `cd`, `pushd`, or `Set-Location` on the same line;
- for a bare operand without a directory or extension (`node server`),
  which the interpreter may resolve to another file;
- for paths with any other variable or a glob, and for
  `$CLAUDE_PLUGIN_ROOT` paths;
- for hooks in a file outside those config directories, such as a
  Claude plugin's `hooks/hooks.json`.

Not reported at all: `.claude/settings.local.json` and
`.github/copilot/settings.local.json`, which are personal.

## Limits

- Whether a script that exists is committed. The scan does not run git,
  so an untracked or gitignored script counts as present. Reading the
  git index is a follow-up.
- What the target script does. Only the hook entry is read.
- User-scope hooks. `negativos/malformed-fields.json` includes
  `~/.cursor/hooks.json` running `~/.cursor/hooks/stop.sh`, and that
  negative stays as it is, so the rule still requires repository scope.
  A home path on that item would match if the scope gate were opened.

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

Reported as "Referenced script missing from repo", when
`.cursor/hooks/redact.mjs` is not in the tree:

```json
{"version": 1, "hooks": {"beforeShellExecution": [
  {"command": "node .cursor/hooks/redact.mjs"}]}}
```

Not reported, when `.claude/hooks/guard.sh` is in the tree:

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
