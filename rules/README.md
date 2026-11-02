# Rules

This directory is the built-in core pack, `tripcord/core`. It is
embedded in the binary.

- `pack.yaml` names the pack and its version.
- `REGISTRY` lists every rule id ever allocated. It is append-only.
- `<ID>.yaml` is one rule, and `<ID>.test/` holds its `positivos/` and `negativos/` fixtures.

| Rule | Detects |
| --- | --- |
| TC-CFG-001 | SessionStart or Setup hook, in shared config, that downloads or runs code from the network. The command line is read by `shell.risks`, a shell tokenizer: a downloader has to be in command position with a non-loopback URL or other network target, any pipe into a shell counts on its own (except `./script.sh \| sh`), `powershell -EncodedCommand` counts on sight, and so does nesting deeper than eight levels of `$( )`, `-c`, or `eval`. A pipe into Invoke-Expression counts only when a command in that pipeline fetches, so `oh-my-posh init pwsh \| Invoke-Expression` is quiet. Decoded content into it (`base64 -d` or `--decode`, `FromBase64`, `[Text.Encoding]::GetString`) counts as encoded. `localhost`, `127.0.0.0/8`, and `[::1]` are loopback. Quoting is resolved per command, and the payloads of `bash -c` (after `-o`, `--`, and other wrapper flags), `powershell -Command` or a positional script block, `cmd /c`, `$( )`, backticks, and `eval` are read with the same exemptions. `-File` is a script path, not a payload. [Docs](../docs/rules/TC-CFG-001.md). |
| TC-CFG-002 | `.vscode/tasks.json` task with `runOptions.runOn: folderOpen`. Reported once, on the vscode surface, under any `--harness`, because Cursor and Windsurf open the same file. A harness-limited scan reads that one file, not AGENTS.md or the shared skills. [Docs](../docs/rules/TC-CFG-002.md). |
| TC-CFG-003 | MCP server normalized by any adapter whose command is a shell (sh, bash, zsh, dash, ksh, ash, csh, tcsh, fish, cmd, PowerShell), a pipe to a shell (read by `shell.risks`, so `./script.sh \| sh` is exempt as in TC-CFG-001), or an inline interpreter (`python -c`, `node -e`/`--eval`, `perl -e`, `ruby -e`, `deno eval`). The inline flag counts only before any script or `-m`, so `python -m srv -c conf.yaml` does not match. [Docs](../docs/rules/TC-CFG-003.md). |
| TC-CFG-004 | `permissions.allow` in shared Claude settings. A broad exec wildcard or `Edit(//**)` (the filesystem root, with any number of leading slashes) is high. A broad read or write, including `Read(//**)`, bare `Write`, and the project-relative `Read(/**)`, is medium. One permissions object is one finding, at the first matching severity. [Docs](../docs/rules/TC-CFG-004.md). |
| TC-CFG-005 | A shared mode that turns approvals off, high: `permissions.defaultMode: bypassPermissions` in `.claude/settings.json`; `sandbox_mode = "danger-full-access"` or `approval_policy = "never"` in `.codex/config.toml`, at the top level or in a `[profiles.<name>]` table; yolo (`general.defaultApprovalMode`) or `autoAccept` (`tools.autoAccept` or the flat key) in `.gemini/settings.json`. Claude's `skipDangerousModePermissionPrompt` alone is medium; with bypassPermissions in the same file the pair is one high finding. [Docs](../docs/rules/TC-CFG-005.md). |
| TC-CFG-006 | Any shared hook whose target is not committed with it, read by `shell.locations`: an HTTP hook or program at a non-loopback URL, or a program or interpreter script under the home or a temp directory, is high; another absolute path or one above the project (`../x.sh`) is medium. `$CLAUDE_PROJECT_DIR` and the other project variables are the project. Binaries under system directories, paths in arguments, and unknown `$VAR` paths are not reported. A project script the hook runs that is not in the scanned tree, or a symlink that does not resolve, is medium, titled "Referenced script missing from repo". A symlink that resolves outside the repository is reported at that target's severity. Whether an existing script is committed is not checked (no git). [Docs](../docs/rules/TC-CFG-006.md). |
| TC-CFG-007 | A hook declared in the frontmatter of a shared `SKILL.md` (`.claude/skills`, `.agents/skills`, `.github/skills`), which Claude Code registers when the skill runs, even under `-p`. One finding per hook. High when the hook also fetches, pipes into a shell, runs encoded or deeply nested code (`shell.risks`), runs a program or script at a URL or under the home or a temp directory (`shell.locations`), or is an HTTP hook to a non-loopback URL; medium otherwise. [Docs](../docs/rules/TC-CFG-007.md). |
| TC-CFG-008 | A shared Cursor, Copilot, or Windsurf hook that reaches the network (a `shell.risks` fetch, a program at a non-loopback URL, or an HTTP hook to one), or a Cursor or Copilot hook whose whole command prints a fixed `"permission"`, `"permissionDecision"`, or `"decision"` of `"allow"` or `"approve"` (`echo`, `printf`, `Write-Output`, `exec: echo`). High. Anything that makes the output vary (`$`, pipes, `if`, a script) is not matched. [Docs](../docs/rules/TC-CFG-008.md). |
| TC-CFG-009 | Environment setup that runs unpinned fetched code: Copilot setup steps, Cursor environment commands, devcontainer `initializeCommand` (on the host), lifecycle commands, http(s) tarball Features, and Devin blueprint `initialize` / `maintenance` commands. An immutable commit/digest URL or fail-closed checksum pins a download; tags and git clone do not. High. Dockerfile `RUN`, OCI Features, and blueprint `uses` actions are not read. [Docs](../docs/rules/TC-CFG-009.md). |
| TC-CFG-010 | An OpenCode plugin or tool, or Claude Code plugin, that the repository ships or enables. Medium: scan mode reports presence for review; pr-context will tell an addition apart. [Docs](../docs/rules/TC-CFG-010.md). |
| TC-CFG-011 | Hidden Unicode in agent instructions, including shared/local Claude files, Claude/Cursor rules, Copilot instructions/agents, `.cursorrules`, and Devin blueprint maintenance commands and knowledge. Bidi controls, tags, and zero-width characters are high; an emoji ZWJ sequence is exempt. Evidence gives code point, line, and column, never hidden text. [Docs](../docs/rules/TC-CFG-011.md). |
| TC-CFG-012 | Instruction text that asks to read the environment, a dotenv file, or credentials, or to send them to an outbound sink. Medium heuristic over TC-CFG-011's paths plus repository skills, Claude agents/commands (including plugin roots), and Devin blueprint knowledge. Markdown/polite prefixes are allowed, a secret must be the direct object rather than a documentation topic, and findings give the first matching line without exposing text. [Docs](../docs/rules/TC-CFG-012.md). |
| TC-CFG-013 | No v0 coverage for an AI coding-agent workflow triggered by an event a non-collaborator can produce (`issues`, `issue_comment`, `discussion`, `discussion_comment`, `pull_request_target`). zizmor's proposed `agentic-actions` audit is unreleased as of 2026-11-02; this pack has no `TC-CFG-013.yaml` or `rules/REGISTRY` line. See [docs](../docs/rules/TC-CFG-013.md). |
| TC-CFG-014 | An agent-config change in a pull request whose author `pr-context` classifies as a bot or agent, with no human approval. Not a CEL rule: `tripcord pr-context` evaluates it from the event's reviews and the `base...head` diff. A classified path is one an adapter already recognizes. No `rules/TC-CFG-014.yaml` and no `rules/REGISTRY` line. [Docs](../docs/rules/TC-CFG-014.md). |
| TC-CFG-015 | Shared Claude `permissions.allow` WebFetch or `sandbox.network.allowedDomains` entry naming a host with a public read-back channel. Sandbox coverage is deliberately limited to Hugging Face, Pastebin, webhook.site, and gists; package registries remain allowed for installs. `raw.githubusercontent.com` and `github.io` are excluded as false positives; revisiting the list is [issue #38](https://github.com/vgmartinez/tripcord/issues/38). High. Ref CVE-2026-54316. [Docs](../docs/rules/TC-CFG-015.md). |
| TC-CFG-016 | A shared setting that turns off every hook at once: Claude Code and Copilot `disableAllHooks: true`, Gemini CLI `hooksConfig.enabled: false`. Cursor and Windsurf document no such key. High: this also disables any hook-based guard the harness would otherwise run, including Tripcord's own once hook mode ships. Detecting that a previously-present hook was deleted needs a base to diff against and is out of scope here; see [docs](../docs/rules/TC-CFG-016.md). |

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
