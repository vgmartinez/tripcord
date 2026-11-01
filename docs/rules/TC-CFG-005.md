# TC-CFG-005: shared config turns off approvals

| | |
| --- | --- |
| Severity | high; medium for `skipDangerousModePermissionPrompt` alone |
| Harnesses | Claude Code, Codex, Gemini CLI |
| Files | `.claude/settings.json`, `.codex/config.toml`, `.gemini/settings.json` (any depth, repository scope) |
| Rule | [`rules/TC-CFG-005.yaml`](../../rules/TC-CFG-005.yaml) |

## What it detects

A mode that removes the approval step, committed to a file every
contributor's agent loads.

| Setting | Severity |
| --- | --- |
| Claude Code: `permissions.defaultMode` `"bypassPermissions"` | high |
| Claude Code: `permissions.defaultMode` `"bypassPermissions"` and `skipDangerousModePermissionPrompt: true` in the same file | high, one finding |
| Claude Code: `skipDangerousModePermissionPrompt: true` without bypassPermissions | medium |
| Codex: `sandbox_mode = "danger-full-access"` | high |
| Codex: `approval_policy = "never"` | high |
| Codex: either of the above in a `[profiles.<name>]` table | high |
| Gemini CLI: `general.defaultApprovalMode` `"yolo"` | high |
| Gemini CLI: `tools.autoAccept: true`, or the older flat `autoAccept: true` | high |

With bypassPermissions, Claude Code runs every tool call without a
prompt. `skipDangerousModePermissionPrompt` removes the warning Claude
Code shows when that mode is switched on, so on its own it is medium:
it does not turn approvals off, but anyone who turns the mode on is no
longer warned. When both are in one file, the finding is reported once,
on `permissions`, with a title that names both.

`danger-full-access` runs Codex commands with no sandbox, so the
approval policy no longer protects anything outside the workspace;
`approval_policy = "never"` runs every command without asking. A
profile is evaluated exactly like the top level. Codex does not apply
`profile` or `profiles` from a project config, but the file is still
shared and its profiles are copied into user configs, so the rule does
not rely on that.

In Gemini CLI, yolo approves every tool call and `autoAccept` approves
the tool calls it considers safe without asking.

A Codex config with both `danger-full-access` and
`approval_policy = "never"` is two findings, one per setting.

**Case.** Each value is compared the way its harness reads it, and keys
are case-sensitive in all three:

| Harness | Value | Case |
| --- | --- | --- |
| Claude Code | `defaultMode` | exact: a zod enum after mapping the alias `manual` to `default`, so `BypassPermissions` is not the mode |
| Codex | `sandbox_mode`, `approval_policy` | exact: serde enums with fixed names (`danger-full-access`, `never`) |
| Gemini CLI | `defaultApprovalMode` | exact: a string switch, and `YOLO` is rejected as an invalid mode |
| Gemini CLI | `autoAccept`, `tools.autoAccept` | `true`, or a string `"true"` in any case: the settings loader converts boolean strings case-insensitively |

Not reported:

- `.claude/settings.local.json`, which is personal and not shared.
- Other modes: `acceptEdits`, `plan`, `default`, `workspace-write`,
  `read-only`, `on-request`, `auto_edit`.
- `skipDangerousModePermissionPrompt: false`, and `autoAccept: false`.
- A value in another case where the harness compares exactly:
  `BypassPermissions`, `Danger-Full-Access`, `NEVER`, `YOLO`.
- Mentions of the mode inside other values, such as an allow rule
  `Bash(grep -rn bypassPermissions docs/)`.

Codex loads a project `.codex/` layer only in a trusted project. The
rule reports the file whatever the trust state, because the next person
to trust the project gets the mode.

## Examples

Reported, high:

```json
{
  "permissions": {
    "defaultMode": "bypassPermissions",
    "allow": ["Bash(go test ./...)"]
  }
}
```

```toml
sandbox_mode = "workspace-write"

[profiles.ci]
approval_policy = "never"
```

```json
{"general": {"defaultApprovalMode": "yolo"}}
```

Reported, medium:

```json
{"permissions": {"defaultMode": "acceptEdits"}, "skipDangerousModePermissionPrompt": true}
```

Not reported:

```json
{"permissions": {"defaultMode": "acceptEdits", "allow": ["Bash(npm run test:*)"]}}
```

```toml
sandbox_mode = "workspace-write"
approval_policy = "on-request"
```

## How to fix

Remove the mode from the shared file. In Claude Code, delete
bypassPermissions and `skipDangerousModePermissionPrompt`, and use
`acceptEdits` or the default mode with a narrow `permissions.allow`
list. In Codex, use `sandbox_mode = "workspace-write"` and an
approval policy other than `never`, in profiles too. In Gemini CLI,
remove the yolo approval mode and `autoAccept`. Someone who wants the
mode for a session can pass it on their own command line
(`--permission-mode bypassPermissions`, `--sandbox danger-full-access`,
`--yolo`) or in their user config, where it affects only them.

## References

- [Novee: The Sandbox is a Suggestion](https://novee.security/blog/breaking-ai-agent-sandboxes/)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
- [Codex config basics](https://learn.chatgpt.com/docs/config-file/config-basic.md)
- [Gemini CLI configuration](https://geminicli.com/docs/get-started/configuration/)
