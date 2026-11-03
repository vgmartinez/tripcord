# TC-CFG-016: Shared config turns off every hook

| | |
| --- | --- |
| Severity | high |
| Harnesses | Claude Code, GitHub Copilot, Gemini CLI; Cursor for the embed case only |
| Files | `.claude/settings.json`, `.github/copilot/settings.json`, `.github/hooks/*.json`, `.gemini/settings.json`, `.cursor/hooks.json` (any depth, repository scope) |
| Rule | [`rules/TC-CFG-016.yaml`](../../rules/TC-CFG-016.yaml) |

## What it detects

A hook-based guard only runs when the harness actually invokes hooks at
all. A shared setting that turns every hook off at once defeats that,
regardless of which specific hook is the guard, including the one
[`tripcord init --embed`](../init.md) registers.

The rule reports two things:

1. A shared setting that turns every hook off (the table below).
2. A Tripcord embed whose own hook wiring is missing or no longer calls
   tripcord (see "Embedded repositories" below).

| Harness | Setting |
| --- | --- |
| Claude Code | `disableAllHooks: true` |
| GitHub Copilot | `disableAllHooks: true` (`.github/copilot/settings.json`, or `.github/hooks/*.json`'s own `disableAllHooks`) |
| Gemini CLI | `hooksConfig.enabled: false` |

Cursor and Windsurf are not in the table. Neither documents a
file-level setting that turns every hook off, and this rule does not
guess a key.

Cursor's hooks reference lists one global option, `version`
([Cursor hooks](https://cursor.com/docs/hooks), reviewed 2026-11-02).
Loading Claude Code hooks is a Cursor Settings toggle, Agents →
Third-Party Imports → Include Third-Party Plugins, Skills, and Other
Configs
([Third Party Hooks](https://cursor.com/docs/reference/third-party-hooks)).
That toggle is not a key in a committed file.

Windsurf's Cascade hooks page
([Cascade hooks](https://docs.windsurf.com/windsurf/cascade/hooks)),
reviewed for this adapter on 2026-10-31, documents handler fields
`command`, `powershell`, `show_output`, and `working_directory`, and no
disable-all key. Fetched again on 2026-11-02, that URL serves Devin
Local's customization page. That page does not document a committed
disable-all key either. It says hooks neither load nor run while a
workspace is open in Restricted Mode, which is a workspace mode, not a
setting in `hooks.json`.

Gemini CLI's `hooksConfig.disabled` is a list of specific hook names,
not a blanket switch; this rule does not try to tell which hook a
partial disable targets, the same way it does not try to tell which
hook a deletion removed (see "Limits" below).

Not reported:

- `disableAllHooks: false`, or `hooksConfig.enabled: true`.
- Gemini CLI's `hooksConfig.disabled` naming specific hooks, without
  `enabled: false`.
- `settings.local.json` (Claude Code, Copilot), which is personal and
  is not part of this rule's files.

## Embedded repositories

A repository is embedded when it has `.tripcord/bootstrap.sh` or
`.tripcord/embed.json`. A `.tripcord/policy.yaml` alone, which plain
`tripcord init` writes, is not an embed.

For an embedded repository, the scan checks the hooks `init --embed`
writes for each hook-capable harness the manifest records as selected
at init time. With no manifest, or one that cannot be read, it checks
all three.

| Harness | Wiring file | Hooks |
| --- | --- | --- |
| Claude Code | `.claude/settings.json` | `SessionStart`, `PreToolUse` |
| Cursor | `.cursor/hooks.json` | `sessionStart`, `preToolUse` |
| GitHub Copilot | `.github/hooks/tripcord.json` | `sessionStart`, `preToolUse` |

Each hook is compared, by the SHA-256 of its canonical JSON, with the
entry this build of init writes. Reported, high, titled "Tripcord embed
is missing its own hook", at the wiring file:

- the wiring file is missing, or the event has no Tripcord entry;
- the event's entry was edited so it no longer matches (for example,
  it runs another command, or `onFailure: block` was removed);
- the manifest records a digest that differs from this build's entry;
- the wiring file cannot be read or parsed, or is a symlink out of the
  repository.

A wiring file that also sets `disableAllHooks: true` is reported by
the first clause as well.

Codex, Jules, and Devin have no repository hooks; their wiring
(`AGENTS.md`, `.devin/blueprint.yaml`) is not checked.

A fresh `init --embed` output, for any harness selection, is not
reported.

## Limits

- This rule only reads a config value that is present and set to the
  disabling value. It cannot tell whether a hook that used to be
  present, Tripcord's own or any other, was since removed: that needs a
  base tree to diff against, and a single scan of one tree does not
  have one. A future rule or pr-context integration that diffs a
  pull request's base and head could cover deletion directly; this
  rule covers only the config precondition that defeats hooks
  wholesale, which is detectable, and useful, on a single tree today.
- The embed check reads one tree. A pull request that removes the
  embed (`.tripcord/bootstrap.sh` and `.tripcord/embed.json`) together
  with the hooks leaves nothing to compare against; detecting that
  needs the base tree, which stays with TC-CFG-014 and `pr-context`.
- Removing a harness from `.tripcord/embed.json` stops its check. The
  manifest is part of the same tree a pull request can edit.
- The bootstrap script's own content is not hashed or checked here.
- The hook `init --embed` wires, `tripcord hook`, is not in this build
  (hook mode is the next change; see [init.md](../init.md)). The
  `disableAllHooks` finding stands on its own merits regardless: it
  also weakens whatever other hook-based checks the harness or its
  plugins run.

## Examples

Reported, high:

```json
{"disableAllHooks": true}
```

```json
{"hooksConfig": {"enabled": false}}
```

Not reported:

```json
{"disableAllHooks": false}
```

```json
{"hooksConfig": {"disabled": ["flaky-formatter"]}}
```

## How to fix

Remove `disableAllHooks` (Claude Code, Copilot) or
`hooksConfig.enabled: false` (Gemini CLI) from the shared file.
Disabling every hook also disables any hook-based guard the harness
would otherwise run. To pause a single hook, remove that hook's own
entry, or use the harness's managed-hooks allow list, instead of a
blanket switch.

For a missing or edited Tripcord hook, run `tripcord init --embed`
again with the same pins to restore it (`--force` replaces an edited
entry). If a harness is no longer used, remove it from
`.tripcord/embed.json`'s `harnesses`.

## References

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Gemini CLI documentation](https://geminicli.com/docs/)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [Cursor third-party hooks](https://cursor.com/docs/reference/third-party-hooks)
- [Cascade hooks](https://docs.windsurf.com/windsurf/cascade/hooks)
- [Novee: The Sandbox is a Suggestion](https://novee.security/blog/breaking-ai-agent-sandboxes/)
