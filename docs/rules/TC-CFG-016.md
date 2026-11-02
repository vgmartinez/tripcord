# TC-CFG-016: Shared config turns off every hook

| | |
| --- | --- |
| Severity | high |
| Harnesses | Claude Code, GitHub Copilot, Gemini CLI |
| Files | `.claude/settings.json`, `.github/copilot/settings.json`, `.github/hooks/*.json`, `.gemini/settings.json` (any depth, repository scope) |
| Rule | [`rules/TC-CFG-016.yaml`](../../rules/TC-CFG-016.yaml) |

## What it detects

A hook-based guard only runs when the harness actually invokes hooks at
all. A shared setting that turns every hook off at once defeats that,
regardless of which specific hook is the guard, including Tripcord's
own once its hook mode ships (see [docs/README.md](../README.md),
"Decisions").

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

## Limits

- This rule only reads a config value that is present and set to the
  disabling value. It cannot tell whether a hook that used to be
  present, Tripcord's own or any other, was since removed: that needs a
  base tree to diff against, and a single scan of one tree does not
  have one. A future rule or pr-context integration that diffs a
  pull request's base and head could cover deletion directly; this
  rule covers only the config precondition that defeats hooks
  wholesale, which is detectable, and useful, on a single tree today.
- A tree that contains `.tripcord/policy.yaml` or
  `.tripcord/bootstrap.sh` but no hook invoking tripcord is not
  reported. v0 has no `tripcord init` subcommand
  ([fingerprint.md](../fingerprint.md) records that), so there is no
  `init --embed` output that names the wiring files such a check would
  compare against. A missing file emits no config item. The
  embed-present-but-wiring-missing case is deferred to the week-4
  `init --embed` work in [issue #39](https://github.com/vgmartinez/tripcord/issues/39).
- Tripcord does not yet register its own hook in any harness (hook mode
  is implemented later; see [docs/README.md](../README.md),
  "Decisions"). This rule's finding stands on its own merits
  regardless: a shared `disableAllHooks: true` also weakens whatever
  other hook-based checks the harness or its plugins run, which is a
  real present-day risk, not only a future one.

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

## References

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Gemini CLI documentation](https://geminicli.com/docs/)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [Cursor third-party hooks](https://cursor.com/docs/reference/third-party-hooks)
- [Cascade hooks](https://docs.windsurf.com/windsurf/cascade/hooks)
- [Novee: The Sandbox is a Suggestion](https://novee.security/blog/breaking-ai-agent-sandboxes/)
