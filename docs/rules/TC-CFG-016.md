# TC-CFG-016: Shared config turns off every hook

| | |
| --- | --- |
| Severity | high |
| Harnesses | Claude Code, GitHub Copilot, Gemini CLI; Cursor and the embed's own files for the embed case only |
| Files | `.claude/settings.json`, `.github/copilot/settings.json`, `.github/hooks/*.json`, `.copilot/hooks/*.json`, `.copilot/settings.json`, `.gemini/settings.json`, `.cursor/hooks.json` (any depth, repository or user scope); for the embed, `.tripcord/bootstrap.sh`, `.tripcord/embed.json`, `.github/workflows/tripcord.yml`, `.github/workflows/copilot-setup-steps.yml`, `.gitattributes`; tracked, or staged, `.claude/settings.local.json`, `.github/copilot/settings.local.json`, and `.tripcord/policy.local.yaml`; `.tripcord/policy.yaml` with a base (repository scope; the embed is a repository tree) |
| Rule | [`rules/TC-CFG-016.yaml`](../../rules/TC-CFG-016.yaml) |

## What it detects

A hook-based guard only runs when the harness actually invokes hooks at
all. A repository or user setting that turns every hook off at once defeats that,
regardless of which specific hook is the guard, including the one
[`tripcord init --embed`](../init.md) registers.

The rule reports two things:

1. A shared setting that turns every hook off (the table below).
2. A Tripcord embed whose guard is missing, edited, or unreadable, or,
   in a pull request, removed or weakened (see "Embedded repositories"
   below).

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
- A `settings.local.json` (Claude Code, Copilot) git does not track. It
  is personal. A tracked one is checked as described under "Local
  settings" below.

## Embedded repositories

A repository is embedded when it has `.tripcord/bootstrap.sh` or
`.tripcord/embed.json`. A `.tripcord/policy.yaml` alone, which plain
`tripcord init` writes, is not an embed. A repository that has lost
both files is still checked when a leftover piece only `init --embed`
writes is there: `.github/workflows/tripcord.yml`, or a hook that runs
`.tripcord/bootstrap.sh hook` (a string command, or an argv array whose
`bootstrap.sh` item is followed by `hook`). A `session-start` hook
alone is not a leftover. A leftover reports only what it implies: the
missing `bootstrap.sh` and `embed.json`, plus that harness's hooks for
a hook leftover, or the workflow for a workflow leftover. A hook that
runs `tripcord` some other way (for example `/usr/local/bin/tripcord
hook ...`) is manual wiring, not an embed, and does not make the
repository embedded.

The check covers:

| Subject | File | Compared with |
| --- | --- | --- |
| Bootstrap | `.tripcord/bootstrap.sh` | What init renders for the version and checksums in `embed.json`, then the digest `embed.json` records |
| Manifest | `.tripcord/embed.json` | It must parse, with a valid pin |
| Workflow | `.github/workflows/tripcord.yml` | What init renders, then the recorded digest |
| Copilot setup step | `.github/workflows/copilot-setup-steps.yml` | The `Tripcord bootstrap` step init writes, then the recorded digest (when the manifest records the step, or the file still contains it; `init --embed --cloud-setup`) |
| Claude Code hooks | `.claude/settings.json` | `SessionStart`, `PreToolUse` |
| Cursor hooks | `.cursor/hooks.json` | `sessionStart`, `preToolUse` |
| GitHub Copilot hooks | `.github/hooks/tripcord.json` | `sessionStart`, `preToolUse` |
| Gitattributes | `.gitattributes` | `text eol=lf` for `bootstrap.sh`, `embed.json`, `tripcord.yml`, and the Copilot hook file |

Hooks are checked for each hook-capable harness the manifest records
as selected at init time; with no manifest, or one that cannot be
read, all three. Each item is reported, high, at its file, with a
title and fix for its state:

| State | Title | Meaning |
| --- | --- | --- |
| missing | Tripcord embed is missing part of its guard | The file, hook, or step is not there. |
| changed | Tripcord guard was edited | It differs from what init writes for the recorded pin and from the recorded digest, or `.tripcord` or `bootstrap.sh` is a symlink. |
| stale | Tripcord guard was written by an older Tripcord | It matches the digest `embed.json` records, but not what this build writes. Rerun `tripcord init --embed --force` with the same pins. |
| unreadable | Tripcord guard file cannot be read | The file cannot be read or parsed, or is a symlink out of the repository. |

Because `bootstrap.sh` is compared with the script re-rendered from
the recorded pin, an edit to it is reported whether or not the
manifest's digest was edited to match: `changed` when it was not,
`stale` when it was. Tamper cases covered by tests include replacing
the checksum comparison with `false`, the scan with `exit 0`, the whole
script with `curl | sh`, adding a package download, moving the cache,
swapping a checksum, and swapping the version.

A symlinked `.tripcord` directory or `bootstrap.sh` is reported as
changed even when its target holds the right bytes: the hooks run the
path, and the target can change without a reviewed edit to the
repository. `bootstrap.sh` also refuses to run through one.

Files are hashed with CRLF normalized to LF, but only when every line
in the checked-out file ends in CRLF, the way a real
`core.autocrlf=true` checkout converts them; a file with a `\r` on only
one line, among otherwise plain `\n` lines, is hashed as its raw bytes
instead, so an injected carriage return is not normalized away before
the compare. A blob read directly from git (the base revision, or a
`--staged` scan's index tree, both read with no checkout filter) never
gets this leniency, whichever lines it has. `init --embed` also writes
`.gitattributes` lines (`text eol=lf`) that stop CRLF conversion in a
real Windows checkout, because `bash` cannot run a CRLF `bootstrap.sh`.

The scan checks that `.gitattributes` still resolves `text eol=lf` for
`bootstrap.sh`, `embed.json`, `tripcord.yml`, and the Copilot hook
file: git resolves an attribute by the last matching pattern in the
file, so a later line for the same pattern (`-text`, `eol=crlf`) undoes
an earlier one, including Tripcord's own, and lets a `\r` survive in a
checkout, or a committed file, that the digest would otherwise have
converted away while `bash` still sees it. `.gitattributes` itself is
reported missing, changed (including a symlink, or a later line that
weakens it), or unreadable the same way `bootstrap.sh` is, and, with a
base, removed.

### Pull requests

With a base revision (`tripcord scan --since <rev>` or `--base <rev>`;
the composite action passes the pull request's base commit), the scan
also compares the head with the base when the base is embedded:

| State | Title | Meaning |
| --- | --- | --- |
| removed | This change removes Tripcord's guard | The base had the file or a Tripcord hook and the change removes it, including removing the whole embed. |
| dropped | This change drops a harness from the Tripcord embed | A harness the base manifest records is gone from the head's. Its hooks are still checked. |
| repinned | This change re-pins Tripcord | The version or a checksum changed. A consistent re-pin of `bootstrap.sh` and `embed.json` is the one edit the head alone cannot tell from a release update, so it needs review. |
| weakened | This change weakens the Tripcord policy | The head's `.tripcord/policy.yaml` (with what it `extends`) reports or fails on less than the base's: a weaker `mode`, a higher `fail-on`, a dropped harness or rule, a lower severity override, a new exception, or a removed custom rule or lock. One item per aspect, at `.tripcord/policy.yaml`. |

With a base, the scan loads the repository policy from the base, as
`pr-context` does, and does not read `.tripcord/policy.local.yaml`, so
a pull request cannot relax the scan of itself. `weakened` applies
whether or not the repository is embedded. An explicit `--policy` file
inside the repository is read from the base the same way; one outside
the repository (shared, machine-local, or managed) is used as given.

### Local settings

Claude Code applies `.claude/settings.local.json` over
`.claude/settings.json`
([Claude Code settings](https://code.claude.com/docs/en/settings)).
Copilot CLI documents `.github/copilot/settings.local.json` as
"Personal overrides (add this to .gitignore)" that use "the same schema
as the repository configuration file" and take precedence over it, and
it also reads `.claude/settings.json` and `.claude/settings.local.json`
for a shared subset that includes `disableAllHooks` and `hooks`
([Copilot CLI config directory reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference)).
Its hooks reference loads inline hooks from either settings file, and
runs every source's entries for an event
([Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)).

A `settings.local.json` git tracks is shared configuration, not
personal. In an embedded repository, and in any scan with a base, the
rule reports a tracked one, high:

| State | Title | Meaning |
| --- | --- | --- |
| local-disabled | Committed settings.local.json turns off every hook | It sets `disableAllHooks: true`. |

Both harnesses merge hooks across files rather than letting a local one
replace the shared file's hook for the same event, so a tracked
`settings.local.json` that only adds its own hook for an event the
embed also wires is not reported; `disableAllHooks` is still checked.
An untracked `settings.local.json`, or one that does not parse, is not
reported.

`.tripcord/policy.local.yaml` is the same kind of per-checkout layer:
[scan.md](../scan.md) documents it as never read for a head compared
with a base, and `tripcord init --embed` adds it to `.gitignore`, so it
is meant to stay personal too. A copy the repository tracks, or a
staged change stages, overrides the effective policy for everyone who
checks the branch out, not only the person who committed it, the
opposite of what a per-checkout layer is for, and the scan does not
load it, so it cannot relax the decision on itself either, including
on this clause. A differently-cased copy (`.tripcord/Policy.local.yaml`,
`.TRIPCORD/policy.local.yaml`) is reported the same way, at its own
real, cased path, whatever the host filesystem: git's own tracking is
always case-exact, but a case-insensitive checkout (macOS, Windows)
resolves the policy loader's own file read to one of these behind
git's back:

| State | Title | Meaning |
| --- | --- | --- |
| local-policy | A committed policy.local.yaml overrides everyone's policy | The repository tracks, or a staged change stages, `.tripcord/policy.local.yaml`. |

The `disableAllHooks` advice in the rule's fix applies to the first
clause only; each embed, local, and `.gitattributes` state carries its
own fix.

Codex, Jules, and Devin have no repository hooks; their wiring
(`AGENTS.md`, `.devin/blueprint.yaml`) is not checked.

A fresh `init --embed` output, for any harness selection, is not
reported.

## Limits

- The disable-all clause only reads a config value that is present and
  set to the disabling value. It cannot tell which other hook a
  partial disable targets.
- Without a base revision the embed check reads one tree. A change
  that removes the embed and every leftover piece, or re-pins
  `bootstrap.sh` and `embed.json` consistently, is only reported with
  `--since` or `--base`. A `--staged` pre-commit scan has no base.
- The hook `init --embed` wires runs [`tripcord hook`](../hook.md).
  The `disableAllHooks` finding also weakens whatever other hook-based
  checks the harness or its plugins run.

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

For a missing, edited, or stale Tripcord guard, run `tripcord init
--embed --force` with the version and checksums recorded in
`.tripcord/embed.json` to restore it. If a harness is no longer used,
remove it from `.tripcord/embed.json`'s `harnesses` in a reviewed
change. For a pull request that removes the guard or re-pins Tripcord,
restore the base's files, or check that the new pin matches a
published release before approving.

## References

- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
- [Copilot CLI config directory reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference)
- [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Gemini CLI documentation](https://geminicli.com/docs/)
- [Cursor hooks](https://cursor.com/docs/hooks)
- [Cursor third-party hooks](https://cursor.com/docs/reference/third-party-hooks)
- [Cascade hooks](https://docs.windsurf.com/windsurf/cascade/hooks)
- [Novee: The Sandbox is a Suggestion](https://novee.security/blog/breaking-ai-agent-sandboxes/)
