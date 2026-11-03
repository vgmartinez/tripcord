# `tripcord init`

```text
tripcord init [PATH] [--embed] [--harness h,...] [--version V --sha256 os-arch=HEX ...] [--force] [--dry-run]
```

`init` writes Tripcord's files into the repository at `PATH` (default:
the current directory). `PATH` must be the repository root: a
subdirectory of a Git repository exits 3.

> **Not releasable yet.** `init --embed` wires each hook-capable harness
> to run `bash .tripcord/bootstrap.sh hook --harness <h> --event
> pre-tool`, which runs the verified binary's `tripcord hook`. This
> build has no `hook` subcommand; hook mode is the next pull request.
> Until it lands, the Claude Code hook blocks every tool call
> (`onFailure: block`) and the Cursor hook fails closed. Do not cut a
> release that contains `init --embed` before hook mode. `make
> release-gate` (see "Release gate" below) fails until then.
>
> The generated `.github/workflows/tripcord.yml` pins the reusable
> workflow, and this repository's own workflows pin the composite
> action, at `main@8b33b1b`, the merge that added the embed check and
> `scan --base`. The workflow file at that commit still calls the
> action at `main@141db48`, which has neither, so a repository that
> runs the generated workflow still scans the head tree alone. A later
> pin of the reusable workflow, at a commit whose own action pin is
> `8b33b1b` or later, is what makes that scan compare a pull request
> with its base. `TestPinsHaveEmbedCheck` requires every pin to be a
> full SHA on main whose tree contains `internal/embedded` and
> TC-CFG-016.

## Without `--embed`

Writes `.tripcord/policy.yaml` with the scan defaults from
[policy.md](policy.md):

```yaml
version: 1
mode: enforce
fail-on: high
```

An existing policy file is kept as it is. `--harness`, `--version`, and
`--sha256` without `--embed` exit 3.

## With `--embed`

`--version` and `--sha256` are required. `--sha256` takes
`os-arch=HEX`, one per platform the repository's agents run on, and is
repeatable. Platforms are `darwin-arm64`, `darwin-x64`, `linux-arm64`,
and `linux-x64`. A missing version, a missing checksum, a malformed
value, or an unknown platform exits 3 and writes nothing. There are no
placeholder values.

Files written for every selection:

| File | Content |
| --- | --- |
| `.tripcord/policy.yaml` | Policy, as without `--embed`. |
| `.tripcord/bootstrap.sh` | Pinned installer (mode `0755`). See "Bootstrap". |
| `.tripcord/embed.json` | Manifest: the pinned version and checksums, the harnesses selected at init time, the SHA-256 of `bootstrap.sh`, `tripcord.yml`, and the generated `copilot-setup-steps.yml` step, and the SHA-256 of every hook entry init wrote. |
| `.github/workflows/tripcord.yml` | Pull request scan. See "Workflow". |
| `.gitattributes` | `text eol=lf` for `bootstrap.sh`, `embed.json`, `tripcord.yml`, and `.github/hooks/tripcord.json`, under a `# Tripcord embed` comment. Lines already there are kept; missing ones are appended, in the file's own line ending. |
| `.gitignore` | `/.tripcord/policy.local.yaml`, appended if not already there, in the file's own line ending. `policy.local.yaml` is a per-checkout layer (see [policy.md](policy.md)); this keeps a fresh checkout from tracking one by accident. |

`bash` cannot run a `bootstrap.sh` with CRLF line endings, and the scan
hashes these files, so the `.gitattributes` lines keep a Windows
checkout with `core.autocrlf=true` from converting them. The scan also
hashes the files with CRLF normalized to LF, so a checkout that was
already converted is not reported as edited, and init treats a
Tripcord-owned file that differs only by CRLF as its own and rewrites
it with LF.

Files written per harness. `--harness` takes a comma-separated subset;
empty means all five.

| `--harness` | Files |
| --- | --- |
| `claude` | `.claude/settings.json`: `hooks.SessionStart` runs `bash "${CLAUDE_PROJECT_DIR}/.tripcord/bootstrap.sh" session-start --harness claude`; `hooks.PreToolUse` runs `bash "${CLAUDE_PROJECT_DIR}/.tripcord/bootstrap.sh" hook --harness claude --event pre-tool` with `onFailure: block`. |
| `cursor` | `.cursor/hooks.json`: `sessionStart` runs `bash "${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh" session-start --harness cursor`; `preToolUse` runs `bash "${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh" hook --harness cursor --event pre-tool` with `failClosed: true`. `.cursor/environment.json`: `install` runs `bash .tripcord/bootstrap.sh install`. |
| `copilot` | `.github/hooks/tripcord.json`: `sessionStart` runs `bash .tripcord/bootstrap.sh session-start --harness copilot` (`timeoutSec: 300`); `preToolUse` runs `bash .tripcord/bootstrap.sh hook --harness copilot --event pre-tool` (`timeoutSec: 60`). Both set `cwd: "."`. `.github/workflows/copilot-setup-steps.yml`: a `Tripcord bootstrap` step. |
| `devin` | `.devin/blueprint.yaml`: a `maintenance` entry named `tripcord`. |
| `codex` | `AGENTS.md`: a note between `<!-- tripcord:begin -->` and `<!-- tripcord:end -->` asking the environment setup script to run the bootstrap. This covers Codex and Jules, which have no repository hooks. |

No hook runs a `tripcord` found on `PATH`. Every hook runs the
repository's own `bootstrap.sh` by path, and the bootstrap runs the
cached binary by absolute path after checking it against the pinned
SHA-256 (see "Bootstrap"). The Claude Code pre-tool entry:

```json
{"matcher": "*", "hooks": [{"type": "command",
  "command": "bash \"${CLAUDE_PROJECT_DIR}/.tripcord/bootstrap.sh\" hook --harness claude --event pre-tool",
  "onFailure": "block"}]}
```

Claude Code and Cursor expand their project-directory variable
(`CLAUDE_PROJECT_DIR`, `CURSOR_PROJECT_DIR`), so the hook finds the
script from any working directory. Copilot has no such variable; its
`cwd` is relative to the repository root, so `cwd: "."` plus the
relative script path is its equivalent.

Copilot's hook format has no fail-closed field, so none is written. A
Copilot `preToolUse` hook that exits non-zero denies the tool call, but
a hook that times out is let through: Copilot fails open on a hook
timeout. init sets `timeoutSec` (60 for `preToolUse`, 300 for
`sessionStart`, against Copilot's default of 30) so a cold start does
not hit it; the pre-tool hook never installs, so it only verifies a
checksum and runs the binary.

Running init again with a different `--harness` adds the new
harnesses' wiring; the manifest keeps the union.

## Merging

init never replaces a file it did not write.

- JSON files (`settings.json`, `hooks.json`, `environment.json`,
  `.github/hooks/tripcord.json`): existing keys keep their order and the
  file keeps its indentation. New keys are appended. A Tripcord entry
  is added to an event's array only if an identical entry is not
  already there.
- YAML files (`copilot-setup-steps.yml`, `blueprint.yaml`): the step or
  maintenance entry is appended.
- `AGENTS.md`: the note is appended after the existing text.
- Files only Tripcord writes (`bootstrap.sh`, `tripcord.yml`,
  `embed.json`) must already match what init would write.

A second run on unchanged files writes byte-identical output and
reports every file `unchanged`.

A file init cannot merge exits 3, lists every such file on stderr, and
writes nothing. Two kinds:

- **Conflicts**, which `--force` overrides:
  - a JSON or YAML file whose formatting a merge would change (for
    example, compact JSON or a different YAML indent);
  - an existing entry for the same event that names tripcord but
    differs from init's (it is replaced);
  - `disableAllHooks: true` in a hook file (it is left in place, and
    TC-CFG-016 reports it);
  - a different `install` in `.cursor/environment.json` (it becomes
    `bash .tripcord/bootstrap.sh install && <existing>`);
  - a different tripcord step in `copilot-setup-steps.yml`, or a setup
    workflow without a checkout step;
  - a scalar `maintenance` in `blueprint.yaml` (it becomes a list);
  - a Tripcord-owned file, or the `AGENTS.md` note, with other content
    (it is rewritten).
- **Unmergeable**, which `--force` does not override: a file that does
  not parse (including JSON with comments in `.cursor/hooks.json`), a
  duplicate JSON key, a hook file `version` other than 1, `hooks` that
  is not an object, an event that is not an array, a setup workflow
  without `jobs.copilot-setup-steps.steps`, or an `AGENTS.md` begin
  marker with no end marker.

## Safety

- Every write is atomic: a temporary file in the same directory is
  synced, given its mode, and renamed over the target.
- Files are opened through an `os.Root` at `PATH`. init refuses a
  target that is a symlink, a target any of whose parent directories is
  a symlink, and a target that is not a regular file. This applies to
  symlinks that stay inside the repository as well as ones that leave
  it. The refusal exits 3 and writes nothing.
- Files over 1 MiB are not read.

## `--dry-run`

Prints a unified diff of every file init would create or change, then
`dry run, nothing written` on stderr, and writes nothing. Merge
failures exit 3 as without `--dry-run`.

## Bootstrap

```text
bash .tripcord/bootstrap.sh install
bash .tripcord/bootstrap.sh session-start [--harness claude|cursor|copilot]
bash .tripcord/bootstrap.sh hook --harness <h> --event <e>
```

`install` and `session-start` install the pinned release and then run
`tripcord scan --config` on the repository. `hook` never installs: it
checks the cached binary against the pinned SHA-256 and `exec`s it by
absolute path as `tripcord hook --harness <h> --event <e>`. Without a
verified cached binary it exits 1 and asks for `bootstrap.sh install`;
the harness then blocks the tool call where it fails closed.

- The install sources default to `npm pypi cache`, tried in that
  order: `npm pack @tripcord/cli-<os>-<arch>@<version>
  --ignore-scripts`, then `pip download tripcord==<version> --no-deps
  --only-binary=:all:`, then a binary already in the cache at
  `${XDG_CACHE_HOME:-$HOME/.cache}/tripcord/<version>/<os-arch>/tripcord`.
  Set `TRIPCORD_INSTALL_SOURCES` in the environment to a
  space-separated subset, in any order, to change that for one run
  (for example `TRIPCORD_INSTALL_SOURCES=cache` on an offline runner).
  Any other word exits 3.
- Every candidate, cached or downloaded, is checked against the pinned
  SHA-256 for the running platform before it is used. A mismatch is
  discarded. The source setting only chooses where to look; it cannot
  make an unverified binary run.
- There is no fallback to latest, to another version, or to
  `curl | sh`. An unpinned platform exits 3; no network and no valid
  cache, or a bad checksum, exits 1. Any other mode exits 2.
- The cache directory must be an absolute path; a relative
  `XDG_CACHE_HOME` exits 3.
- Downloads go to a `mktemp -d` directory with mode `0700`, removed on
  exit. The verified binary is moved into the cache atomically.
- The script changes no `PATH`: it writes nothing to `GITHUB_PATH` or
  `CLAUDE_ENV_FILE`.

Output: diagnostics and the scan report go to stderr. stdout carries
only what the harness parses: `{}` for a Cursor `session-start`, even
when the bootstrap fails, and the binary's own output in `hook` mode.
Claude Code and Copilot read nothing from a session-start hook's
stdout.

The npm and PyPI packages are pending the distribution pipeline and are
not published. Until they are, only a cached binary can satisfy the
bootstrap, and on a machine without one it fails closed.

The script is POSIX `sh`, quotes every expansion, and uses no `eval`.
CI runs shellcheck on it (`init --embed output lint` in
`.github/workflows/ci.yml`).

## Workflow

`.github/workflows/tripcord.yml` runs on `pull_request` only, never
`pull_request_target`, with a `paths` filter over agent configuration.
Workflow permissions are `contents: read`; the job adds
`pull-requests: read` and `security-events: write`. It calls this
repository's `.github/workflows/tripcord-pr.yml` pinned by full commit
SHA, with the short SHA in a trailing comment. CI runs actionlint and
zizmor on it and on the generated `copilot-setup-steps.yml`, which also
has to pass zizmor's `pedantic` persona.

The workflow only protects the branch if a failing run blocks the
merge. Make its job a required status check in the protected branch's
rule (or ruleset) for the default branch: the check is named
`scan / Tripcord`. Without that, a pull request that removes the embed
reports TC-CFG-016 and can still be merged.

## Guard identity and TC-CFG-016

Each hook entry init writes is identified by the SHA-256 of its event
name and the entry's canonical JSON (sorted keys, no whitespace). The
Copilot setup step is identified the same way. `bootstrap.sh` and
`tripcord.yml` are identified by the SHA-256 of their bytes. The
manifest records all of those digests. A fresh embed scans with no
findings.

The scan checks the embed when `.tripcord/bootstrap.sh` or
`.tripcord/embed.json` exists, and also when only a leftover piece
does: `.github/workflows/tripcord.yml`, or a hook that runs
`.tripcord/bootstrap.sh hook` (the guard; a `session-start` hook alone
is not a leftover). A leftover reports only what it implies: the
missing `bootstrap.sh` and `embed.json`, plus the hooks of the harness
whose hook was left, or the workflow when the workflow was left.
Otherwise it compares each hook harness recorded in the
manifest (all three when the manifest is missing or unreadable) with
what init writes. A `.tripcord` directory or `bootstrap.sh` that is a
symlink is reported as changed, and `bootstrap.sh` refuses to run
through one. `bootstrap.sh` and `tripcord.yml` are compared with
what init renders again from the version and checksums recorded in
the manifest, not only with the recorded digests, so editing the
script and the manifest's digest together still reports.
[TC-CFG-016](rules/TC-CFG-016.md) reports, high:

- **missing**: a file, hook, or setup step is not there;
- **changed**: it differs from what init writes for the recorded pin
  and from the recorded digest;
- **stale**: it matches the recorded digest but not what this build
  writes, because an older Tripcord wrote it (rerun `tripcord init
  --embed --force` with the same pins), or because its digest in
  `embed.json` was edited to match;
- **unreadable**: a file cannot be read or parsed.

`bootstrap.sh`, `tripcord.yml`, and the Copilot hook file are hashed
with CRLF normalized to LF, but only when every line in the checked-out
file ends in CRLF, the way a real `core.autocrlf=true` checkout
converts them; a file with a `\r` on only one line is hashed as its raw
bytes instead, so the digest still sees it. A blob read directly from
git (a base revision, or a `--staged` scan's index tree) never gets
this leniency, whichever lines it has. The scan also checks that
`.gitattributes` still resolves `text eol=lf` for every file this
normalizes: removing those lines, or a later line for the same pattern
that turns the file's `text` or `eol` attribute back off (`-text`,
`eol=crlf`), is itself reported the same way `bootstrap.sh` itself is
(missing, changed, or removed with a base), because it is what lets a
checkout, or the repository, keep a `\r` the digest would otherwise
have normalized away while `bash` still sees it.

### Pull requests

A pull request can rewrite `bootstrap.sh` and `embed.json` together, for
example re-pinning to a different checksum, or delete the whole embed.
The head tree alone cannot tell that from a legitimate change. With a
base revision, `tripcord scan --since <rev>` or `tripcord scan --base
<rev>`, the scan also compares the embed with the base's when the base
has one, and reports, high:

- **removed**: the base had the file or a Tripcord hook and the change
  removes it, including removing the embed entirely;
- **dropped**: the change drops a harness from the manifest;
- **repinned**: the change changes the pinned version or a checksum;
- **weakened**: the change weakens `.tripcord/policy.yaml` (see
  [scan.md](scan.md)).

A committed `.claude/settings.local.json` or
`.github/copilot/settings.local.json` that sets `disableAllHooks: true`
(**local-disabled**) is reported too; both harnesses merge hooks across
files rather than letting a local one replace the shared file's hook
for the same event, so a local hook for an event the embed also wires
is not. A committed, or staged, `.tripcord/policy.local.yaml`
(**local-policy**) is reported the same way: it is a per-checkout
layer, so a copy the repository tracks overrides the effective policy
for everyone who checks the branch out, not only the person who added
it. The scan never loads it to decide its own outcome, with or without
a base; see [TC-CFG-016](rules/TC-CFG-016.md).

With a base, an explicit `--policy` path inside the repository is also
read from the base revision, the same as the implicit
`.tripcord/policy.yaml`: the change under review cannot relax its own
copy of the file named on the command line either. A path outside the
repository (shared, machine-local, or managed) is still used as given,
unaffected by the base; see [scan.md](scan.md).

The composite action passes `--base` with the pull request's base
commit (its `base` input), so the reusable workflow reports these on
pull requests once its pin includes this change (see the note at the
top). A forged `embed.json` plus `bootstrap.sh` in one pull request is
caught there as `repinned` or `changed`.

## Release gate

Two tests run only with `TRIPCORD_RELEASE_GATE=1`:

```sh
make release-gate
```

`TestReleaseGateHookSubcommand` (`cmd/tripcord/init_test.go`) runs
`tripcord` with the arguments each harness's wiring passes through
`bootstrap.sh`, and fails, without skipping, if this build answers with
an unknown command.

`TestReleaseGatePinnedActionHasEmbedCheck`
(`cmd/tripcord/release_gate_test.go`) follows both pins to the
composite action: the reusable workflow commit the generated
`tripcord.yml` calls, and the action commit this tree's
`tripcord-pr.yml` and `tripcord-pr-comment.yml` call. It fails unless
the action at each pin has the `base` input and builds a Tripcord with
the embed check (`internal/embedded`). This tree's workflows pin the
action at `main@8b33b1b`, which has both. The generated workflow calls
`tripcord-pr.yml` at that same commit, and the file there still pins
the action at `main@141db48`, which has neither, so the gate still
fails on that path until a later re-pin. It reads the pinned commits
with `git show`, so the clone must have them (`fetch-depth: 0`).
`TestReleaseGateHookSubcommand` still fails until hook mode lands;
that failure is the missing `hook` subcommand, not the pins.

Without the variable both log that the gate was not requested and pass,
so pull request CI stays green. There is no release workflow in this
repository; run the target before tagging a release.
`TestInitWiringInvokesTripcordHook` always runs and asserts the exact
command each wiring file holds, `bash <project dir>/.tripcord/bootstrap.sh
hook --harness <h> --event pre-tool`, and the fail-closed and timeout
fields.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Files written, unchanged, or a dry run. |
| 3 | Invalid flags, a missing or malformed pin, a `PATH` that is not a repository root, a symlink or non-regular target, or a file that cannot be merged. Nothing was written. |
| 4 | Internal error, including a failure while writing. |

`init` does not create the fingerprint key; `tripcord scan` still
creates it on first use ([fingerprint.md](fingerprint.md)).
