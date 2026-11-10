# `tripcord init`

```text
tripcord init [PATH] [--embed] [--cloud-setup] [--harness h,...] [--version V --sha256 os-arch=HEX ...] [--force] [--dry-run]
```

`init` writes Tripcord's files into the repository at `PATH` (default:
the current directory). `PATH` must be the repository root: a
subdirectory of a Git repository exits 3. With `--embed`, `PATH` must
be a Git repository: its `.git`, after following symlinks, is a
directory or a regular file (a worktree's), as the hook requires.
Anything else exits 3 and writes nothing, because the hooks find the
policy at the Git root and would block every tool call without one.

> **Fail-closed, with two gaps.** `init --embed` wires each hook-capable
> harness to run `bash .tripcord/bootstrap.sh hook --harness <h> --event
> pre-tool --on-failure block`, which runs the verified binary's
> [`tripcord hook`](hook.md). A run that cannot decide denies the call
> (`--on-failure block`), and so does a bootstrap that finds no verified
> binary (exit 2). The harnesses also block on a failed hook: the
> Claude Code hook has `onFailure: block`, the Cursor hook `failClosed`,
> and Copilot blocks a `preToolUse` hook on any non-zero exit or crash.
> Two gaps remain. A Copilot hook that times out lets the call through;
> `tripcord hook` ends its own run after 10 s, under the 60 s
> `timeoutSec` init sets. A Claude Code release older than the
> `onFailure` field still blocks on exit 2, which every failure the hook
> reports returns, but not on another status, such as a crash or a
> missing `bash`. There is no published release, so each machine fills
> the bootstrap cache itself ([Bootstrap](#bootstrap)).
>
> The generated `.github/workflows/tripcord.yml` pins the reusable
> workflow at `main@277066a`. `tripcord-pr.yml` at that commit pins the
> composite action at `main@8b33b1b`, which has the `base` input and
> the embed check, so the generated workflow compares a pull request
> with its base. This repository's own workflows pin that same action.
> `TestPinsHaveEmbedCheck` requires every pin to be a full SHA on main,
> with a `# main@` comment, whose tree contains `internal/embedded` and
> TC-CFG-016.

## Without `--embed`

Writes `.tripcord/policy.yaml` with the scan defaults from
[policy.md](policy.md):

```yaml
version: 1
mode: enforce
fail-on: high
```

An existing policy file is kept as it is. `--harness`, `--version`,
`--sha256`, and `--cloud-setup` without `--embed` exit 3.

## With `--embed`

`--version` and `--sha256` are required. `--sha256` takes
`os-arch=HEX`, one per platform the repository's agents run on, and is
repeatable. Platforms are `darwin-arm64`, `darwin-x64`, `linux-arm64`,
and `linux-x64`. A missing version, a missing checksum, a malformed
value, or an unknown platform exits 3 and writes nothing. There are no
placeholder values.

A release build of `init` refuses a `--version` older than itself
(exit 3, nothing written): that release's `bootstrap.sh` runs its own
`scan --config`, which would then be an older TC-CFG-016 judging this
newer embed. Run the older release's `init` to pin it. A development
build (`dev`) does not check. Exit 3 here is a configuration error.
`init` does not return 2: `bootstrap.sh` with no verified binary, and
`tripcord hook` when it blocks a call, still exit 2.

Files written for every selection:

| File | Content |
| --- | --- |
| `.tripcord/policy.yaml` | Policy, as without `--embed`. |
| `.tripcord/bootstrap.sh` | Pinned installer (mode `0755`). See "Bootstrap". |
| `.tripcord/embed.json` | Manifest: the pinned version and checksums, the harnesses selected at init time, the SHA-256 of `bootstrap.sh` and `tripcord.yml`, the SHA-256 of every hook entry init wrote, and, only with `--cloud-setup`, the SHA-256 of the generated `copilot-setup-steps.yml` step. |
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
| `claude` | `.claude/settings.json`: `hooks.SessionStart` runs `bash "${CLAUDE_PROJECT_DIR:-.}/.tripcord/bootstrap.sh" session-start --harness claude`; `hooks.PreToolUse` runs `bash "${CLAUDE_PROJECT_DIR:-.}/.tripcord/bootstrap.sh" hook --harness claude --event pre-tool --on-failure block` with `onFailure: block`. |
| `cursor` | `.cursor/hooks.json`: `sessionStart` runs `bash "${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh" session-start --harness cursor`; `preToolUse` runs `bash "${CURSOR_PROJECT_DIR}/.tripcord/bootstrap.sh" hook --harness cursor --event pre-tool --on-failure block` with `failClosed: true`. |
| `copilot` | `.github/hooks/tripcord.json`: `sessionStart` runs `bash .tripcord/bootstrap.sh session-start --harness copilot` (`timeoutSec: 300`); `preToolUse` runs `bash .tripcord/bootstrap.sh hook --harness copilot --event pre-tool --on-failure block` (`timeoutSec: 60`). Both set `cwd: "."`. |
| `devin` | Recorded in the manifest. No file, unless `--cloud-setup` is set. |
| `codex` | `AGENTS.md`: a note between `<!-- tripcord:begin -->` and `<!-- tripcord:end -->` asking the environment setup script to run the bootstrap. That command does not download Tripcord. This covers Codex and Jules, which have no repository hooks. |

`--cloud-setup` is off by default. It is a known gap: `bootstrap.sh
install` downloads nothing, and v0 has no download channel, so the
files below do not install Tripcord. They only run the cached build.
Fill the cache first (see "Bootstrap"). With the flag, init also writes:

| `--harness` | File |
| --- | --- |
| `cursor` | `.cursor/environment.json`: `install` runs `bash .tripcord/bootstrap.sh install`. |
| `copilot` | `.github/workflows/copilot-setup-steps.yml`: a `Tripcord bootstrap` step. The manifest records that step's digest. |
| `devin` | `.devin/blueprint.yaml`: a `maintenance` entry named `tripcord`. |

No hook runs a `tripcord` found on `PATH`. Every hook runs the
repository's own `bootstrap.sh` by path, and the bootstrap runs the
cached binary by absolute path after checking it against the pinned
SHA-256 (see "Bootstrap"). The Claude Code pre-tool entry:

```json
{"matcher": "*", "hooks": [{"type": "command",
  "command": "bash \"${CLAUDE_PROJECT_DIR:-.}/.tripcord/bootstrap.sh\" hook --harness claude --event pre-tool --on-failure block",
  "onFailure": "block"}]}
```

Claude Code and Cursor expand their project-directory variable
(`CLAUDE_PROJECT_DIR`, `CURSOR_PROJECT_DIR`), so the hook finds the
script from any working directory. Copilot has no such variable; its
`cwd` is relative to the repository root, so `cwd: "."` plus the
relative script path is its equivalent. The Copilot CLI also runs the
hooks in `.claude/settings.json`, from the repository root and without
`CLAUDE_PROJECT_DIR`, so the Claude Code hooks fall back to the working
directory (`${CLAUDE_PROJECT_DIR:-.}`).

Copilot's hook format has no fail-closed field, so none is written. A
Copilot `preToolUse` hook that exits non-zero denies the tool call, but
a hook that times out is let through: Copilot fails open on a hook
timeout. init sets `timeoutSec` (60 for `preToolUse`, 300 for
`sessionStart`, against Copilot's default of 30) so a slow start does
not hit it; the bootstrap never installs, so a hook only verifies a
checksum and runs the binary.

Running init again with a different `--harness` adds the new
harnesses' wiring; the manifest keeps the union.

## Merging

init never replaces a file it did not write.

- JSON files (`settings.json`, `hooks.json`,
  `.github/hooks/tripcord.json`): existing keys keep their order and the
  file keeps its indentation. New keys are appended. A Tripcord entry
  is added to an event's array only if an identical entry is not
  already there.
- With `--cloud-setup`, the same JSON merge applies to
  `environment.json`, and YAML files (`copilot-setup-steps.yml`,
  `blueprint.yaml`) gain the step or maintenance entry. Without the
  flag, init does not read or rewrite those files, so a broken one does
  not fail the run.
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
  - with `--cloud-setup`, a different `install` in
    `.cursor/environment.json` (it becomes
    `bash .tripcord/bootstrap.sh install && <existing>`);
  - with `--cloud-setup`, a different tripcord step in
    `copilot-setup-steps.yml`, or a setup workflow without a checkout
    step;
  - with `--cloud-setup`, a scalar `maintenance` in `blueprint.yaml`
    (it becomes a list);
  - a Tripcord-owned file, or the `AGENTS.md` note, with other content
    (it is rewritten).
- **Unmergeable**, which `--force` does not override: a file that does
  not parse (including JSON with comments in `.cursor/hooks.json`), a
  duplicate JSON key, a hook file `version` other than 1, `hooks` that
  is not an object, an event that is not an array, a `--cloud-setup`
  setup workflow without `jobs.copilot-setup-steps.steps`, or an
  `AGENTS.md` begin marker with no end marker.

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

The diff quotes the existing files, which can hold credentials (an `env`
block, an MCP server's token), so it is redacted like any other output:
each JSON string is decoded, redacted, and re-encoded when it held a
credential, and each line is capped at 1024 bytes. A line with a control,
bidi, or invalid byte is escaped. The diff is a preview and does not
always apply as a patch. See [privacy.md](privacy.md).

## Bootstrap

```text
bash .tripcord/bootstrap.sh install
bash .tripcord/bootstrap.sh session-start [--harness claude|cursor|copilot]
bash .tripcord/bootstrap.sh hook --harness <h> --event <e> [--on-failure block|error]
```

The bootstrap never downloads or installs anything. `install` and
`session-start` copy the binary at
`${XDG_CACHE_HOME:-$HOME/.cache}/tripcord/<version>/<os-arch>/tripcord`
into a new directory of mode `0700` under
`${XDG_CACHE_HOME:-$HOME/.cache}/tripcord/.run/`, check the copy
against the SHA-256 pinned for the running platform, and run the copy
by absolute path. The file that runs is the file that was hashed, so
replacing the cached binary between the check and the run does not
work. They then record that cached file's device, inode, size, mtime,
and ctime in `verified` in the same directory, mode `0400`, and run
`tripcord scan --config` on the repository. `hook`, when that record
still matches the cached file, runs the cached file directly and does
not copy or hash it. When the record is missing, `hook` does this
verification once. When the file's identity changed, or the record is
not a private regular file, `hook` exits 2 and runs nothing until
`install` or `session-start` verifies it again. The script waits for
the binary so an execution failure can report that a `noexec` mount is
a likely cause, then removes a private copy.

The tools that decide what runs (`sha256sum` or, on macOS, `shasum`,
and `find`, `id`, `cp`, `mktemp`, `uname`, and the others the script
calls) come from `/usr/bin` or `/bin`, then from NixOS's
`/run/current-system/sw/bin` only when that directory is root-owned and
not group- or world-writable. They never come from the caller's `PATH`.

There is no published release, so fill the cache with a build of the
commit the pin was made from, on each machine the agents run on:

```sh
git checkout <pinned commit>
cache="${XDG_CACHE_HOME:-$HOME/.cache}/tripcord/<version>/<os-arch>"
(
  umask 022
  mkdir -p "$cache"
)
chmod go-w "${cache%/*/*}" "${cache%/*}" "$cache"
CGO_ENABLED=0 go build -trimpath -o "$cache/tripcord" ./cmd/tripcord
sha256sum "$cache/tripcord"
```

The last line prints the value for `--sha256 <os-arch>=`. A
`-trimpath` build of the same commit with the same Go toolchain gives
the same bytes on every machine of a platform, so one pin covers them.

It fails closed. Each of these exits 2 with `tripcord bootstrap:
<reason>` on stderr and runs nothing:

- no binary in the cache (the reason names the path to fill);
- a binary with another SHA-256 (the reason names both digests);
- a cached binary whose device, inode, size, mtime, or ctime no longer
  matches the `verified` record, or a cached binary that is group- or
  world-writable (`hook` only: it does not re-hash, and it runs nothing
  until `install` or `session-start`);
- a binary that is a symlink or not a regular file;
- a binary without the execute bit (`chmod 0755` it), rather than the
  shell's 126; or a binary that still cannot execute, for which a
  `noexec` mount is a likely cause;
- a cache directory, from `tripcord/` down to `<os-arch>/` and
  including `tripcord/.run/`, that is a symlink, is owned by another
  user, or is group- or world-writable (`chmod go-w` it): another user
  could swap the binary there;
- no SHA-256 pinned for the platform, or an unsupported OS or
  architecture;
- no `sha256sum` or `shasum` in `/usr/bin` or `/bin`;
- a relative `XDG_CACHE_HOME`, or a symlinked `.tripcord` or
  `bootstrap.sh`;
- a usage error.

Exit 2 is what every harness blocks on, so a hook that cannot run a
verified `tripcord` blocks the tool call. There is no fallback to
latest, to another version, to a package registry, or to `curl | sh`.
The script changes no `PATH`: it writes nothing to `GITHUB_PATH` or
`CLAUDE_ENV_FILE`. It does not defend against another process already
running as the same user: that process can read and replace the private
copy. That local same-user compromise is outside this bootstrap's threat
model.

The same-user residual is not equivalent to the old private-copy
behaviour. Before, if the binary changed, the next hook detected it.
Now, if the binary and the registry (the `verified` record) are
rewritten together, the malicious binary stays attested until the
registry is deleted or the identity changes. It is accepted as a
design tradeoff because it is the same principal.

On a filesystem with coarse ctime, where ctime has a granularity of a
second or more or is not kept at all (FAT and exFAT, some network
filesystems), the record is weaker. A rewrite in place that keeps the
inode and the size, and lands in the same ctime tick (the writer can
reset mtime), leaves the device, inode, size, mtime, and ctime the
record compares unchanged, so `hook` runs the rewritten file. This is
a residual: fill the cache on a filesystem with fine-grained ctime.

Output: diagnostics and the scan report go to stderr. stdout carries
only what the harness parses: `{}` for a Cursor `session-start`, even
when the bootstrap fails, and the binary's own output in `hook` mode.
Claude Code and Copilot read nothing from a session-start hook's
stdout.

The script is POSIX `sh`, quotes every expansion, and uses no `eval`.
CI runs shellcheck on it (`init --embed output lint` in
`.github/workflows/ci.yml`).

## Workflow

`.github/workflows/tripcord.yml` runs on `pull_request` only, never
`pull_request_target`, and it sets no `paths` filter. A filter limited
to a fixed list of directories would skip nested configuration,
`CLAUDE.local.md`, `.gemini`, `.agents`, `.devcontainer`, `.opencode`,
`.windsurf`, `.cursorrules`, `.windsurfrules`, `.claude-plugin`, a
nested `AGENTS.md`, `.gitattributes`, and any path a Claude plugin
manifest names. Adapters match those case-insensitively. The workflow
therefore runs on every pull request.
Workflow permissions are `contents: read`; the job adds
`pull-requests: read` and `security-events: write`. It calls this
repository's `.github/workflows/tripcord-pr.yml` pinned by full commit
SHA, with the short SHA in a trailing comment. CI runs actionlint and
zizmor on the generated workflow. `copilot-setup-steps.yml` is
generated only with `--cloud-setup`, and CI lints that file the same
way, including zizmor's `pedantic` persona.

The workflow only protects the branch if a failing run blocks the
merge. Make its job a required status check in the protected branch's
rule (or ruleset) for the default branch: the check is named
`scan / Tripcord`. Without that, a pull request that removes the embed
reports TC-CFG-016 and can still be merged.

## Guard identity and TC-CFG-016

Each hook entry init writes is identified by the SHA-256 of its event
name and the entry's canonical JSON (sorted keys, no whitespace). The
Copilot setup step, when `--cloud-setup` wrote it, is identified the
same way. `bootstrap.sh` and
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
[TC-CFG-016](rules/TC-CFG-016.md) reports:

- **missing** (high): a file, hook, or setup step is not there;
- **changed** (high): it differs from what init writes for the
  recorded pin and from the recorded digest, or it matches the digest
  but breaks an invariant every Tripcord version keeps, or a pin this
  scanner knows never wrote it;
- **outdated** (low): an earlier Tripcord under a known pin wrote it
  (rerun `tripcord init --embed --force` with the same pins);
- **unverified** (low): it matches the digest and keeps every
  invariant, but this scanner cannot tell who wrote it, most likely a
  newer Tripcord;
- **pin-unknown** and **pin-malformed** (high): `tripcord.yml` pins a
  `tripcord-pr.yml` commit this scanner does not know, or no full
  commit SHA at all;
- **unreadable** (high): a file cannot be read or parsed.

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

Five tests run only with `TRIPCORD_RELEASE_GATE=1`:

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
`tripcord-pr.yml` at `main@277066a`, and the file there pins the same
action, so both paths pass. It reads the pinned commits with `git show`,
so the clone must have them (`fetch-depth: 0`).

`TestReleaseGatePinsContainLatestScannerChange`
(`cmd/tripcord/pin_contract_test.go`) fails unless the generated
workflow pin, every documented pin of the reusable workflows, and the
documented pre-commit rev contain the latest commit on `origin/main`
(or `main`) that changes the scanner: the reusable workflows, the
composite action, `.pre-commit-hooks.yaml`, advisories, the rule
registry, top-level rule YAML, the rule and adapter sources, or
`go.mod`. Every merge that changes those paths makes it fail until a
repin pull request lands, so a repin pull request is required before
tagging. A shallow or non-git checkout fails it.

`TestReleaseGateKnownWorkflowPins`
(`cmd/tripcord/release_gate_pins_test.go`) checks every
`KnownWorkflowPins` entry and `WorkflowPin`: each is on main, descends
from the embed check, and pins, through its `tripcord-pr.yml`, an action
with the embed check and the `base` input; the list is in history
order, holds neither excluded pin (`8b33b1b`, `6e1d5db`), and only
extends main's.

`TestVersionSkewCIScanner` (`cmd/tripcord/version_skew_e2e_test.go`)
builds the tripcord the generated `tripcord.yml` really runs in CI
(`tripcord-pr.yml@WorkflowPin`, then its action, built from source the
way the action does) and scans a fresh embed from this tree's `init`
with `GITHUB_ACTIONS=true`. It fails on any high TC-CFG-016 finding.
It fails on this tree: the action at `8b33b1b` predates this tree's
templates and reports seven highs (six surfaces "written by an older
Tripcord", and the Copilot setup step `init` writes only with
`--cloud-setup` as missing). It passes once the action and then
`WorkflowPin` are repinned past the TC-CFG-016 version-skew fix
([release notes](release-notes.md)), so until then no release can be
tagged.

`TestVersionSkewCIScanner`, and `TestReleaseGatePinsContainLatestScannerChange`
once a scanner change lands after the last repin, fail until the repin
pull requests land; the other tests pass. Without the variable all five
log that the gate was not requested and pass. No `pull_request` or
`push` workflow runs the gate (`TestReleaseGateNotInPullRequestCI`). There is no
release workflow in this repository: run the target before tagging.
Tagging and releases are Victor's.

The per-pull-request pin check is `TestPinsReachableFromHead`. It does
not read `origin/main`. Each pin in the generated workflow,
`README.md`, and `docs/` (including `docs/github-action.md` and the
`docs/pre-commit.md` rev) must be a full 40-character sha and an
ancestor of the `HEAD` under test. In a shallow clone, or when a pin is
missing, it fetches that exact sha from `origin` and fails if the
fetch fails. It never skips.
`TestInitWiringInvokesTripcordHook` always runs and asserts the exact
command each wiring file holds, `bash <project dir>/.tripcord/bootstrap.sh
hook --harness <h> --event pre-tool --on-failure block`, and the
fail-closed and timeout fields. `TestEmbedHookThroughBootstrap` runs
each of those commands through `bootstrap.sh` to a `tripcord` pinned in
the cache by its SHA-256: verified, tampered, and missing.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Files written, unchanged, or a dry run. |
| 3 | Invalid flags, a missing or malformed pin, a `--version` older than a release build of `init`, a `PATH` that is not a repository root (with `--embed`, not a Git repository), a symlink or non-regular target, or a file that cannot be merged. Nothing was written. |
| 4 | Internal error, including a failure while writing. |

`init` does not return 2. Exit 2 is the fail-closed result of
`bootstrap.sh` and of `tripcord hook`, and the `--version` check does
not change it.

`init` does not create the fingerprint key; `tripcord scan` still
creates it on first use ([fingerprint.md](fingerprint.md)).
