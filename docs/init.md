# `tripcord init`

```text
tripcord init [PATH] [--embed] [--harness h,...] [--version V --sha256 os-arch=HEX ...] [--force] [--dry-run]
```

`init` writes Tripcord's files into the repository at `PATH` (default:
the current directory). `PATH` must be the repository root: a
subdirectory of a Git repository exits 3.

> **Not releasable yet.** `init --embed` wires each hook-capable harness
> to run `tripcord hook --harness <h> --event pre-tool`. This build has
> no `hook` subcommand; hook mode is the next pull request. Until it
> lands, the Claude Code hook blocks every tool call (`onFailure:
> block`) and the Cursor hook fails closed. Do not cut a release that
> contains `init --embed` before hook mode. `make release-gate` (see
> "Release gate" below) fails until then.

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
| `.tripcord/embed.json` | Manifest: the pinned version, the harnesses selected at init time, and the SHA-256 of every hook entry init wrote. |
| `.github/workflows/tripcord.yml` | Pull request scan. See "Workflow". |

Files written per harness. `--harness` takes a comma-separated subset;
empty means all five.

| `--harness` | Files |
| --- | --- |
| `claude` | `.claude/settings.json`: `hooks.SessionStart` runs the bootstrap; `hooks.PreToolUse` runs `tripcord hook --harness claude --event pre-tool` with `onFailure: block`. |
| `cursor` | `.cursor/hooks.json`: `sessionStart` runs the bootstrap; `preToolUse` runs `tripcord hook --harness cursor --event pre-tool` with `failClosed: true`. `.cursor/environment.json`: `install` runs `bash .tripcord/bootstrap.sh install`. |
| `copilot` | `.github/hooks/tripcord.json`: `sessionStart` runs the bootstrap; `preToolUse` runs `tripcord hook --harness copilot --event pre-tool`. `.github/workflows/copilot-setup-steps.yml`: a `Tripcord bootstrap` step. |
| `devin` | `.devin/blueprint.yaml`: a `maintenance` entry named `tripcord`. |
| `codex` | `AGENTS.md`: a note between `<!-- tripcord:begin -->` and `<!-- tripcord:end -->` asking the environment setup script to run the bootstrap. This covers Codex and Jules, which have no repository hooks. |

The Claude Code entry is the one in the spec:

```json
{"matcher": "*", "hooks": [{"type": "command", "command": "tripcord",
  "args": ["hook", "--harness", "claude", "--event", "pre-tool"],
  "onFailure": "block"}]}
```

Copilot's hook format has no fail-closed field, so none is written.

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

`.tripcord/bootstrap.sh install` and `.tripcord/bootstrap.sh
session-start` install the pinned release and then run `tripcord scan
--config` on the repository.

- The install source is one variable at the top of the script,
  `TRIPCORD_INSTALL_SOURCES='npm pypi cache'`, tried in that order:
  `npm pack @tripcord/cli-<os>-<arch>@<version> --ignore-scripts`, then
  `pip download tripcord==<version> --no-deps --only-binary=:all:`, then
  a binary already in the cache at
  `${XDG_CACHE_HOME:-$HOME/.cache}/tripcord/<version>/<os-arch>/tripcord`.
- Every candidate, cached or downloaded, is checked against the pinned
  SHA-256 for the running platform before it is used. A mismatch is
  discarded.
- There is no fallback to latest, to another version, or to
  `curl | sh`. An unpinned platform exits 3; no network and no valid
  cache, or a bad checksum, exits 1. Any other mode exits 2.
- Downloads go to a `mktemp -d` directory with mode `0700`, removed on
  exit. The verified binary is moved into the cache atomically.
- On GitHub Actions and in Claude Code, the cache directory is added to
  `GITHUB_PATH` and `CLAUDE_ENV_FILE`, so `tripcord` is on the `PATH`
  for the hooks.

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
zizmor on it and on the generated `copilot-setup-steps.yml`.

## Hook identity and TC-CFG-016

Each hook entry init writes is identified by the SHA-256 of its event
name and the entry's canonical JSON (sorted keys, no whitespace). The
manifest records those digests. A fresh embed scans with no findings.

When `.tripcord/bootstrap.sh` or `.tripcord/embed.json` exists, the scan
compares each hook harness recorded in the manifest (all three when the
manifest is missing or unreadable) with what init writes.
[TC-CFG-016](rules/TC-CFG-016.md) reports a wiring file or hook that is
missing, a hook edited so it no longer matches, and a wiring file that
cannot be read. Harnesses not selected at init time are not checked.

## Release gate

`TestReleaseGateHookSubcommand` in `cmd/tripcord/init_test.go` runs only
with `TRIPCORD_RELEASE_GATE=1`:

```sh
make release-gate
```

It runs the exact command each harness is wired to, and fails, without
skipping, if this build answers with an unknown command. Without the
variable it logs that the gate was not requested and passes, so pull
request CI stays green. There is no release workflow in this
repository; run the target before tagging a release.
`TestInitWiringInvokesTripcordHook` always runs and asserts that the
wiring init writes names exactly `tripcord hook --harness <h> --event
pre-tool`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Files written, unchanged, or a dry run. |
| 3 | Invalid flags, a missing or malformed pin, a `PATH` that is not a repository root, a symlink or non-regular target, or a file that cannot be merged. Nothing was written. |
| 4 | Internal error, including a failure while writing. |

`init` does not create the fingerprint key; `tripcord scan` still
creates it on first use ([fingerprint.md](fingerprint.md)).
