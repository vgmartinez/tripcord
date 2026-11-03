# FAQ and troubleshooting

## Does tripcord run anything from the repository?

No. `scan` reads configuration files and never starts the agent, runs a
hook, or contacts a network service. `--since` and `--base` invoke Git
with hooks, filters, external diff drivers, and network transports
disabled ([scan](scan.md#flags)). `preopen` fetches with a bare clone, so
no checkout, filter, LFS, hook, or submodule runs
([preopen](preopen.md#what-is-fetched-and-how)).

## Is there a release, or an npm or PyPI package?

Not yet. Build from source or use `go install`
([Getting started](getting-started.md#build)). The
[GitHub Action](github-action.md) builds tripcord from source at a pinned
commit. The bootstrap `init --embed` writes runs only a binary you
build into its cache from the pinned commit
([init](init.md#bootstrap)).

## Why did the scan exit 3?

Exit 3 is a usage, configuration, or incomplete-scan error
([Commands](commands.md#exit-codes)). Common causes:

- **Incomplete scan.** A file was malformed, oversized, unsafe, or
  unreadable, a walk limit was reached, or a rule hit its CEL cost limit.
  The findings that could be produced are still written, and stderr has
  one diagnostic per problem ([scan](scan.md#exit-codes)).
- **`--secrets` or `--all`.** Secret scanning lands in v1; v0 scans
  configuration only.
- **A broken fingerprint key.** `TRIPCORD_FINGERPRINT_KEY` or
  `~/.tripcord/fingerprint.key` is too short, not hex, a symlink, or has
  the wrong owner or permissions. tripcord fails closed rather than
  silently changing fingerprints
  ([Fingerprints](fingerprint.md#fail-closed-vs-s1-fallback)).
- **`--harness vscode`.** `vscode` is the harness of `.vscode/tasks.json`
  findings, not a `--harness` value. Those tasks are read under any
  `--harness` ([Harness adapters](adapters/README.md)).
- **A locked policy.** `--fail-on` may tighten a locked ceiling but not
  loosen it ([Policy](policy.md#what-overrides-them)).
- **An unknown command**, such as `tripcord fingerprint`.

## Why does the same finding have a different fingerprint in CI?

Findings on an entry that lost a secret to redaction use a keyed `k1`
fingerprint when a key is available and a structural `s1` one when it is
not. A scan in CI never creates a key, so it uses `s1` unless
`TRIPCORD_FINGERPRINT_KEY` is set. Set the same key locally and in CI to
compare them ([Fingerprints](fingerprint.md#local-k1-vs-ci-s1)).

## How do I report findings without failing the build?

Set `mode: audit` (or `warn`) in `.tripcord/policy.yaml`. Both print the
findings and exit 0 whatever `--fail-on` is
([Policy](policy.md#surfaces)). A locked organization policy can prevent
that.

## Can I scan one directory of a monorepo?

Not yet. A path inside a Git repository scans that whole repository from
its root. Monorepo scoping is tracked in
[#59](https://github.com/vgmartinez/tripcord/issues/59).

## The pre-commit hook did not run on a merge

Git skips `pre-commit` for a merge without conflicts. Install the
`pre-merge-commit` stage too
([pre-commit](pre-commit.md#what-the-hook-does-not-cover)).

## The pre-commit hook blocks every commit in a large repository

The walk stops after 200,000 directory entries, and past that the scan
is incomplete and exits 3. Skip the hook there with
`SKIP=tripcord-config` ([pre-commit](pre-commit.md#what-the-hook-does-not-cover)).

## `pr-context` reports no commit signals

The checkout needs the pull request's base commit. A shallow clone
usually does not have it, so only the login and branch signals remain.
Check out with `fetch-depth: 0`
([GitHub Action](github-action.md)).

## Does `init --embed` work today?

Yes, in a Git repository. It writes every file, and `scan` checks the
embed (TC-CFG-016). The pre-tool hooks it wires run
[`tripcord hook --on-failure block`](hook.md) through the verified
bootstrap, which runs only the pinned binary from its cache: build it
there with `go build -trimpath` of the pinned commit
([init](init.md#bootstrap)). A hook that cannot decide, or finds no
verified binary, blocks the tool call, except a Copilot hook that times
out ([init](init.md)).

## Does tripcord cover agent workflows triggered by issue comments?

Not in v0. TC-CFG-013 is a known gap and is documentation-only in v0
([#41](https://github.com/vgmartinez/tripcord/issues/41)); see
[TC-CFG-013](rules/TC-CFG-013.md) and the
[Rules catalog](rules/README.md#known-gaps).

## How do I edit this wiki?

Edit the matching file under `docs/` in the repository and open a pull
request. The wiki is regenerated from `docs/` when `main` changes, and
direct wiki edits are overwritten.
