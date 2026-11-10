# Commands

Implemented commands, from `tripcord --help`:

```text
tripcord help
tripcord version
tripcord scan [PATH] [flags]
tripcord pr-context [flags]
tripcord preopen <git-url|path> [flags]
tripcord init [PATH] [--embed] [--harness h,...] [flags]
tripcord hook --harness <claude|cursor|copilot> --event <e> [--on-failure block|error]
```

`version` prints the link-time version, or `dev` when it was not set.
`tripcord <command> --help` prints that command's flags and exits 0. An
unknown command prints the usage and exits 3.

| Command | What it does | Page |
| --- | --- | --- |
| `scan` | Statically scans a checkout's coding-agent configuration. | [scan](scan.md) |
| `init` | Writes `.tripcord/policy.yaml`; with `--embed`, also the pinned bootstrap, the pull request workflow, and each harness's hook wiring. | [init](init.md) |
| `hook` | Decides one Claude Code, Cursor, or Copilot hook event from the policy's custom event rules. | [hook](hook.md) |
| `preopen` | Fetches a repository without running anything it controls, scans it, and removes it. | [preopen](preopen.md) |
| `pr-context` | Reports whether a pull request looks agent-authored and evaluates TC-CFG-014. | [pr-context](pr-context.md) |

Two more pages describe what every command shares:
[fingerprints](fingerprint.md), the stable `tcf_` id on each finding
(there is no `fingerprint` subcommand), and
[output and sinks](output.md), the `text`, `json`, `sarif`, `md`, and
`gha` formats.

To scan staged coding-agent configuration before committing, install the
[`tripcord-config` pre-commit hook](pre-commit.md). It reads the Git
index, not unstaged working-tree edits.

## `tripcord scan`

`PATH` defaults to the current directory. The scan reads configuration.
It does not execute repository content. The full reference, including
`--staged`, the fingerprint key, and the Git invocation used by
`--since`, is [scan](scan.md#flags).

| Flag | Meaning |
| --- | --- |
| `--config` | Scan configuration. This is what a scan does when the flag is omitted. |
| `--secrets`, `--all` | Reserved for secret scanning, which lands in v1. Currently exits 3. |
| `--harness` | Comma-separated adapter ids from [Harness adapters](adapters/README.md). Empty means autodetect. |
| `--scope repo\|user\|managed\|all` | `repo` (default) does not read the home directory or system settings. `user` and `managed` read those locations and skip the repository. `all` reads every scope. |
| `--format text\|json\|jsonl\|sarif\|md\|gha` | Default `text`. `json` and `jsonl` both write one `tripcord.finding/v1` document per line. `sarif` is SARIF 2.1.0. `md` is Markdown. `gha` is GitHub Actions workflow commands. Help text lists `text`, `json`, `sarif`, `md`, and `gha`; `jsonl` is accepted as well. |
| `--output path\|-` | Write to a new private (`0600`) local file, or `-` for stdout (default). A symlink is rejected. The destination is replaced only after the result is complete. |
| `--since git-ref` | Repository files that differ between the ref and `HEAD`. The ref must not start with `-`. Untracked files and uncommitted edits are not included. Requires Git. Implies `--base` with the same ref. |
| `--base git-ref` | Also compare a Tripcord embed with the ref's and report one the change removes, re-pins, or drops a harness from (TC-CFG-016). Requires Git. Must equal `--since` when both are given; not allowed with `--staged`. |
| `--staged` | Scan the staged Git index; paths given after it are unioned with the staged change set. |
| `--fail-on low\|medium\|high\|critical` | Inclusive threshold for this invocation. A locked policy ceiling can be tightened and cannot be loosened. |
| `--policy path` | Repository policy file. The path must exist. The default `.tripcord/policy.yaml` is optional. |
| `--org-policy path` | One organization policy layer, loaded before the repository policy. |

Rendering limits are in [output and sinks](output.md).

## `tripcord init`

`tripcord init` writes `.tripcord/policy.yaml`. `tripcord init --embed
--version V --sha256 os-arch=HEX` also writes a pinned
`.tripcord/bootstrap.sh`, `.github/workflows/tripcord.yml`, and the hook
or setup wiring of each harness in `--harness` (default
`claude,cursor,copilot,devin,codex`), merging into existing files.
`--dry-run` prints a diff; `--force` resolves conflicts it can. Every
hook runs `.tripcord/bootstrap.sh`, which runs the checksum-verified
binary by absolute path, never a `tripcord` from `PATH`. Its `hook` mode
runs `tripcord hook --on-failure block`. The bootstrap never downloads:
it runs only the pinned binary from its cache, and exits 2, which
blocks the call, without one. `--embed` needs a Git repository. A
Copilot hook that times out lets the call through
([init](init.md)). TC-CFG-016 reports an embed that is missing, edited, or,
against a pull request's base, removed or re-pinned. Details are in
[init](init.md).

## `tripcord hook`

`tripcord hook --harness <claude|cursor|copilot> --event <e>` reads one
hook event as the harness's JSON on stdin and writes the decision in the
harness's format: exit 0 allows and 2 blocks. `--on-failure block` makes
an invalid input or policy, or an internal error, block instead of
exiting 3 or 4. See [hook](hook.md).

## `tripcord preopen`

`tripcord preopen <git-url|path>` takes the `scan` flags except
`--since`, and `--scope` must be `repo`. It ignores the fetched
repository's own `.tripcord` policy. See [preopen](preopen.md).

## `tripcord pr-context`

`tripcord pr-context` takes `--repo` (default `.`), `--event` (default
`$GITHUB_EVENT_PATH`), `--base`, `--head`, `--reviews-file`, and
`--format text|json|gha`. See [pr-context](pr-context.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding meets the effective threshold. `--help` also exits 0. |
| 1 | At least one finding meets the threshold, and the effective mode is `enforce`. |
| 2 | `hook` blocked the tool call ([hook](hook.md#exit-codes)). `scan` does not return 2. |
| 3 | Invalid flags or format, a policy or configuration error, a Git ref `--since` cannot use, an invalid `--output` or `--policy` path, a broken fingerprint key, `--secrets` or `--all`, an unknown command, or an incomplete scan. |
| 4 | Internal error, or a failure to start Git or finish writing the output file. |

An incomplete scan still writes the findings it could produce, prints one
diagnostic per problem to stderr, and exits 3. Exit 3 takes precedence
over exit 1. Informational notes, such as an extra adapter pulled in by
`--harness`, do not change the exit code.

`audit` and `warn` never fail the process, whatever `--fail-on` is. With
no policy file, `scan` uses `enforce` and fail-on `high`
([Policy](policy.md)).

`init`, `hook`, `preopen`, and `pr-context` list their own exit codes on their
pages: [init](init.md#exit-codes), [hook](hook.md#exit-codes),
[preopen](preopen.md#flags-policy-and-exit-codes), and
[pr-context](pr-context.md#exit-codes).
