# `tripcord scan`

`tripcord scan [PATH]` statically scans executable coding-agent configuration.
It reads configuration only: it never executes repository content, starts
hooks, or contacts a network service. `PATH` defaults to the current directory.
A directory that is not a Git repository can still be scanned. `--since` is
the only mode that requires Git.

## Flags

| Flag | Description |
| --- | --- |
| `--config` | Scan executable configuration. This is the v0 default. |
| `--secrets` (v1) | Not available. Secret scanning lands in v1; v0 supports `--config` only. |
| `--all` (v1) | Not available. Secret scanning lands in v1; v0 supports `--config` only. |
| `--harness claude,codex,cursor,copilot,generic,...` | Restrict discovery to comma-separated harnesses. `generic` is the shared-files adapter (skills, `AGENTS.md`, `.vscode/`). With no value, installed adapters autodetect their files. A harness that also loads files another adapter owns pulls that adapter in, for example `--harness cursor` also runs `claude` and `generic`; an informational note on stderr says so. |
| `--scope repo\|user\|managed\|all` | Choose which configuration to read. `repo` (the default) does not read the home directory or system settings. `user` and `managed` read those locations and skip the repository. `all` reads every scope. |
| `--format text\|json\|sarif\|md\|gha` | Select human text, JSONL finding documents, SARIF 2.1.0, Markdown, or GitHub Actions annotations. Default: `text`. |
| `--output <path\|->` | Write output to a new private (`0600`) local file or `-` for stdout (default). A symlink is rejected. The destination is replaced only after the result is complete. |
| `--since <git-ref>` | Scan repository configuration files that differ between `<git-ref>` and `HEAD`. The ref must not start with `-`. Untracked files and uncommitted worktree edits are not included. Names with non-ASCII characters are included. Git is invoked with repository hooks, fsmonitor, textconv, external diff drivers, and rename detection disabled, with every network transport denied, and with lazy fetches from a partial clone's promisor remote disabled; it does not execute repository content or contact a network service, even when the repository's own configuration tries to allow one. |
| `--fail-on low\|medium\|high\|critical` | Set this invocation's threshold. The threshold is inclusive. A locked policy ceiling can be tightened and cannot be loosened. |
| `--policy <path>` | Use this repository policy file instead of `.tripcord/policy.yaml`. The file must exist; a missing explicit `--policy` path is an error, unlike the default `.tripcord/policy.yaml`, which is optional. |
| `--org-policy <path>` | Add one required organization policy layer before the repository policy. |

v0 accepts `--config` only. `--secrets` (v1) and `--all` (v1) stop before scanning and exit 3.

Policy defaults are `enforce` and `high` for scan. Policy files control mode
and the normal threshold. `--fail-on` then applies, subject to a locked
ceiling. See [policy.md](policy.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding meets the effective threshold. |
| 1 | At least one finding meets the effective threshold. |
| 3 | Invalid flags or format, configuration/policy error, a Git ref `--since` cannot use, an invalid `--output` or `--policy` path, unavailable v0 secret scan, or unknown command. `--help` exits 0. |
| 4 | Internal error, or a failure to start Git or finish writing the output file. |

When an adapter cannot fully read the configuration (malformed, oversized,
unsafe, or unreadable files, or walk limits reached), scan still writes the
findings for everything it could read, prints one sanitized diagnostic per
problem to stderr, and exits 3 because the scan is incomplete. Exit 3 takes
precedence over exit 1. The same diagnostics are included in the report:
JSONL gains a `tripcord.diagnostic/v1` line with `"incomplete": true`,
Markdown gains a Diagnostics section, text says `scan incomplete`, and
SARIF sets `invocations[0].executionSuccessful` to false and lists them in
`toolExecutionNotifications`. An informational note, such as the legacy
Windows managed directory, is printed to stderr and does not change the
exit code or the report. See the adapter docs ([claude](adapters/claude.md),
[codex](adapters/codex.md), [cursor](adapters/cursor.md),
[copilot](adapters/copilot.md), [generic](adapters/generic.md)) and
[output.md](output.md).

## Examples

```sh
# Scan the current repository with safe defaults.
tripcord scan --config

# Produce SARIF for a pull request diff.
tripcord scan --since origin/main --format sarif --output tripcord.sarif

# Print GitHub Actions annotations for changed configuration.
tripcord scan . --since HEAD~1 --format gha

# Use a checked-in policy and fail on medium or higher.
tripcord scan --policy security/tripcord.yaml --fail-on medium
```
