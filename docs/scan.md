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
| `--harness claude,codex,cursor,copilot,gemini,opencode,windsurf,devcontainer,generic,...` | Restrict discovery to comma-separated harnesses. `generic` is the shared-files adapter (skills, `AGENTS.md`, `.vscode/`); `devcontainer` reports Dev Container configuration, which every harness that opens the repository in a container runs. With no value, installed adapters autodetect their files. A harness that also loads files another adapter owns pulls that adapter in, for example `--harness cursor` also runs `claude` and `generic`; an informational note on stderr says so. `.vscode/tasks.json` is read under any value, because the editor runs its folder-open tasks whichever agent is in use; a harness-limited scan reads only that shared file, not the skills or `AGENTS.md`. |
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
| 3 | Invalid flags or format, configuration/policy error, a Git ref `--since` cannot use, an invalid `--output` or `--policy` path, unavailable v0 secret scan, unknown command, or an incomplete scan (below). `--help` exits 0. |
| 4 | Internal error, or a failure to start Git or finish writing the output file. |

When an adapter cannot fully read the configuration (malformed, oversized,
unsafe, or unreadable files, or walk limits reached), or a rule cannot be
evaluated on a file (for example it exceeds the CEL cost limit), scan still
writes the findings for everything it could read and evaluate, prints one sanitized diagnostic per
problem to stderr, and exits 3 because the scan is incomplete. Exit 3 takes
precedence over exit 1. The same diagnostics are included in the report:
JSONL gains a `tripcord.diagnostic/v1` line with `"incomplete": true`,
Markdown gains a Diagnostics section, text says `scan incomplete`, and
SARIF sets `invocations[0].executionSuccessful` to false and lists them in
`toolExecutionNotifications`. An informational note, such as the legacy
Windows managed directory, is printed to stderr and does not change the
exit code or the report. See the adapter docs ([claude](adapters/claude.md),
[codex](adapters/codex.md), [cursor](adapters/cursor.md),
[copilot](adapters/copilot.md), [gemini](adapters/gemini.md),
[opencode](adapters/opencode.md), [windsurf](adapters/windsurf.md),
[devcontainer](adapters/devcontainer.md), [generic](adapters/generic.md)) and
[output.md](output.md).

## Rule evaluation

Rules match the configuration as the file wrote it. Adapters also produce a
sanitized copy of every entry, with URL queries, fragments, and userinfo
stripped and credentials redacted. Every finding, evidence key,
fingerprint, and diagnostic is built from that copy only. Matching the raw
text means sanitizing cannot hide a command from a rule: in
`echo https://e.com/?x;curl … | sh`, stripping the query must not swallow
the `;` that starts the second command. A rule has no way to put the raw
text in a report. The quote-aware URL boundary applies only when a single
or double quote appears immediately before the URL scheme. In that narrow
case, the matching closing quote bounds the query or fragment, so old-style
query separators such as `;`, `|`, and `&&` are stripped rather than shown.
Outside that case, shell metacharacters are kept with the following command.

The redaction PR will add real quote tracking. Known limits of the current
boundary matcher are a quote of the other type or an escaped quote inside a
query, a space or `<` inside a quoted URL, `"--url=https://…"`,
`-d "x https://…"`, and a greedy closing quote that hides evidence such as
`'a'https://…`. These predate PR #12 and affect only the JSON evidence key.

Each evaluation of a rule on one entry has a deterministic CEL cost limit:
20M units for a scan. That limit, not the clock, decides when an expensive
evaluation is cut short, so the outcome is the same on any machine under
any load. A unit takes 8 to 160 ns on an idle machine and about 300 ns
under load, so 20M units take up to about 6 s. Each evaluation also has a
15 s timeout, which is only a safety net set well past that point. An
evaluation stopped by either is reported as a diagnostic, and the scan
exits 3. There is no time budget for a whole scan yet; that is a planned
follow-up.

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
