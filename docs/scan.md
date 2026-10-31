# `tripcord scan`

`tripcord scan [PATH]` statically scans executable coding-agent configuration.
It reads configuration only: it never executes repository content, starts
hooks, or contacts a network service. `PATH` defaults to the current directory
and must be inside a Git repository.

## Flags

| Flag | Description |
| --- | --- |
| `--config` | Scan executable configuration. This is the v0 default. |
| `--secrets` (v1) | Not available. Secret scanning lands in v1; v0 supports `--config` only. |
| `--all` (v1) | Not available. Secret scanning lands in v1; v0 supports `--config` only. |
| `--harness claude,cursor,...` | Restrict discovery to comma-separated harnesses. With no value, installed adapters autodetect their files. Harness adapters arrive after the scan orchestration. |
| `--format text\|json\|sarif\|md\|gha` | Select human text, JSONL finding documents, SARIF 2.1.0, Markdown, or GitHub Actions annotations. Default: `text`. |
| `--output <path\|->` | Write output to a private (`0600`) local file or `-` for stdout (default). |
| `--since <git-ref>` | Scan only repository configuration files reported by `git diff --no-ext-diff --name-only <git-ref> --`. It does not execute repository content or hooks. |
| `--fail-on low\|medium\|high\|critical` | Replace the effective policy threshold for this invocation. The threshold is inclusive. |
| `--policy <path>` | Use this repository policy file instead of `.tripcord/policy.yaml`. |
| `--org-policy <path>` | Add one required organization policy layer before the repository policy. |

v0 accepts `--config` only. `--secrets` (v1) and `--all` (v1) stop before scanning and exit 3.

Policy defaults are `enforce` and `high` for scan. Policy files control mode
and the normal threshold; `--fail-on` is the final per-invocation override.
See [policy.md](policy.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding meets the effective threshold. |
| 1 | At least one finding meets the effective threshold. |
| 3 | Invalid flags, configuration/policy error, unavailable v0 secret scan, or unknown command. |
| 4 | Internal, discovery, output, or file write error. |

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
