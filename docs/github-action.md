# GitHub Action

The composite action at
[`./.github/actions/tripcord`](../.github/actions/tripcord) builds
`tripcord` from source and scans a repository. It does not download a
release binary. No release is published.

By default it builds the tree that contains the action
(`github.action_path`). Set `ref` to build another commit of this
action's repository instead. That checkout lives at `tripcord-src` in
the workspace only long enough to compile. The binary is written under
`RUNNER_TEMP`, and the checkout is removed before the scan, so the
default `path` of `.` does not include Tripcord's own tree. Set
`binary` to an existing executable to skip the build.
`actions/setup-go` caches modules for the build.

An empty `fail-on` leaves the threshold to the CLI and the repository
policy. The action passes `--fail-on` only when the caller sets the
input. The CLI default is enforce mode with fail-on `high`. A locked
policy can reject a looser value.

The action runs three scans with that binary:

- GitHub Actions annotations (`::error` output);
- a SARIF report, uploaded to GitHub code scanning by default; and
- a Markdown report, which can optionally be posted to a pull request.

It then runs `tripcord pr-context` with the same binary. The action
outputs `is_agent` and `agents` are that command's `GITHUB_OUTPUT`
values. A pr-context read error is a warning and does not fail the job;
the scan exit code does, after the reports are published.

`pr-context` reads commits between the pull request base and head. The
checkout of the repository being scanned needs `fetch-depth: 0`. A
shallow clone usually does not contain `base`, so commit and note
signals are skipped and only the pull request login and branch remain.

Publishing runs when the scan recorded an exit code. A pull request
whose head repository differs from its base repository skips both the
SARIF upload and the comment and emits a warning. A missing SARIF file,
for example when the scan exits 3 before writing the report, warns that
the file is missing. A read-only token warns that the token cannot
upload code scanning results. None of these cases fails the job.

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0
    persist-credentials: false
- uses: ./.github/actions/tripcord
```

## Inputs and permissions

`path` defaults to `.` and `upload-sarif` defaults to `true`. Set
`comment: true` to create or update a marked Markdown comment on
pull-request events.

The calling job needs `security-events: write` when SARIF upload is
enabled and `pull-requests: write` when `comment: true`. A checkout of
`ref` uses `github-token`. Give only the permissions needed by the
selected features.

## Reusable workflow

[`.github/workflows/tripcord-pr.yml`](../.github/workflows/tripcord-pr.yml)
is `workflow_call` only. It checks out the calling repository with
`fetch-depth: 0` and runs the composite action at a full commit SHA, so
the scanner is not taken from the tree being scanned. The workflow's
inputs match the action (`ref`, `binary`, `path`, `fail-on`,
`upload-sarif`, `comment`, `github-token`) and use the same defaults.
An empty `github-token` uses `github.token`, because a `workflow_call`
default cannot be an expression. There is no `policy` input: an empty
`fail-on` still leaves the threshold to the CLI and the repository
policy. The workflow outputs are `is_agent` and `agents`.

A caller that leaves the defaults needs `contents: read`,
`pull-requests: read`, and `security-events: write`. Set `comment: true`
only from a job that also has `pull-requests: write`. Set
`upload-sarif: false` to drop `security-events: write`. The workflow
splits those combinations into separate jobs, and exactly one job runs.
It does not use `pull_request_target`. A fork pull request still skips
the SARIF upload and the comment and emits the action's warning.

The workflow does not fetch pull-request reviews. `pr-context` in the
pinned action has no review set yet. Wiring
`GET /repos/{owner}/{repo}/pulls/{n}/reviews` and `--reviews-file`
follows #44.

```yaml
name: tripcord
on:
  pull_request:

jobs:
  tripcord:
    permissions:
      contents: read
      pull-requests: read
      security-events: write
    uses: ./.github/workflows/tripcord-pr.yml
```

Another repository pins the same file by full commit SHA:

```yaml
uses: vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@<commit>
```
