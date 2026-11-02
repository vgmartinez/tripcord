# GitHub Action

The composite action at
[`./.github/actions/tripcord`](../.github/actions/tripcord) builds
`tripcord` from source and scans a repository. It does not download a
release binary. No release is published.

By default it builds the tree that contains the action
(`github.action_path`). Set `ref` to build another commit of this
action's repository instead. Set `binary` to an existing executable to
skip the build. `actions/setup-go` caches modules for the build.

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

Publishing runs when the scan recorded an exit code. A pull request
whose head repository differs from its base repository skips both the
SARIF upload and the comment and emits a warning. A read-only token
does the same instead of failing the job.

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
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

`.github/workflows/tripcord-pr.yml` is not in this change. Add it, as
`workflow_call` only, once this action is on `main`.
