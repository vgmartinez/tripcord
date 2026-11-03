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

`path` is a directory in the workspace. A path inside a Git repository
scans that whole repository from its git root; it does not narrow
discovery to the directory. Monorepo scoping is tracked in
[#59](https://github.com/vgmartinez/tripcord/issues/59). The action
fails before the scan when `path` is empty, does not exist, is not a
directory, or is an empty directory.

An empty `fail-on` leaves the threshold to the CLI and the repository
policy. The action passes `--fail-on` only when the caller sets the
input. The CLI default is enforce mode with fail-on `high`. A locked
policy can reject a looser value.

The action runs three scans with that binary:

- GitHub Actions annotations (`::error` output);
- a SARIF report, uploaded to GitHub code scanning by default; and
- a Markdown report, which can optionally be posted to a pull request.

It then runs `tripcord pr-context` with the same binary. Set
`reviews-file` to a JSON array of pull request reviews to pass
`--reviews-file`. An empty value skips the flag. The array stays on
disk and is not printed. The action outputs `is_agent`, `agents`, and
`tc-cfg-014` are that command's `GITHUB_OUTPUT` values. After reports
are published, a TC-CFG-014 denial (exit 1) fails the job. With
`reviews-file`, incomplete or invalid review data (exit 3 or 4) also
fails the job; without it, exits 3 and 4 warn and leave the job green.
The scan exit code also fails the job after reports are published.

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

`path` defaults to `.`. As above, a path inside a Git repository scans
that repository from its git root. `upload-sarif` defaults to `true`.
Set `comment: true` to create or update a marked Markdown comment on
pull-request events.

A job that calls the composite action directly needs
`security-events: write` when SARIF upload is enabled and
`pull-requests: write` when `comment: true`. A checkout of `ref` uses
`github-token`.

## Reusable workflows

GitHub checks the permissions of every job in a called workflow when
the caller starts, before any `if:` condition and before inputs are
read. Each file below is `workflow_call` only and contains one job.
The caller picks the file. Both jobs request `security-events: write`,
including when `upload-sarif` is false. Neither file uses
`pull_request_target`. A fork pull request still skips the SARIF upload
and the comment and emits the action's warning.

Each workflow checks out the calling repository with `fetch-depth: 0`
and runs the composite action at a full commit SHA, so the scanner is
not taken from the tree being scanned. The inputs match the action's
scan inputs (`ref`, `binary`, `path`, `fail-on`, `upload-sarif`,
`comment`, `github-token`) and use the same defaults. Reviews are not
an input. An empty `github-token` uses `github.token`, because a
`workflow_call` default cannot be an expression. There is no `policy`
input: an empty `fail-on` still leaves the threshold to the CLI and the
repository policy. The outputs are `is_agent` and `agents`. The
action step does not continue on error, so a TC-CFG-014 denial
(exit 1) fails the scan job after publishing.

The reviews step calls `github.paginate` on
`GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews`. Owner,
repository, and pull number come from the Actions `context`. The JSON
array is written under `RUNNER_TEMP` and passed as `reviews-file`. The
step does not print the array. If the event has no pull request, or the
read fails, the step warns and the scan still runs. `pr-context` then
runs without `--reviews-file` and reports an incomplete review set.

### Scan

[`.github/workflows/tripcord-pr.yml`](../.github/workflows/tripcord-pr.yml)
needs `contents: read`, `pull-requests: read`, and
`security-events: write`.

```yaml
name: tripcord
on:
  pull_request:

jobs:
  tripcord:
    permissions:
      contents: read # checkout the repository being scanned
      pull-requests: read # read pull request reviews
      security-events: write # upload the SARIF report
    uses: ./.github/workflows/tripcord-pr.yml
```

Another repository pins the same file by full commit SHA:

```yaml
permissions:
  contents: read # checkout the repository being scanned
  pull-requests: read # read pull request reviews
  security-events: write # upload the SARIF report
uses: vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@<commit>
```

### Comment

[`.github/workflows/tripcord-pr-comment.yml`](../.github/workflows/tripcord-pr-comment.yml)
needs the same permissions, with `pull-requests: write` in place of
`pull-requests: read`, because posting the Markdown comment requires
write. `write` includes read, so the reviews fetch uses the same token.

```yaml
name: tripcord
on:
  pull_request:

jobs:
  tripcord:
    permissions:
      contents: read # checkout the repository being scanned
      pull-requests: write # create or update the Markdown comment
      security-events: write # upload the SARIF report
    uses: ./.github/workflows/tripcord-pr-comment.yml
    with:
      comment: "true"
```

Another repository pins the same file by full commit SHA:

```yaml
permissions:
  contents: read # checkout the repository being scanned
  pull-requests: write # create or update the Markdown comment
  security-events: write # upload the SARIF report
uses: vgmartinez/tripcord/.github/workflows/tripcord-pr-comment.yml@<commit>
```
