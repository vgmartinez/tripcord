# GitHub Action

The composite action at
[`./.github/actions/tripcord`](../.github/actions/tripcord) runs an
installed `tripcord` binary against a repository. It defaults to enforce
behavior with a `high` failure threshold.

It performs three scans:

- GitHub Actions annotations (`::error` output);
- a SARIF report, uploaded to GitHub code scanning by default; and
- a Markdown report, which can optionally be posted to a pull request.

The caller installs the binary before using the action. For example:

```yaml
- uses: actions/checkout@<full-commit-sha>
- name: Install Tripcord
  run: go install github.com/vgmartinez/tripcord/cmd/tripcord@<version>
- uses: ./.github/actions/tripcord
```

Replace both placeholders with reviewed immutable values. The action does
not download or install a binary itself.

## Inputs and permissions

`path` defaults to `.`, `fail-on` defaults to `high`, and `upload-sarif`
defaults to `true`. Set `comment: true` to create or update a marked
Markdown comment on pull-request events. The `command` input can select a
different installed binary.

The calling job needs `security-events: write` when SARIF upload is enabled.
It also needs `pull-requests: write` when `comment: true`. Give only the
permissions needed by the selected features.

## PR context

<!-- TODO(#33): add pr-context wiring after https://github.com/vgmartinez/tripcord/pull/33 is merged to main. -->

This action does not yet collect pull-request context. That wiring is
deferred until [#33](https://github.com/vgmartinez/tripcord/pull/33) lands
on `main`.

## Reusable workflow

A reusable workflow would need a new file under `.github/workflows/`.
It is intentionally not included while that path requires Researcher
approval.
