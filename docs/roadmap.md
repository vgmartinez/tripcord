# Roadmap

Nothing here is released. There is no tagged release yet; `main` is the
v0 tree described in [Release notes](release-notes.md).

## In this tree

`scan`, `init` (including `--embed`), [`hook`](hook.md), `preopen`, `pr-context`, the
[GitHub Action](github-action.md) and its reusable workflows, and the
[pre-commit hook](pre-commit.md).

## Coming in v0

- A custom rule that asks for confirmation. `tripcord hook` already
  renders `ask` in each harness's format ([Hook](hook.md#output)).

## Later

- Secrets in transcripts. `--secrets` and `--all` (v1) already parse and
  refuse to scan.
- Live watch.
- Local forensics and blast radius.
- Import from cloud agents.
- Monorepo scoping
  ([#59](https://github.com/vgmartinez/tripcord/issues/59)).
- TC-CFG-013 through zizmor's `agentic-actions` audit, once it is
  released ([#41](https://github.com/vgmartinez/tripcord/issues/41)).
