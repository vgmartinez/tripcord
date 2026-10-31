# Contributing

This repository is a private pre-release. The license is Apache-2.0
([LICENSE](LICENSE)).

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a contributor license agreement.

Every commit must include a `Signed-off-by` trailer that matches the commit author:

```
git commit -s
```

That adds a trailer of this form:

```
Signed-off-by: Your Name <you@example.com>
```

CI rejects pull requests whose commits are missing that trailer.

## First contributions

Three ways to start, once the corresponding code exists:

1. Add a rule from a public incident, with positive fixtures, negative fixtures, and a link to the incident or to official documentation.
2. Add fixtures for a new version of a harness that already has an adapter.
3. Add an adapter for a harness that is not covered yet.

## Rules

A rule is one YAML file, `rules/<ID>.yaml`, plus fixtures in
`rules/<ID>.test/`. Rules are data: the condition is a CEL expression,
and CEL cannot read files, use the network, or run commands.

```yaml
id: TC-CFG-002
pack: tripcord/core
title: "VS Code task that runs when the folder opens"
severity: high                       # low | medium | high | critical
harness: [vscode, cursor, windsurf]
files: [".vscode/tasks.json"]        # repo-relative or ~/ globs; ** is allowed
when: >-
  has(task.runOptions) && has(task.runOptions.runOn) &&
    task.runOptions.runOn == "folderOpen"
fix: "Remove runOn: folderOpen or move the task to an explicit script"
refs:
  - https://workos.com/blog/npm-worm-coding-agent-config-credentials
```

Every key is required. `refs` needs at least one https link to the
incident or to official documentation; a rule without `refs` is not
accepted. `pack` is the pack name, `<namespace>/<name>`. The version
lives only in `rules/pack.yaml` (for example `tripcord/core@2026.11`);
a rule inherits it. `rules/REGISTRY` is what stops a rule id from being
reused.

`when` sees these variables:

- `config`: the config item (`id`, `harness`, `scope`, `path`, `sha256`, `kind`).
- `payload`: the item's parsed content.
- `task`: the same as `payload` when `config.kind == "task"`, otherwise empty.
- `event`: a `tripcord.event/v1` event, for event rules. Every
  non-list event field is present; omitted strings are `""`.

Reading a field that is missing makes the whole expression false, not
an error. That fails open for negations and deny rules:
`!(payload.tools.size() > 0)` would be false for a server with no
`tools`. So the loader rejects any read below `payload`, `task`, a
comprehension variable (`x` in `payload.servers.exists(x, ...)`), or an
event field outside the schema, unless a `has()` test (or `"key" in x`)
proves it present first: on the left of `&&`, negated on the left of
`||`, or in the condition of `?:`. Guard every level:
`has(task.runOptions) && has(task.runOptions.runOn) && ...`. Index
only with constant string keys; use `exists()` or `all()` for lists.

A match cites the config file by id. When the payload has a stable
entry name, that name is the evidence key: `label` for a task, `name`
for an MCP server, and `matcher|command` for a hook. Two entries in
one file then get different fingerprints. Other kinds have no key.
`matches()` uses RE2: no backreferences or lookaround. Each evaluation
has a cost limit and a timeout (10 ms in scans, 5 ms on the hook path),
and a hook event's rules share a 15 ms budget with a 64 KiB input cap.
The timeouts are cooperative: CEL checks them between steps, so one
`matches()` over a large string finishes before it notices. The input
caps bound that case.

### Rule ids

Rule ids are never reused. `rules/REGISTRY` lists every id ever
allocated. When you add a rule, append a line:

```
TC-CFG-002 active tripcord/core@2026.11
```

To withdraw a rule, delete its YAML and change the line to `retired`.
Do not remove lines. CI compares the file with the pull request base.

### Fixtures

`rules/<ID>.test/positivos/` holds inputs that must trigger the rule and
`rules/<ID>.test/negativos/` inputs that must not. Each needs at least
one file. An engine fixture is a JSON config item, or an array of
them; `sha256` may be left empty. Raw config files are checked later,
with the harness adapters:

```json
{"harness": "vscode", "scope": "repo", "path": ".vscode/tasks.json", "sha256": "",
 "kind": "task", "payload": {"label": "setup", "runOptions": {"runOn": "folderOpen"}}}
```

Run one rule:

```sh
make test-rule ID=TC-CFG-002
```

`go test ./internal/rules` runs every rule's fixtures.

## Policy

The org policy comes from sources the repository does not control: the
managed file (`/etc/tripcord/policy.yaml` on Linux,
`/Library/Application Support/Tripcord/policy.yaml` on macOS,
`%ProgramData%\Tripcord\policy.yaml` on Windows) and any file passed
explicitly, as the `--org-policy` flag or the GitHub Action input will.
In CI, the Action input is only as trustworthy as the managed file: it
comes from the repository's own workflow file, which the repository
controls, so a repo that wants an org layer it cannot bypass in CI
needs the runner-managed file or an org-level required workflow the
repo cannot edit, not the Action input alone.
`.tripcord/policy.yaml` is the repo policy. Its `extends` adds layers
after the org layer; it cannot replace or skip it.
`.tripcord/policy.local.yaml` is the per-checkout layer and is not
committed. `tripcord init`, when it lands, must add
`.tripcord/policy.local.yaml` to the `.gitignore` it writes.

With no policy file, `scan`, `preopen`, `pr-context`, and the Action
run in `enforce` and fail on `high`. The hook defaults to `warn` with
the same fail-on, so it shows findings, including high and critical,
and does not block. A finding only blocks (exit 1, or a hook block)
when mode is `enforce` and its severity is at or above fail-on: `audit`
and `warn` never block, whatever fail-on is. `DefaultsFor` in
`internal/policy` is the only definition of the no-policy defaults. An
explicit `mode` or `fail-on` replaces it. See
[docs/policy.md](docs/policy.md).

`locked` can freeze `mode`, `rules`, and `exceptions`. A locked rule
stays enabled even if a later `rules.include` leaves it out, and a
later layer cannot add an exception for it, pin its pack below the
version in effect at the lock, or remove a harness the rule covers
from `harnesses`. Locking `mode` also locks `fail-on` to a ceiling, the
value in effect at the lock: a later layer may lower it but a raise is
rejected.

## Dependencies and licenses

Every dependency must use a license on the CI allowlist: Apache-2.0,
MIT, BSD-2-Clause, BSD-3-Clause, or ISC. The `dependency licenses` job
fails on anything else, including AGPL, GPL, SSPL, and licenses it
cannot identify.

TruffleHog is AGPL-3.0. It must never be linked into Tripcord, and no
code may be copied from it. Secret detection uses gitleaks rules (MIT).

## Development

```sh
make fmt
make lint
make test
make build
```

`make build` sets `CGO_ENABLED=0`. `make test` runs the race detector, which needs a C toolchain and cgo; the module itself does not use cgo.
