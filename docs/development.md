# Development

This page is for people changing the scanner. Using it starts at [Getting started](getting-started.md).

## Module and version

The module path in `go.mod` is `github.com/vgmartinez/tripcord`. The CLI package is `./cmd/tripcord`. `internal/project.Repository` is `vgmartinez/tripcord`, and a test checks that `github.com/` plus that constant matches the module path.

`main.version` defaults to `dev`. Override it at link time:

```sh
go build -ldflags "-X main.version=vX.Y.Z" -o tripcord ./cmd/tripcord
```

## Make targets

The [Makefile](../Makefile) is the development entry point. `build` is `CGO_ENABLED=0`. `test` runs the race detector, which needs a C toolchain and cgo; the module itself does not use cgo.

```sh
make fmt      # gofmt -s -w .
make lint     # go vet ./... and golangci-lint run
make test     # go test -race ./...
make build    # bin/tripcord, version from VERSION (default dev)
make test-rule ID=TC-CFG-002
```

## Layout

| Path | Role |
| --- | --- |
| `cmd/tripcord` | CLI: `help`, `version`, `scan`, `init`, `preopen`, and `pr-context` |
| `cmd/wikigen` | Renders `docs/` into the GitHub Wiki. See "Wiki" below |
| `internal/adapters` | Per-harness discovery. One subdirectory per adapter |
| `internal/rules` | YAML rules compiled to CEL, and the scan engine |
| `internal/policy` | Policy file parsing and layer merge |
| `internal/model` | Config items, findings, harness ids, and related types |
| `internal/output` | `text`, `json`, `jsonl`, `sarif`, `md`, and `gha` sinks |
| `internal/exitcode` | Process statuses 0 through 4 |
| `internal/scriptcheck` | Hook-script and checksum-file annotation for rules |
| `internal/hiddenchar` | Hidden-code-point scan used by TC-CFG-011 |
| `internal/fpkey` | Fingerprint key for the `k1` discriminator |
| `internal/wiki` | Page map, link rewriting, and rules catalog for `cmd/wikigen` |
| `rules/` | Core pack embedded in the binary. See [CONTRIBUTING.md](../CONTRIBUTING.md#rules) |
| `schemas/` | JSON Schemas for the event and finding documents. See [schemas/README.md](../schemas/README.md) |
| `docs/` | Design notes. [scan.md](scan.md), [policy.md](policy.md), [output.md](output.md), [fingerprint.md](fingerprint.md) |

Exit statuses live in `internal/exitcode`: 0 no finding at the threshold, 1 findings, 2 hook-mode block, 3 configuration or incomplete scan, 4 internal or I/O. `scan` returns 0, 1, 3, or 4. The user-facing table is in [Commands](commands.md#exit-codes).

## Rules and policy

New rules, fixtures, and the id registry are in [CONTRIBUTING.md](../CONTRIBUTING.md#rules). Policy layers and the no-policy defaults are in [CONTRIBUTING.md](../CONTRIBUTING.md#policy) and [policy.md](policy.md).

## Contributing

[CONTRIBUTING.md](../CONTRIBUTING.md) covers the Developer Certificate of
Origin, rule files, fixtures, and policy layers. Report vulnerabilities as
described in [SECURITY.md](../SECURITY.md).

## Wiki

`docs/` is the source of the [GitHub Wiki](https://github.com/vgmartinez/tripcord/wiki).
Nobody edits the wiki by hand. `cmd/wikigen` renders every `docs/**/*.md`
file to one page, rewrites relative links to wiki pages or to files on
`main`, and replaces the catalog marker in `docs/rules/README.md` with
tables built from `rules/*.yaml` and `rules/ADVISORIES.json`. It fails on
a docs file with no page, a broken link, or a missing anchor, and it
checks the links in the root `README.md`.

```sh
make wiki     # renders into bin/wiki
go test ./internal/wiki
```

A new docs file needs an entry in `docPages` in `internal/wiki` (rule
pages under `docs/rules/` are named after the rule id). The `wiki render
and links` CI job runs both commands on every pull request. After a merge
to `main` that touches `docs/`, `rules/`, or the generator, the `wiki-sync` workflow
renders the pages again and pushes them to the wiki repository's
`master` branch; it makes no commit when nothing changed.

## Decisions

A finding's `decision` is `allow`, `deny`, `warn`, `audit`, or `ask`.
Policy mode (`enforce`, `warn`, `audit`) is a separate vocabulary.

In hook mode, `ask` maps to the harness's native human-confirmation
prompt where that harness has one (Claude Code `PreToolUse`, Cursor
`beforeShellExecution`) and degrades to `deny` with an explanatory
message elsewhere; each adapter's `RenderDecision` does the mapping
([Hook](hook.md#output)). No custom rule produces `ask` yet.

## Repository identity

The GitHub owner and repository name are defined in one place: `Repository`
in `internal/project`.

The module path in `go.mod` is the import path (`github.com/` plus that
constant). A test checks that the two stay in sync. To move the project to
another owner, change those two and leave every other file alone.
