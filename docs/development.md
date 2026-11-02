# Development

This page is for people changing the scanner. Using it is in the [README](../README.md).

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
| `cmd/tripcord` | CLI: `help`, `version`, and `scan` |
| `internal/adapters` | Per-harness discovery. One subdirectory per adapter |
| `internal/rules` | YAML rules compiled to CEL, and the scan engine |
| `internal/policy` | Policy file parsing and layer merge |
| `internal/model` | Config items, findings, harness ids, and related types |
| `internal/output` | `text`, `json`, `jsonl`, `sarif`, `md`, and `gha` sinks |
| `internal/exitcode` | Process statuses 0 through 4 |
| `internal/scriptcheck` | Hook-script and checksum-file annotation for rules |
| `internal/hiddenchar` | Hidden-code-point scan used by TC-CFG-011 |
| `internal/fpkey` | Fingerprint key for the `k1` discriminator |
| `rules/` | Core pack embedded in the binary. See [CONTRIBUTING.md](../CONTRIBUTING.md#rules) |
| `schemas/` | JSON Schemas for the event and finding documents. See [schemas/README.md](../schemas/README.md) |
| `docs/` | Design notes. [scan.md](scan.md), [policy.md](policy.md), [output.md](output.md), [fingerprint.md](fingerprint.md) |

Exit statuses live in `internal/exitcode`: 0 no finding at the threshold, 1 findings, 2 hook-mode block, 3 configuration or incomplete scan, 4 internal or I/O. `scan` returns 0, 1, 3, or 4. The user-facing table is in the [README](../README.md#exit-codes).

## Rules and policy

New rules, fixtures, and the id registry are in [CONTRIBUTING.md](../CONTRIBUTING.md#rules). Policy layers and the no-policy defaults are in [CONTRIBUTING.md](../CONTRIBUTING.md#policy) and [policy.md](policy.md).
