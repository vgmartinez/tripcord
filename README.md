# tripcord

Catch malicious coding-agent configuration before it runs: hooks, MCP servers, skills, and setup commands in Claude Code, Cursor, Copilot, Codex, Gemini CLI, and more.

[![CI](https://github.com/vgmartinez/tripcord/actions/workflows/ci.yml/badge.svg)](https://github.com/vgmartinez/tripcord/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go 1.27.3](https://img.shields.io/badge/Go-1.27.3-00ADD8?logo=go&logoColor=white)](go.mod)

tripcord reads agent configuration statically, without running the agent, a hook, or a network call, and reports what would run.

## What it catches

- Session-start and setup hooks that download or run code from the network.
- MCP servers launched through a shell, a pipe to `sh`, an inline interpreter, or a package version with a known advisory.
- Shared settings that turn off approvals or every hook, allow broad commands, or allowlist hosts with a public read-back channel.
- Folder-open tasks, unpinned environment setup, and agent plugins that run code when a repository is opened.
- Hidden Unicode and secret-reading instructions in agent instruction files.

## Install

There is no published release and no npm or PyPI package. Install from source with Go 1.27.3 or newer:

```sh
go install github.com/vgmartinez/tripcord/cmd/tripcord@main
```

or build a checkout:

```sh
git clone https://github.com/vgmartinez/tripcord.git
cd tripcord
CGO_ENABLED=0 go build -trimpath -o tripcord ./cmd/tripcord
```

In CI, use the reusable workflow pinned by commit (step 3 below). It builds tripcord from source at that commit.

## Quickstart

**1. Scan a repository.** It exits 1 when a finding is at or above `high`:

```sh
tripcord scan .
```

**2. Add a policy, and optionally embed tripcord into the repository's agent hooks.** `init` writes `.tripcord/policy.yaml`. `init --embed` also writes a checksum-pinned bootstrap, a pull request workflow, and each harness's hook wiring:

```sh
tripcord init .
tripcord init . --embed --version <version> --sha256 linux-x64=<sha256> --dry-run
```

`--embed` needs a Git repository. `--version` and `--sha256` pin the binary the hooks may run; `--dry-run` prints the diff. The embedded hooks run [`tripcord hook --on-failure block`](https://github.com/vgmartinez/tripcord/wiki/Hook) from the verified binary in the bootstrap's cache, which you fill with `go build -trimpath` of the pinned commit; the bootstrap never downloads anything. A hook that cannot decide, or finds no verified binary, blocks the tool call, except when a Copilot hook times out. See [Init](https://github.com/vgmartinez/tripcord/wiki/Init).

**3. Run it on every pull request**, with the GitHub Action:

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
    uses: vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@277066a292b8717d4d91393a10d00c5dd2d51cdb # main@277066a
```

or before every commit, with [pre-commit](https://pre-commit.com/):

```yaml
repos:
  - repo: https://github.com/vgmartinez/tripcord
    rev: 277066a292b8717d4d91393a10d00c5dd2d51cdb # main@277066a
    hooks:
      - id: tripcord-config
```

## Documentation

The [wiki](https://github.com/vgmartinez/tripcord/wiki) is generated from [`docs/`](docs/README.md):

- [Getting started](https://github.com/vgmartinez/tripcord/wiki/Getting-Started)
- [Commands](https://github.com/vgmartinez/tripcord/wiki/Commands) and [exit codes](https://github.com/vgmartinez/tripcord/wiki/Commands#exit-codes)
- [Policy](https://github.com/vgmartinez/tripcord/wiki/Policy)
- [Rules catalog](https://github.com/vgmartinez/tripcord/wiki/Rules-Catalog)
- [Harness adapters](https://github.com/vgmartinez/tripcord/wiki/Harness-Adapters)
- [GitHub Action](https://github.com/vgmartinez/tripcord/wiki/GitHub-Action) and [pre-commit](https://github.com/vgmartinez/tripcord/wiki/Pre-commit)
- [FAQ and troubleshooting](https://github.com/vgmartinez/tripcord/wiki/FAQ)

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) covers the Developer Certificate of Origin, rules, and fixtures. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
