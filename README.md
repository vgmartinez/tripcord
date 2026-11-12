# tripcord

Catch malicious coding-agent configuration before it runs: hooks, MCP servers, skills, and setup commands in Claude Code, Cursor, Copilot, Codex, Gemini CLI, and more.

[![CI](https://github.com/vgmartinez/tripcord/actions/workflows/ci.yml/badge.svg)](https://github.com/vgmartinez/tripcord/actions/workflows/ci.yml) [![Latest release](https://img.shields.io/github/v/release/vgmartinez/tripcord?sort=semver)](https://github.com/vgmartinez/tripcord/releases/latest) [![Marketplace: Tripcord Security](https://img.shields.io/badge/Marketplace-Tripcord_Security-2088FF?logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/tripcord-security) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE) [![Go 1.27.3](https://img.shields.io/badge/Go-1.27.3-00ADD8?logo=go&logoColor=white)](go.mod)

tripcord reads agent configuration statically, without running the agent, a hook, or a network call, and reports what would run.

Other repositories can show a static [Scanned with Tripcord](docs/badge.md) badge. The image is shields.io; the binary does not fetch it.

## What it catches

- Session-start and setup hooks that download or run code from the network.
- MCP servers launched through a shell, a pipe to `sh`, an inline interpreter, or a package version with a known advisory.
- Shared settings that turn off approvals or every hook, allow broad commands, or allowlist hosts with a public read-back channel.
- Folder-open tasks, unpinned environment setup, and agent plugins that run code when a repository is opened.
- Hidden Unicode and secret-reading instructions in agent instruction files.

## Install

```sh
brew install vgmartinez/tap/tripcord   # macOS and Linux
npx tripcord scan .                    # npm
uvx tripcord scan .                    # PyPI (or: pip install tripcord)
```

Each one installs the release binary and checks it against the release's `SHA256SUMS`; see [Installation](https://github.com/vgmartinez/tripcord/wiki/Installation) for what each verifies.

Or download an archive for your platform and `SHA256SUMS` from [Releases](https://github.com/vgmartinez/tripcord/releases), then check the checksum and the build provenance:

```sh
gh release download v0.1.0 --repo vgmartinez/tripcord --pattern 'tripcord_0.1.0_linux_amd64.tar.gz' --pattern SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify tripcord_0.1.0_linux_amd64.tar.gz --repo vgmartinez/tripcord
tar -xzf tripcord_0.1.0_linux_amd64.tar.gz tripcord && ./tripcord --version
```

`gh attestation verify` needs `gh auth login` or `GH_TOKEN`; the checksum step does not.

Archives exist for linux, darwin, and windows on amd64 and arm64; see [Installation](https://github.com/vgmartinez/tripcord/wiki/Installation).

Or install from source with Go 1.27.3 or newer:

```sh
go install github.com/vgmartinez/tripcord/cmd/tripcord@main
```

or build a checkout:

```sh
git clone https://github.com/vgmartinez/tripcord.git
cd tripcord
CGO_ENABLED=0 go build -trimpath -o tripcord ./cmd/tripcord
```

In CI, use the GitHub Action or the reusable workflow pinned by commit (step 3 below). Both build tripcord from source.

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

**3. Run it on every pull request**, with the [Tripcord Security](https://github.com/marketplace/actions/tripcord-security) action:

```yaml
name: tripcord
on:
  pull_request:

jobs:
  tripcord:
    runs-on: ubuntu-latest
    permissions:
      contents: read # checkout the repository being scanned
      pull-requests: read # read pull request reviews
      security-events: write # upload the SARIF report
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: vgmartinez/tripcord@v0.1.0
```

To adopt it gradually, start in report-only mode: SARIF and the pull request comment are still published, and findings are a warning with the finding count instead of a failed job. Exit 3, exit 4, and an invalid `path` still fail.

```yaml
      - uses: vgmartinez/tripcord@v0.1.0
        with:
          fail-on: none
```

or with the reusable workflow, pinned by commit:

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
    uses: vgmartinez/tripcord/.github/workflows/tripcord-pr.yml@12c7476ae05ea2c791ea39ef44bd4f1a0f5f9164 # main@12c7476
```

or before every commit, with [pre-commit](https://pre-commit.com/):

```yaml
repos:
  - repo: https://github.com/vgmartinez/tripcord
    rev: 12c7476ae05ea2c791ea39ef44bd4f1a0f5f9164 # main@12c7476
    hooks:
      - id: tripcord-config
```

## Documentation

The [wiki](https://github.com/vgmartinez/tripcord/wiki) is generated from [`docs/`](docs/README.md):

- [Getting started](https://github.com/vgmartinez/tripcord/wiki/Getting-Started)
- [Installation](https://github.com/vgmartinez/tripcord/wiki/Installation): Homebrew, npm, PyPI, release archives, checksums, and provenance
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
