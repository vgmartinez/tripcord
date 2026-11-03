# tripcord

Catch malicious coding-agent configuration before it runs: hooks, MCP servers, skills, and setup commands in Claude Code, Cursor, Copilot, Codex, Gemini CLI, and more.

[![CI](https://github.com/vgmartinez/tripcord/actions/workflows/ci.yml/badge.svg)](https://github.com/vgmartinez/tripcord/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go 1.27.3](https://img.shields.io/badge/Go-1.27.3-00ADD8?logo=go&logoColor=white)](go.mod)

Opening a repository in a coding agent can run code: a SessionStart hook, a folder-open task, an MCP server launched through a shell, or a setup step that pipes curl to sh. tripcord reads that configuration statically, without running the agent, a hook, or a network call, and reports what would run.

## Quick start

tripcord has no published release yet. Build it from source with Go 1.27.3:

```sh
git clone https://github.com/vgmartinez/tripcord.git
cd tripcord
CGO_ENABLED=0 go build -trimpath -o tripcord ./cmd/tripcord
```

`tripcord scan PATH` scans the Git repository that contains `PATH`, or `PATH` itself when it is not inside a checkout. From that checkout, this scans two fixtures in a temporary directory:

```sh
bin="$PWD/tripcord"
sample=$(mktemp -d)
mkdir -p "$sample/.vscode" "$sample/.github/workflows"
cp rules/TC-CFG-002.test/positivos/folderopen-local-script/.vscode/tasks.json "$sample/.vscode/"
cp rules/TC-CFG-009.test/positivos/copilot-curl-pipe-sh/.github/workflows/copilot-setup-steps.yml "$sample/.github/workflows/"
(cd "$sample" && "$bin" scan .)
```

That command exits 1. This is the output, captured from that run:

```text
HIGH TC-CFG-002 .vscode/tasks.json: VS Code task that runs when the folder opens (also Cursor and Windsurf) | fix: Remove runOn: folderOpen or move the task to an explicit script. Cursor and Windsurf open this same .vscode/tasks.json. | fingerprint: tcf_22bc80b217a42306
HIGH TC-CFG-009 .github/workflows/copilot-setup-steps.yml: Environment setup runs code fetched from an unpinned source | fix: Commit the setup script to the repository and run it from there, or pin what it downloads: fetch an https URL that names a commit, or download to a file and check its SHA-256 (sha256sum -c) before running it, with && so a mismatch stops setup. | fingerprint: tcf_529866e0be350750
2 finding(s): 0 critical, 2 high, 0 medium, 0 low
```

The default fail-on is `high`, and both findings are high, so the process exits 1. The same scan with `mode: audit` still prints the findings and exits 0. See [Policy](#policy).

## Supported agents

`tripcord scan` autodetects these adapters. `--harness` takes a comma-separated subset of the same ids. A product that also loads files another adapter owns pulls that adapter in; an informational note on stderr says so.

| Id | Adapter | Docs |
| --- | --- | --- |
| `claude` | Claude Code | [docs/adapters/claude.md](docs/adapters/claude.md) |
| `codex` | Codex | [docs/adapters/codex.md](docs/adapters/codex.md) |
| `cursor` | Cursor | [docs/adapters/cursor.md](docs/adapters/cursor.md) |
| `copilot` | GitHub Copilot | [docs/adapters/copilot.md](docs/adapters/copilot.md) |
| `gemini` | Gemini CLI | [docs/adapters/gemini.md](docs/adapters/gemini.md) |
| `opencode` | OpenCode | [docs/adapters/opencode.md](docs/adapters/opencode.md) |
| `windsurf` | Windsurf | [docs/adapters/windsurf.md](docs/adapters/windsurf.md) |
| `devin` | Devin blueprint | [docs/adapters/devin.md](docs/adapters/devin.md) |
| `devcontainer` | Dev Container configuration | [docs/adapters/devcontainer.md](docs/adapters/devcontainer.md) |
| `generic` | Shared skills, `AGENTS.md`, and `.vscode/` | [docs/adapters/generic.md](docs/adapters/generic.md) |

`.vscode/tasks.json` findings use harness `vscode`. That id is not a `--harness` value (`--harness vscode` exits 3). A harness-limited scan still reads `.vscode/tasks.json`, because the editor runs its folder-open tasks whichever agent is in use.

## Rules

The binary embeds the core pack `tripcord/core@2026.11` (`rules/pack.yaml`). Catalog severity is the `severity` field of each rule file. [TC-CFG-004](docs/rules/TC-CFG-004.md), [TC-CFG-005](docs/rules/TC-CFG-005.md), [TC-CFG-006](docs/rules/TC-CFG-006.md), and [TC-CFG-007](docs/rules/TC-CFG-007.md) also set `severity_when`, so a match of those rules can be medium.

| ID | Name | Severity |
| --- | --- | --- |
| [TC-CFG-001](docs/rules/TC-CFG-001.md) | SessionStart or Setup hook in shared config downloads or runs code from the network | high |
| [TC-CFG-002](docs/rules/TC-CFG-002.md) | VS Code task that runs when the folder opens (also Cursor and Windsurf) | high |
| [TC-CFG-003](docs/rules/TC-CFG-003.md) | MCP server launched through a shell, a pipe to sh, or an inline interpreter | high |
| [TC-CFG-004](docs/rules/TC-CFG-004.md) | permissions.allow with a broad rule in shared config | high |
| [TC-CFG-005](docs/rules/TC-CFG-005.md) | Shared config turns off approvals | high |
| [TC-CFG-006](docs/rules/TC-CFG-006.md) | Hook runs a script outside the repository or at a remote URL | high |
| [TC-CFG-007](docs/rules/TC-CFG-007.md) | Skill registers hooks from its frontmatter | high |
| [TC-CFG-008](docs/rules/TC-CFG-008.md) | Cursor, Copilot, or Windsurf hook reaches the network or always allows | high |
| [TC-CFG-009](docs/rules/TC-CFG-009.md) | Environment setup runs code fetched from an unpinned source | high |
| [TC-CFG-010](docs/rules/TC-CFG-010.md) | Repository ships an agent plugin, which runs arbitrary code | medium |
| [TC-CFG-011](docs/rules/TC-CFG-011.md) | Hidden Unicode in an agent instructions file | high |
| [TC-CFG-012](docs/rules/TC-CFG-012.md) | Agent instructions ask to read secrets or send them out | medium |

Per-rule file lists and examples are in those pages. The pack index is [rules/README.md](rules/README.md).

## Usage

Implemented commands, from `tripcord --help`:

```text
tripcord help
tripcord version
tripcord scan [PATH] [flags]
tripcord init [PATH] [--embed] [--harness h,...] [flags]
```

`version` prints the link-time version, or `dev` when it was not set. `scan --help` prints the flags below.

To scan staged coding-agent configuration before committing, install the
[`tripcord-config` pre-commit hook](docs/pre-commit.md). It reads the Git
index, not unstaged working-tree edits.

### `tripcord init`

`tripcord init` writes `.tripcord/policy.yaml`. `tripcord init --embed --version V --sha256 os-arch=HEX` also writes a pinned `.tripcord/bootstrap.sh`, `.github/workflows/tripcord.yml`, and the hook or setup wiring of each harness in `--harness` (default `claude,cursor,copilot,devin,codex`), merging into existing files. `--dry-run` prints a diff; `--force` resolves conflicts it can. Every hook runs `.tripcord/bootstrap.sh`, which runs the checksum-verified binary by absolute path, never a `tripcord` from `PATH`. Its `hook` mode runs `tripcord hook`, which is planned: do not release `--embed` before it. TC-CFG-016 reports an embed that is missing, edited, or, against a pull request's base, removed or re-pinned. Details are in [docs/init.md](docs/init.md).

### `tripcord scan`

`PATH` defaults to the current directory. The scan reads configuration. It does not execute repository content.

| Flag | Meaning |
| --- | --- |
| `--config` | Scan configuration. This is what a scan does when the flag is omitted. |
| `--secrets`, `--all` | Reserved for secret scanning (planned). Currently exits 3. |
| `--harness` | Comma-separated adapter ids from the table above. Empty means autodetect. |
| `--scope repo\|user\|managed\|all` | `repo` (default) does not read the home directory or system settings. `user` and `managed` read those locations and skip the repository. `all` reads every scope. |
| `--format text\|json\|jsonl\|sarif\|md\|gha` | Default `text`. `json` and `jsonl` both write one `tripcord.finding/v1` document per line. `sarif` is SARIF 2.1.0. `md` is Markdown. `gha` is GitHub Actions workflow commands. Help text lists `text`, `json`, `sarif`, `md`, and `gha`; `jsonl` is accepted as well. |
| `--output path\|-` | Write to a new private (`0600`) local file, or `-` for stdout (default). A symlink is rejected. The destination is replaced only after the result is complete. |
| `--since git-ref` | Repository files that differ between the ref and `HEAD`. The ref must not start with `-`. Untracked files and uncommitted edits are not included. Requires Git. Implies `--base` with the same ref. |
| `--base git-ref` | Also compare a Tripcord embed with the ref's and report one the change removes, re-pins, or drops a harness from (TC-CFG-016). Requires Git. Must equal `--since` when both are given; not allowed with `--staged`. |
| `--fail-on low\|medium\|high\|critical` | Inclusive threshold for this invocation. A locked policy ceiling can be tightened and cannot be loosened. |
| `--policy path` | Repository policy file. The path must exist. The default `.tripcord/policy.yaml` is optional. |
| `--org-policy path` | One organization policy layer, loaded before the repository policy. |

Full behavior, including the fingerprint key and the Git invocation used by `--since`, is in [docs/scan.md](docs/scan.md). Rendering limits are in [docs/output.md](docs/output.md).

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding meets the effective threshold. `--help` also exits 0. |
| 1 | At least one finding meets the threshold, and the effective mode is `enforce`. |
| 2 | Hook-mode block, defined in `internal/exitcode`. `scan` does not return 2. The hook command is planned. |
| 3 | Invalid flags or format, a policy or configuration error, a Git ref `--since` cannot use, an invalid `--output` or `--policy` path, a broken fingerprint key, `--secrets` or `--all`, an unknown command, or an incomplete scan. |
| 4 | Internal error, or a failure to start Git or finish writing the output file. |

An incomplete scan still writes the findings it could produce, prints one diagnostic per problem to stderr, and exits 3. Exit 3 takes precedence over exit 1. Informational notes, such as an extra adapter pulled in by `--harness`, do not change the exit code.

`audit` and `warn` never fail the process, whatever `--fail-on` is. With no policy file, `scan` uses `enforce` and fail-on `high`.

### Policy

`.tripcord/policy.yaml` is the repository policy. `.tripcord/policy.local.yaml` is the per-checkout layer and is not meant to be committed. An organization file is read from `/etc/tripcord/policy.yaml` on Linux, `/Library/Application Support/Tripcord/policy.yaml` on macOS, and `%ProgramData%\Tripcord\policy.yaml` on Windows, and from `--org-policy`.

```yaml
version: 1
mode: audit
fail-on: critical    # low | medium | high | critical
```

`mode` is `enforce`, `warn`, or `audit`. On the sample above, the same binary with `--policy` pointing at this file prints the same two findings and exits 0. Layers, locks, and exceptions are in [docs/policy.md](docs/policy.md).

## CI

There is no published Action. This workflow checks out the repository to scan and this repository, builds `./cmd/tripcord`, writes SARIF, and uploads it. Actions are pinned by commit. `ref: main` is the default branch of this repository; no release tag exists to pin instead.

While tripcord is private, store a fine-grained token with read access to `vgmartinez/tripcord` contents as the `TRIPCORD_READ_TOKEN` secret. Remove the `token:` line once the repository is public.

A high finding makes `scan` exit 1, which fails the job. The upload step still runs. Uploading SARIF on a private repository requires GitHub Code Security.

```yaml
name: tripcord
on:
  pull_request:
permissions:
  contents: read
  actions: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout the repository to scan
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          path: target

      - name: Checkout tripcord
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: vgmartinez/tripcord
          ref: main
          persist-credentials: false
          token: ${{ secrets.TRIPCORD_READ_TOKEN }}
          path: tripcord

      - name: Setup Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version-file: tripcord/go.mod
          cache: false

      - name: Build tripcord
        working-directory: tripcord
        run: CGO_ENABLED=0 go build -trimpath -o "$RUNNER_TEMP/tripcord" ./cmd/tripcord

      - name: Scan
        working-directory: target
        run: '"$RUNNER_TEMP/tripcord" scan . --format sarif --output "$RUNNER_TEMP/tripcord.sarif"'

      - name: Upload SARIF
        if: always() && !cancelled()
        uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          sarif_file: ${{ runner.temp }}/tripcord.sarif
```

`actions: read` is what `github/codeql-action/upload-sarif` requires when the repository is private.

## How it works

- The scan is local: adapters read configuration files and do not start the agent, run a hook, or make a network call, and `--since` denies Git's network transports ([docs/scan.md](docs/scan.md)).
- Rules are CEL with a fixed budget, so a busy machine does not change the result ([docs/scan.md](docs/scan.md)).
- Findings are built from sanitized text, and sinks redact again before display ([docs/output.md](docs/output.md)).
- Fingerprints are stable ids for triage; findings that involved a redacted secret use a per-machine key ([docs/fingerprint.md](docs/fingerprint.md)).

## Roadmap

Planned. None of these are in this build:

- Secrets in transcripts. `--secrets` and `--all` already parse and refuse to scan.
- Live watch.
- Local forensics and blast radius.
- Import from cloud agents.

`preopen`, `pr-context`, `hook`, and a GitHub Action are planned; today the CLI implements `scan` and `init`.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the Developer Certificate of Origin, rule files, fixtures, and policy layers. Package layout, `ldflags`, and Make targets are in [docs/development.md](docs/development.md). Rule format for new rules is [CONTRIBUTING.md](CONTRIBUTING.md#rules) and [rules/README.md](rules/README.md).

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
