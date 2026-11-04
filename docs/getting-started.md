# Getting started

This page builds tripcord, scans a sample with two known findings, and
explains the result. For every command and flag, see
[Commands](commands.md).

## Build

tripcord has no published release yet. Build it from source with
Go 1.27.3:

```sh
git clone https://github.com/vgmartinez/tripcord.git
cd tripcord
CGO_ENABLED=0 go build -trimpath -o tripcord ./cmd/tripcord
```

`go install github.com/vgmartinez/tripcord/cmd/tripcord@main` installs
the same binary into `$(go env GOPATH)/bin`. Either way, `tripcord
version` prints `dev`, because the version is only set at link time
([Development](development.md#module-and-version)).

## Scan a sample

`tripcord scan PATH` scans the Git repository that contains `PATH`, or
`PATH` itself when it is not inside a checkout. From that checkout, this
scans two fixtures in a temporary directory. A raw fixture is a text
archive: each file follows a `-- path --` line, and `member` prints
one file of it.

```sh
bin="$PWD/tripcord"
sample=$(mktemp -d)
mkdir -p "$sample/.vscode" "$sample/.github/workflows"
member() { awk -v want="-- $2 --" '/^-- .* --$/ { on = ($0 == want); next } on' "$1"; }
member rules/TC-CFG-002.test/positivos/folderopen-local-script.txtar .vscode/tasks.json > "$sample/.vscode/tasks.json"
member rules/TC-CFG-009.test/positivos/copilot-curl-pipe-sh.txtar .github/workflows/copilot-setup-steps.yml > "$sample/.github/workflows/copilot-setup-steps.yml"
(cd "$sample" && "$bin" scan .)
```

That command exits 1. This is the output, captured from that run:

```text
HIGH TC-CFG-002 .vscode/tasks.json: VS Code task that runs when the folder opens (also Cursor and Windsurf) | fix: Remove runOn: folderOpen or move the task to an explicit script. Cursor and Windsurf open this same .vscode/tasks.json. | fingerprint: tcf_22bc80b217a42306
HIGH TC-CFG-009 .github/workflows/copilot-setup-steps.yml: Environment setup runs code fetched from an unpinned source | fix: Commit the setup script to the repository and run it from there, or pin what it downloads: fetch an https URL that names a commit, or download to a file and check its SHA-256 (sha256sum -c) before running it, with && so a mismatch stops setup. | fingerprint: tcf_529866e0be350750
2 finding(s): 0 critical, 2 high, 0 medium, 0 low; 0 warning(s)
```

The default fail-on is `high`, and both findings are high, so the
process exits 1. The same scan with `mode: audit` still prints the
findings and exits 0. Save this as `audit.yaml` in the sample and pass
it with `--policy`:

```yaml
version: 1
mode: audit
fail-on: critical    # low | medium | high | critical
```

```sh
(cd "$sample" && "$bin" scan . --policy audit.yaml)
```

That prints the same two findings and exits 0. Layers, locks, and
exceptions are in [Policy](policy.md).

Each line is one finding: severity, [rule id](rules/README.md), path,
title, fix, and a [fingerprint](fingerprint.md) you can use to triage
it. `--format json`, `sarif`, `md`, and `gha` write the same findings
for machines ([Output and sinks](output.md)).

## How it works

- The scan is local: adapters read configuration files and do not
  start the agent, run a hook, or make a network call, and `--since`
  denies Git's network transports ([`scan`](scan.md)).
- Rules are CEL with a fixed budget, so a busy machine does not change
  the result ([`scan`](scan.md#rule-evaluation)).
- Findings are built from sanitized text, and sinks redact again
  before display ([Output and sinks](output.md)).
- Fingerprints are stable ids for triage; findings that involved a
  redacted secret use a per-machine key
  ([Fingerprints](fingerprint.md)).

## Next steps

- Scan a repository before you clone it: [`preopen`](preopen.md).
- Commit a policy and, optionally, embed tripcord into the
  repository's agent hooks: [`init`](init.md).
- Run it in CI: [GitHub Action](github-action.md), or before each
  commit: [pre-commit](pre-commit.md).
