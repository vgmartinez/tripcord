# tripcord

tripcord catches malicious coding-agent configuration before it runs:
hooks, MCP servers, skills, and setup commands in Claude Code, Cursor,
GitHub Copilot, Codex, Gemini CLI, and more.

The [project wiki](https://github.com/vgmartinez/tripcord/wiki) is
generated from the repository's
[`docs/`](https://github.com/vgmartinez/tripcord/tree/main/docs)
directory by `cmd/wikigen` and pushed by the `wiki-sync` workflow when
`main` changes; nobody edits the wiki by hand. To change a page, edit the
matching file under `docs/` and open a pull request.

## What it is

Opening a repository in a coding agent can run code: a SessionStart hook,
a folder-open task, an MCP server launched through a shell, or a setup
step that pipes curl to sh. tripcord reads that configuration statically,
without running the agent, a hook, or a network call, and reports what
would run. It works on a checkout ([`scan`](scan.md)), on a repository you
have not cloned yet ([`preopen`](preopen.md)), on a pull request in CI
([`pr-context`](pr-context.md) and the [GitHub Action](github-action.md)),
and before a commit ([pre-commit](pre-commit.md)).

## Install

There is no published release, and no npm or PyPI package. Install from
source with Go 1.27.3 or newer:

```sh
go install github.com/vgmartinez/tripcord/cmd/tripcord@main
```

or build a checkout:

```sh
git clone https://github.com/vgmartinez/tripcord.git
cd tripcord
CGO_ENABLED=0 go build -trimpath -o tripcord ./cmd/tripcord
```

In GitHub Actions, call the reusable workflow pinned by commit
([GitHub Action](github-action.md)). It builds tripcord from source too.

## 60-second quickstart

1. Scan a repository. Exit 1 means a finding at or above `high`:

   ```sh
   tripcord scan .
   ```

2. Write a repository policy (`.tripcord/policy.yaml`) with
   [`tripcord init`](init.md):

   ```sh
   tripcord init .
   ```

   `init --embed` also wires each harness's hooks to a pinned,
   checksum-verified bootstrap that runs [`tripcord hook`](hook.md).
   `--embed` is not releasable yet, so read [Init](init.md) before you
   embed.

3. Run it on every pull request with the
   [GitHub Action](github-action.md), or before every commit with the
   [pre-commit hook](pre-commit.md).

[Getting started](getting-started.md) walks through a scan with real
output. [Commands](commands.md) lists every command, flag, and exit code.

## Pages

- Using tripcord: [Getting started](getting-started.md),
  [Commands](commands.md), [FAQ and troubleshooting](faq.md).
- Commands: [`scan`](scan.md), [`init` and `init --embed`](init.md),
  [`preopen`](preopen.md), [`pr-context`](pr-context.md),
  [fingerprints](fingerprint.md), [output and sinks](output.md).
- CI and hooks: [GitHub Action](github-action.md),
  [pre-commit](pre-commit.md).
- Configuration: [Policy](policy.md),
  [Harness adapters](adapters/README.md),
  [Rules catalog](rules/README.md).
- Project: [Roadmap](roadmap.md), [Release notes](release-notes.md),
  [Development](development.md).
