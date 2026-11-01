# TC-CFG-009: Environment setup runs code fetched from an unpinned source

| | |
| --- | --- |
| Severity | high |
| Harnesses | Copilot (coding agent), Cursor (cloud agents), dev containers |
| Files | `.github/workflows/copilot-setup-steps.yml`, `.cursor/environment.json`, `.devcontainer/devcontainer.json`, `.devcontainer/<name>/devcontainer.json`, `.devcontainer.json` (repository scope) |
| Rule | [`rules/TC-CFG-009.yaml`](../../rules/TC-CFG-009.yaml) |

## What it detects

A cloud agent or a dev container runs the repository's environment
setup on its own, before anyone reviews what that setup downloaded. A
setup command that fetches code from a source that can change, and runs
it, runs whatever that source serves the next time.

Commands read:

- Copilot: the `run` of each step of the `copilot-setup-steps` job.
  `uses` steps are not read.
- Cursor: the `install` and `start` strings and each terminal
  `command` in `.cursor/environment.json`.
- Dev containers: `initializeCommand`, `onCreateCommand`,
  `updateContentCommand`, `postCreateCommand`, `postStartCommand`, and
  `postAttachCommand`, as a string, an array, or an object of named
  commands. `initializeCommand` runs on the host before the container
  starts, so is the most sensitive lifecycle command. An `http(s)`
  tarball Feature is read as a `curl` of its URL.

Each command is read by `shell.unpinned`, which reports the same
risks as `shell.risks` (see [TC-CFG-001](TC-CFG-001.md): a fetch, a
pipe into a shell or Invoke-Expression, encoded PowerShell, or
nesting it cannot follow) unless every fetch in the command is pinned.

## What "pinned" means

A command is pinned in one of two ways. A command that mixes the two is
not.

- **Immutable URL.** Every downloader target is `https`, has no
  userinfo, and its host does not end in a dot. The commit has to sit
  where that host actually stores an immutable object:
  `raw.githubusercontent.com/<owner>/<repo>/<sha>/`,
  `github.com/<owner>/<repo>/raw/<sha>/`,
  `github.com/<owner>/<repo>/archive/<sha>.tar.gz` or `.zip`,
  `codeload.github.com` archive paths (`tar.gz`, `zip`,
  `legacy.tar.gz`, `legacy.zip`), a gist `raw/<sha>/` path,
  `cdn.jsdelivr.net/gh/<user>/<repo>@<sha>/`, or
  `gitlab.com/<group>/<project>/-/raw/<sha>/`. A 40- or 64-digit hex
  commit on one of those paths cannot change. jsDelivr and GitLab are
  on the list because those exact paths address one commit, as GitHub's
  raw and archive paths do. A `sha256:<64 hex>` digest in the URL,
  even after an OCI `blobs` or `manifests` segment, is not a pin:
  curl and wget do not verify it. Any other host, a
  release asset, a tag, a branch, userinfo
  (`raw.githubusercontent.com@evil.example`), or a trailing-dot host
  is not a pin. Nor is a path with a `.` or `..` segment, as written or
  percent-encoded in any case (`%2e%2e`, `.%2E`): curl and wget resolve
  it before the request, so `<sha>/../main/` fetches `main`. The host
  match is case-insensitive.
- **Checksum verified before execution.** The whole script (the step,
  the string, or the payload of an exact `["sh"|"bash", "-c", script]`
  array) parses under the checksum grammar below. The grammar is an
  allowlist: anything it does not list gives no checksum credit, and
  the fetch is reported. An unusual script that is in fact safe can be
  reported. That is the intended trade-off.

### The checksum grammar

Every command in the script is one of these forms:

| Form | Accepted | Notes |
| --- | --- | --- |
| Fetch | `curl -o <file> <url>`, `wget -O <file> <url>` | Exactly one `http(s)` URL and one plain output filename: `^[A-Za-z0-9_][A-Za-z0-9._-]*$`. It has no `/`, leading dot, or leading `-` (so not `-q` or `--`) and is not `curlrc`, `_curlrc`, `wgetrc`, `.wgetrc`, `netrc`, or `_netrc`, or a command the grammar runs (`sha256sum`, `sh`, ...), in any case (`CURLRC` and `SH` are rejected too, since macOS and Windows file systems ignore case). It is never a sums file. This prevents a fetch from planting curl, wget, loader, or netrc configuration. curl options: `-f -s -S -L -k` (clustered, `-o` last), `--fail`, `--silent`, `--show-error`, `--location`, `--create-dirs`, `--compressed`, `--fail-with-body`, `--no-progress-meter`, `--tlsv1.2`, `--tlsv1.3`, `--http1.1`, `--retry`, `--retry-delay`, `--retry-max-time`, `--connect-timeout`, `--max-time`, `--proto`, `--proto-redir`, `--output`. wget options: `-q`, `-nv`, `--quiet`, `--no-verbose`, `--https-only`, `--tries`, `--timeout`, `--output-document`. |
| Check | `sha256sum -c <sums>`, `shasum -a 256 -c <sums>` | `--check` is the long form of `-c`. No other option. `<sums>` is a plain filename, not `-` or a path. It must be committed to the repository (see below), and is never fetched or run by the script. |
| Entry check | `echo '<64 hex>  <file>' \| sha256sum -c [-]` | Or `printf '<64 hex>  <file>\n'`, or `shasum -a 256 -c [-]`. The text is parsed: exactly one entry, 64 hex digits, two spaces or ` *`, and a plain filename. No `echo` option, no `printf` conversion, and no escape except a final `\n`. It covers only the file it names. The pipe is exactly these two commands, the check last, so it fails when the check fails without `pipefail`. |
| Run | `sh <file>`, `bash <file>` | `<file>` is a plain filename the script fetched; no shell option. Arguments after it are passed to the script. |
| Errexit | `set -e`, `set -eu`, `set -euo pipefail`, `set -eo pipefail`, `set -o errexit` | Only before every other command, each a statement of its own. A `set` anywhere else gives no credit. |
| Files | `mkdir <file>`, `rm <file>`, `chmod <mode> <file>` | Every file is a plain filename. `chmod` mode is exactly `+x`, `0755`, or `u+x`. `cd` is not accepted. |

Syntax:

- Statements are joined by `;`, a newline, or `&&`. A newline may
  follow `&&`. `#` starts a comment at the start of a word. The only
  pipe is the one of an entry check.
- Command names are literal: not quoted, not escaped, no path
  (`/usr/bin/curl`), no variable.
- Unquoted words use letters, digits, and `_-./:=+,@%^`. Double quotes
  may not hold `$`, a backquote, `\`, or `!`. Single quotes may hold
  anything.
- Anything else gives no credit: another command (`trap`, `eval`,
  `source`, `.`, `alias`, `shopt`, `exec`, `true`, `:`, `npm`, ...), a
  function, a subshell, `{ }`, `if`/`while`/`for`/`case`, `||`, `&`, a
  redirection, `$`, a backquote, a backslash outside single quotes, a
  glob, `~`, a carriage return, `cd`, `export`, or an assignment.

Order:

- Each run of a file comes after a check that covers it, with no fetch
  between the check and the run. The check stops the run when it
  fails: it is in the same `&&` list, or the script starts with
  `set -e` and the check is a statement of its own.
- Each fetch is followed by a check that covers its file before the
  file is fetched again, and that fails the script: a statement of its
  own under `set -e`, or part of the script's last statement. Every
  fetched file must be either the script run or the file named by an
  entry check; an unused fetch gives no credit.
- A sums file is never a fetch target and never run, and is not the
  run file. Names are compared case-insensitively here, so
  `curl -o i.sh ...; sha256sum -c I.SH` gives no credit either.
- An entry check covers only the file it names. A plain check
  (`sha256sum -c <sums>`) covers only the files `<sums>` lists, and
  only when `<sums>` is committed to the scanned repository:
  - it exists at the repository root as a regular file. Like the hook
    scripts of `internal/scriptcheck`, its parent path is resolved with
    `Stat` and `EvalSymlinks` and must stay inside the repository. Its
    final component is checked with `Lstat` and must itself be a regular
    file: a committed sums-file symlink, even one to a file inside the
    repository, gives no credit. It is then read through the
    repository's confined reader, at most 64 KiB;
  - every line is `<64 hex>  <name>` or `<64 hex> *<name>`, with an
    optional final newline. A blank line, a comment, a carriage return,
    or the BSD `SHA256 (name) = ...` form makes the file malformed;
  - the run file appears in it, exactly as the script names it.

  A missing, unreadable, out-of-tree, or malformed sums file, or one
  that lists only other files, gives no credit. The file is looked up
  in the repository root, where Copilot, Cursor, and dev containers
  run setup. A Copilot step with a `working-directory` (its own, or the
  job's or workflow's `defaults.run`), and a `devcontainer.json` that
  sets `workspaceFolder`, run elsewhere, so get no credit for a plain
  check.
- Each file the grammar fetches or runs is also checked with `Lstat`.
  If a committed path with that filename is a symlink, the script gets
  no checksum credit. This prevents a downloaded script from being
  written through a link (including one to the sums file or outside the
  repository), and prevents a sums-file symlink from aliasing the
  downloaded script. The repository directory is inspected
  case-insensitively: `T.SH` is treated as a match for `t.sh`, because
  macOS and Windows may open it for `t.sh`. A symlink or non-regular
  case variant therefore also gets no credit. For a sums file, any
  alternate-cased entry (even a regular one) gets no credit, so the
  named sums file is unambiguous.

Copilot steps whose effective shell is fail-closed are read with a
leading `set -e`, so a check on its own line counts there.

Accepted:

```sh
curl -fsSLo t.sh https://get.tools.example.invalid/t.sh && sha256sum -c t.sh.sha256 && sh t.sh
```

```sh
set -euo pipefail
curl -fsSLo t.sh https://get.tools.example.invalid/t.sh
echo "<sha256>  t.sh" | sha256sum -c -
sh t.sh
```

Not accepted: `trap 'sh t.sh' EXIT` anywhere, `echo set -e`, `\set +e`,
`sha256sum() { :; }`, `echo "<sha256>  /dev/null" | sha256sum -c`,
`echo "<sha256>  other.sh" | sha256sum -c && sh t.sh`,
`printf '%s  t.sh\n' <sha256> | sha256sum -c`, a fetched sums file
(`curl -o t.sha ...; curl -o t.sh ...; sha256sum -c t.sha; sh t.sh`),
and the script as its own sums file
(`curl -o t.sh ...; sha256sum -c t.sh; sh t.sh`).

Never pinned: package runners (`npx -y`, `bunx`, `pnpm dlx`,
`yarn dlx`, `uvx`, `pipx run`), tags, `git clone` (including a later
checkout of a 40-hex sha), inline `python -c` or `node -e` network
code, a downloader whose target is a variable, and encoded or
too-deeply nested payloads.

## Limits

- Devin's `.devin/blueprint.yaml` is not read: no adapter normalizes
  it yet.
- `RUN` lines of a Dockerfile and OCI Feature references
  (`ghcr.io/devcontainers/features/node:1`) are not read. OCI Feature
  tags are not flagged.
- Copilot's effective shell is the step's `shell`, then the job's
  `defaults.run.shell`, then the workflow's, then GitHub's default
  `bash --noprofile --norc -eo pipefail {0}`. The built-in names `bash`
  and `sh` are also fail-closed (`sh -e {0}`). A custom template such
  as `bash {0}` is not. A step that runs `set +e` or anything else
  outside the checksum grammar gets no checksum credit.
- Variables are not expanded, and the script a setup command fetches
  is not read.
- The checksum itself is not compared with anything: the rule checks
  that a check runs against a hash committed to the repository, not
  that the hash is right.

## Examples

Reported:

```yaml
# .github/workflows/copilot-setup-steps.yml
jobs:
  copilot-setup-steps:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://get.tools.example.invalid/install.sh | sh
```

```json
{"postCreateCommand": "npx -y @acme/bootstrap"}
```

Not reported, with `t.sh.sha256` committed at the repository root and
holding `<sha256>  t.sh`:

```json
{"install": "curl -fsSLo t.sh https://get.tools.example.invalid/t.sh && sha256sum -c t.sh.sha256 && sh t.sh"}
```

```yaml
      - run: |
          curl -fsSLo t.sh https://get.tools.example.invalid/t.sh
          echo "<sha256>  t.sh" | sha256sum -c -
          sh t.sh
```

```json
{"postCreateCommand": "curl -fsSL https://raw.githubusercontent.com/acme/tools/0123456789abcdef0123456789abcdef01234567/install.sh | sh"}
```

## How to fix

Commit the setup script to the repository and run it from there. If it
must be downloaded, fetch an `https` URL that names a commit,
or download it to a file and check its SHA-256 before running it,
joined with `&&` so a mismatch stops setup: put the hash in the
command (`echo '<sha256>  t.sh' | sha256sum -c`) or in a sums file
committed to the repository (`sha256sum -c t.sh.sha256`), never in a
file the setup downloads. Keep that script
to the checksum grammar: move anything else to a separate step or to a
committed script.

## References

- [GitHub: customize the Copilot coding agent's environment](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment)
- [Cursor cloud agents](https://cursor.com/docs/cloud-agent)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
- [WorkOS: the npm worm and coding-agent config](https://workos.com/blog/npm-worm-coding-agent-config-credentials)
