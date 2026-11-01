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
  raw and archive paths do. A `sha256:<64 hex>` digest counts only
  after an OCI `blobs` or `manifests` segment. Any other host, a
  release asset, a tag, a branch, userinfo
  (`raw.githubusercontent.com@evil.example`), or a trailing-dot host
  is not a pin. Nor is a path with a `.` or `..` segment, as written or
  percent-encoded in any case (`%2e%2e`, `.%2E`): curl and wget resolve
  it before the request, so `<sha>/../main/` fetches `main`. The host
  match is case-insensitive.
- **Checksum verified before execution.** The next statement is
  `sha256sum -c <file>` (or `sha384sum`, `sha512sum`, or
  `shasum -a 256|384|512 -c`). The file is not `-` or under `/dev`, and
  the check has no other flag (`--ignore-missing`, `--quiet`, and the
  rest do not count). It joins the download to the command that runs it
  only with `&&`. A top-level `set -e` or `set -euo pipefail` also
  covers a check on the following statement, unless the line later has
  `set +e`, or has `||`, `!`, or a pipe anywhere. `set -e` inside a
  subshell, a function, or `if` does not count.

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
  as `bash {0}` is not, and a step whose script starts with `set +e`
  turns errexit back off.
- Variables are not expanded, and the script a setup command fetches
  is not read.
- The checksum itself is not compared with anything: the rule checks
  that a check runs, not that the expected hash is right.

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

Not reported:

```json
{"install": "curl -fsSLo t.sh https://get.tools.example.invalid/t.sh && sha256sum -c t.sh.sha256 && sh t.sh"}
```

```json
{"postCreateCommand": "curl -fsSL https://raw.githubusercontent.com/acme/tools/0123456789abcdef0123456789abcdef01234567/install.sh | sh"}
```

## How to fix

Commit the setup script to the repository and run it from there. If it
must be downloaded, fetch an `https` URL that names a commit or digest,
or download it to a file and check its SHA-256 (`sha256sum -c`) before
running it, joined with `&&` so a mismatch stops setup.

## References

- [GitHub: customize the Copilot coding agent's environment](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment)
- [Cursor cloud agents](https://cursor.com/docs/cloud-agent)
- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
- [WorkOS: the npm worm and coding-agent config](https://workos.com/blog/npm-worm-coding-agent-config-credentials)
