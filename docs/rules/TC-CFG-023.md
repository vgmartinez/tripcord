# TC-CFG-023: MCP server pins a package version with a known vulnerability

| | |
| --- | --- |
| Severity | high, or critical when the advisory is critical |
| Harnesses | Claude Code, Codex, Copilot, Cursor, Gemini CLI, OpenCode, Windsurf, VS Code |
| Files | every stdio or local MCP server any adapter normalizes, any scope |
| Rule | [`rules/TC-CFG-023.yaml`](../../rules/TC-CFG-023.yaml) |
| List | [`rules/ADVISORIES.json`](../../rules/ADVISORIES.json), part of the free `tripcord/core` pack |

## What it detects

A stdio MCP server whose command is a known package launcher, and whose
package spec can resolve only to versions named by the offline advisory
list. Remote `http`, `sse`, and URL servers are out of scope.

Launchers in v0.1:

- npm: `npx`, `bunx`, `npm exec`, `npm x`, `pnpm dlx`, `yarn dlx`. The
  first positional is the package, unless `-p` or `--package` is set, in
  which case each of those specs is a package and the positional is the
  binary.
- Python: `uvx` and `uv tool run` (the first positional, replaced by
  `--from`; each `--with` is an extra package), `uv run` (only
  `--with`), and `pipx run` (`--spec`, or the first positional).
- `docker run`, `docker container run`, and `podman run`. The first
  positional after options is the image.
- `python -m <module>` and `python <path>.py`, only for an advisory
  that has no fixed version.
- A git URL in `--from`, `--with`, `--spec`, or an npm spec:
  `git+https://…` or `github:user/repo`, with an optional `@ref` or
  `#ref`.

An exact version matches when it falls in an affected interval
(`introduced` inclusive, `fixed` exclusive). A range matches only when
every version it admits is inside that interval, so `~0.5.0` matches a
fix of 0.6.3 and `^0.6.0` does not. A spec with no version, `@latest`,
another dist-tag, `:latest`, or a git branch does not match when the
advisory has a fixed version. It does match when the advisory has no
fixed version, because every current resolution is still affected.

A git ref of 7 to 40 hex digits is a commit, a ref shaped like a version
(`v3.0.0`) is a tag, and any other name is a branch. When the advisory
has no fixed version, any ref matches: a commit, a tag, a branch, or no
ref. When it has one, only a commit listed in `affected_commits`
matches. Tags are not listed in advisories, because a tag can be moved.

`pip install` is not a launcher. `sh -c` around a package command is
already TC-CFG-003.

## Severity

The finding uses the advisory's severity, with a floor of high.
Moderate and low advisories are reported high, so the default fail-on
high stops them. Critical stays critical. The CEL value `v.severity` is
the advisory's own word (`critical`, `high`, `moderate`, or `low`); the
floor is applied by `severity_when`.

## The list

`rules/ADVISORIES.json` is embedded in the binary. v0.1 does not query
OSV and has no `--online` flag. Querying OSV for advisories that are
not in this list yet is future work.

Ids are `TCA-YYYY-NNNN`, append-only, and never reused. A withdrawn
advisory keeps its id and gains a `withdrawn` date. CI checks the file
the way it checks `rules/REGISTRY`: ids are unique, the document
matches the schema, and an id is not deleted.

The list ships in the free core pack. A critical advisory ships in a
pack patch. Every other advisory ships in the monthly release.

| Id | Package | Affected | Fixed | Advisory severity |
| --- | --- | --- | --- | --- |
| TCA-2026-0001 | pypi `prefab-ui` | >=0.14.0, <0.21.0 | 0.21.0 | critical |
| TCA-2026-0002 | git `https://github.com/alishahid74/kali-gpt` and module `kali_gpt.tools.mcp_server` | commit a608c74e99910232dd208fee99de860458672b82, and the module path `kali_gpt/tools/mcp_server.py` | none | high |
| TCA-2026-0003 | npm `figma-developer-mcp` | <0.6.3 | 0.6.3 | high |
| TCA-2026-0004 | npm `mcp-remote` | >=0.0.5, <0.1.16 | 0.1.16 | critical |
| TCA-2026-0005 | pypi `mcp-server-git` | <2025.9.25 | 2025.9.25 | moderate, reported high |
| TCA-2026-0006 | pypi `mcp-server-git` | <2025.12.18 | 2025.12.18 | moderate, reported high |
| TCA-2026-0007 | pypi `mcp-server-git` | <2025.12.18 | 2025.12.18 | moderate, reported high |
| TCA-2026-0008 | pypi `mcp-server-git` | <2026.1.14 | 2026.1.14 | moderate, reported high |
| TCA-2026-0009 | pypi `awslabs.aws-serverless-mcp-server` | <0.2.1 | 0.2.1 | moderate |
| TCA-2026-0010 | npm `@samanhappy/mcphub` | >=0.9.10, <1.1.8 | 1.1.8 | moderate |
| TCA-2026-0011 | npm `@aborruso/ckan-mcp-server` | <0.4.112 | 0.4.112 | low, reported high |
| TCA-2026-0012 | npm `@bytebase/dbhub` | <0.22.6 | 0.22.6 | moderate, reported high |
| TCA-2026-0013 | npm `@tsparticles/mcp-server` | <4.3.1 | 4.3.1 | high |
| TCA-2026-0014 | npm `@tsparticles/mcp-server` | <4.3.1 | 4.3.1 | high |
| TCA-2026-0015 | npm `@tsparticles/mcp-server` | <4.3.2 | 4.3.2 | moderate |
| TCA-2026-0016 | npm `open` | >=7.2.0, <11.0.0 | 11.0.0 | high |
| TCA-2026-0016 | npm `@modelcontextprotocol/inspector` | >=2.0.0, <2.12.0 | 2.12.0 | high |
| TCA-2026-0016 | npm `opencode-ai` | >=1.0.137, <1.18.33 | 1.18.33 | high |

prefab-ui is a library. It matches only when the argv names it, for
example `--with prefab-ui==0.20.2`. A transitive dependency of another
package is not visible here. `open` is the same kind of match:
TCA-2026-0016 also names `@modelcontextprotocol/inspector` and
`opencode-ai`, and each matches only when the argv names that package.

MCPHub is a self-hosted gateway, but its npm package exposes an executable
and can be launched in a stdio MCP configuration with
`npx @samanhappy/mcphub@1.1.7`; it is therefore in scope. A URL-only
connection to a deployed MCPHub remains out of scope.

The Kali-GPT git fixtures (no ref, `@v3.0.0`, and `@4df42a5`) are
illustrative. The repository URL and the module signature come from the
advisory. The command token after the git URL is a placeholder, not a
verified console entry point. There is no published package to pin.

No Docker advisory is seeded. Image parsing is covered by unit tests.

## False positives

- A private registry or mirror that publishes a different package under
  the same name is still reported. The public name matches, and the
  opposite mistake is worse.
- A local backport that reuses the vulnerable version number is a
  policy exception, keyed by the finding fingerprint.
- A fork that keeps the Kali-GPT module path matches until the advisory
  is withdrawn or gains a fixed version.
- prefab-ui is reported even when the vulnerable feature is not enabled.
  The pinned version is the affected one.
- A server marked disabled is still reported. Turning it back on is a
  one-line edit. TC-CFG-003 uses the same policy.

## False negatives

- Transitive dependencies and lockfiles. `fastmcp[apps]` can pull in
  prefab-ui without naming it.
- An unpinned spec that resolves to an old cached copy. Unpinned specs
  match only when the advisory has no fixed version.
- Wrappers that are not unwrapped: `env`, `busybox`, `$SHELL`, `sh -c`,
  and `$VAR` or `${VERSION}` in the version. Those limits are shared
  with the rest of the pack.
- Digests, local paths, tarballs, and an unknown launcher option. Those
  are not guesses.
- A range that still admits a fixed version, such as `^0.6.0` when
  0.6.3 is fixed.
- A version specifier over 256 bytes or 32 clauses. It is opaque, so a
  long `!=` list cannot make the scan quadratic.
- An advisory that is not in the embedded list yet.
- An argument the sanitizer replaced with `[REDACTED]`. A package spec
  such as `figma-developer-mcp@0.6.2` is not redacted. A spec whose
  version text was replaced with `[REDACTED]` does not match. A git
  URL that still carries userinfo, or the marker `[REDACTED]`, is
  opaque and does not match, so a token is not copied into the finding.
- Session configuration the adapters do not read, such as a one-shot
  `--mcp-config`.

## Examples

Reported, high:

```json
{"mcpServers": {"figma": {"command": "npx", "args": ["-y", "figma-developer-mcp@0.6.2", "--stdio"]}}}
```

Reported, critical:

```json
{"mcpServers": {"remote": {"command": "npx", "args": ["-y", "mcp-remote@0.1.15", "https://example.invalid/sse"]}}}
```

Not reported (the range still admits the fixed 0.6.3):

```json
{"mcpServers": {"figma": {"command": "npx", "args": ["-y", "figma-developer-mcp@^0.6.0"]}}}
```

The finding title names the server, the package, the aliases, and the
highest fixed version, or says that the advisory has no fixed version.
The excerpt is the canonical package URLs and the TCA ids. That excerpt
is part of the fingerprint, so a new advisory id stops an old exception
from covering the finding. The title and the reference list are not
hashed.

## How to fix

Pin the package to the fixed version named in the finding. When the
advisory has no fixed version, remove the server.

## References

- [OSV](https://osv.dev/)
- [NVD](https://nvd.nist.gov/)
- [prefab](https://github.com/PrefectHQ/prefab)
- [kali-gpt](https://github.com/alishahid74/kali-gpt)
