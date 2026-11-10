# Release notes

## v0 (unreleased)

### More secret shapes are redacted, in evidence keys too

JSON and JSONL output carry the evidence key of a finding, which
includes the full command of a hook or setup step, and some secrets
stayed in it. These are now redacted in every format (text, JSON, JSONL,
SARIF, Markdown, annotations): a YAML value that continues on later
lines (a quoted value, a comment, then a more-indented line; a quoted
scalar that closes on a later line; a commented-out key followed by its
value), a netrc line (`machine h login u password X`, also in a
copilot-setup-steps `run:` block), the word after `password`, and `-p X`
in a command that names a user. The sink also decodes the key and
redacts each string in it, instead of the JSON text, which hid the
shapes behind `\n` and `\"`.

Fingerprints change only for an entry whose command carried one of these
shapes. Its key and fingerprint are built from the sanitized command,
which before still held the secret, so the fingerprint depended on it
(under `s1`, rotating it changed the fingerprint). It is now redacted
before it is hashed, so under `s1` the fingerprint no longer depends on
the secret. Every other fingerprint is unchanged: the 81 corpus
seeds (50 benign and 31 malicious) scan to byte-identical JSONL. The
sink itself never changes a fingerprint, since it is computed before
the sink runs. As with the section below, this lands before the first
release, so a baseline keyed
by a fingerprint of one of these entries is recorded once.

### Fingerprints of secret-bearing entries change

Findings on a configuration entry that lost a value to redaction (a
`--token`, a secret `env` value, a bearer token, a URL query, ...) get
new fingerprints. Findings on entries with nothing redacted keep theirs.

Before, the evidence key of such an entry ended in `sig:` plus 8 hex
characters of an unkeyed SHA-256 of the removed values, so a short or
guessable secret could be confirmed by brute force from a published
report. That part is now one of:

- `sig:k1:<16 hex>`: HMAC-SHA256 of the removed values under the
  fingerprint key. The key is the hex text decoded to bytes, so the
  same key in uppercase and lowercase is one key. The same entry with a
  different secret gets a different fingerprint. Identical duplicates
  are told apart only by their ordinal in the file, the same rule s1
  uses. **k1 fingerprints change once in this PR** because earlier
  commits on this branch keyed the HMAC with hex text rather than its
  decoded bytes; nothing is released yet, so this is the safe time to
  normalize it.
- `sig:s1:<field[n],...>#<ordinal>`: used when no key is available
  (the default in CI). No function of the secret is used. A rotated
  secret, or a secret with a different recognizable shape (a
  provider-prefixed token versus a generic one), keeps the fingerprint:
  `field[n]` counts `[REDACTED]` markers left in the final sanitized
  payload, never how many sanitization passes produced them, so two
  secrets that redact to the same shape always get the same key even
  when one of them also happened to match an extra detection pass.
  Entries that are identical after sanitizing are told apart only by
  their ordinal in the file.

The key comes from `TRIPCORD_FINGERPRINT_KEY` or
`~/.tripcord/fingerprint.key`. A local scan creates that file with mode
`0600` on first use, writing it atomically so a concurrent scan never
observes a partial file. A CI scan never creates it. Key material that
exists but is broken — unreadable, corrupt, too short, not hex, an odd
number of hex characters, a symlink, owned by someone else, or wider
than its expected permissions (checked on Unix; Windows relies on
ACLs) — now fails the scan closed with exit 3
and an actionable message, instead of silently falling back to `s1`.
In v0 the key is a file or an environment variable; the OS keychain
arrives with the v1 store.

SARIF and JSON/JSONL output now report which mode produced each
secret-bearing finding's fingerprint, as a `fingerprintMode` property
(SARIF) or field (JSON); see
[fingerprint.md](fingerprint.md#reporting-the-mode). A finding with
nothing redacted omits it, so existing output for those findings is
unchanged.

What to do: re-record any baseline, exception, or alert dismissal keyed
by a fingerprint of a secret-bearing finding — this version changes
those fingerprints three ways (the `sig:` format itself, the s1
shape-leak fix above, and decoded-byte k1 keys), all as part of this
same change, so a second re-record is not needed later for any of
them. Record CI baselines in CI (`s1`, or `k1` if CI sets
`TRIPCORD_FINGERPRINT_KEY`; see "Recommended: share the key in CI"
below). A local `k1` baseline matches CI only when both use the same
key. See
[fingerprint.md](fingerprint.md#secret-discriminator).

**Recommended: share the key in CI.** Set `TRIPCORD_FINGERPRINT_KEY`
from a CI secret (a GitHub Actions repository or organization secret,
for example) so CI fingerprints secret-bearing entries with the same
keyed `k1` discriminator developers get locally, rather than defaulting
to `s1`. See
[fingerprint.md](fingerprint.md#fingerprint-key).

### Hook decisions use custom rules

In v0, `tripcord hook` decides from the policy's `custom` rules on the
hook surface. It does not run the core `TC-CFG-*` pack. With no custom
rules, or with the event's harness left out of `harnesses`, the tool
call is allowed. A custom rule can still call the same CEL detectors
the pack uses (`shell.risks`, `shell.unpinned`, `hook.argv`,
`mcp.packages`, and the rest). See [hook.md](hook.md).

### Action refs before 7ffdcbe

`7ffdcbea10174609eb58284c21bcb94aee4a2a82` is the first commit of this
repository with no tracked symlinks. Its parent still has the 46
fixture links. GitHub's action download fails on in-repo and dangling
symlinks, so a `uses:` ref before `7ffdcbe` cannot be consumed as a
remote composite action. Current `main` has no tracked symlinks.

### Empty or missing `path`

The composite action's `path` input defaults to `.`. Omitting it is
that default, not a failure. Before the scan, the `check-path` step
exits 1 when the value is an empty string, names a path that does not
exist, names something that is not a directory, names an empty
directory, or names a directory `ls` cannot read. That last case is
reported as unreadable, not as empty. `tripcord scan` of a directory
inside a Git repository scans that repository from its git root, so an
empty subdirectory used
to fall through and scan the whole repository. It now fails first. A
non-empty subdirectory still scans the git root; scoping a scan to one
package is an open product question
([#59](https://github.com/vgmartinez/tripcord/issues/59)).

### Reusable workflows and report-only

CI runs the composite action as a remote step. The reusable workflows
`tripcord-pr.yml` and `tripcord-pr-comment.yml` are covered by the
contract test and actionlint, not by an end-to-end run. There is no
report-only mode. `fail-on` accepts `low`, `medium`, `high`, and
`critical`, and a non-zero scan or `pr-context` exit fails the job
after publishing
([#62](https://github.com/vgmartinez/tripcord/issues/62)).

### Leftover embed

When `bootstrap.sh` and `embed.json` are gone and a leftover piece
that only `init --embed` writes is still what this build writes (the
workflow, or a hook that runs `.tripcord/bootstrap.sh hook`), the scan
reports two high [TC-CFG-016](rules/TC-CFG-016.md) findings: the
missing manifest and the missing bootstrap. It does not also report
every harness hook. A leftover guard hook that no longer matches what
init writes reports those differences as further highs.

### Known gaps

- `-p X` is redacted only when the same command also names a user
  (`-u`, `-U`, `-l`, `--user`, `--username`, `--login`, or a `login`
  subcommand). A `-p` with no user flag in the command, such as
  `ssh -p 22` or `mkdir -p`, is left as written.
- `useradd -p HASH` is the same gap: with no user flag, the password
  hash after `-p` is not redacted. It is redacted when a user flag or
  a `login` subcommand is also present (`useradd -u 1000 -p HASH bob`).
- A commented-out credential key (`# token: # note`) treats the next
  line as its value and replaces that line in the published evidence
  with `[REDACTED]`. The finding is still reported; the line is only
  missing from the evidence. A command whose network fetch sits on
  that next line is still a TC-CFG-001 finding, and the evidence shows
  `# token: [REDACTED]` instead of the fetch.
- [TC-CFG-013](rules/TC-CFG-013.md), an AI coding-agent workflow
  triggered by an event a non-collaborator can produce (`issues`,
  `issue_comment`, `discussion`, `discussion_comment`, or
  `pull_request_target`), is documentation-only in v0. Tripcord has no
  detection for it: there is no `rules/TC-CFG-013.yaml`. Coverage is
  meant to come from zizmor's `agentic-actions` audit once it is
  released
  ([zizmor#1655](https://github.com/zizmorcore/zizmor/pull/1655),
  [#41](https://github.com/vgmartinez/tripcord/issues/41)). See
  [Known gaps](rules/README.md#known-gaps) in the rule index.
- Report-only mode for the Action and the reusable workflows is not
  implemented. Publishing SARIF or a pull-request comment without
  failing on findings needs a product decision
  ([#62](https://github.com/vgmartinez/tripcord/issues/62)). Exit 3,
  exit 4, and an invalid `path` would still have to fail.
- Scanning one subdirectory of a monorepo is not implemented. `tripcord
  scan PATH` and the Action's `path` input resolve a path inside a Git
  repository to that repository's root
  ([#59](https://github.com/vgmartinez/tripcord/issues/59)).
