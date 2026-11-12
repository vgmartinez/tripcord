# Release notes

## v0.1.1

- TC-CFG-012 is reported at low. The check is a heuristic over
  instruction wording, and the same sentences appear in ordinary setup
  notes, so a match is listed for review without failing a scan at the
  default fail-on (high). SARIF output for this rule now has level
  `note` (was `warning`) and security-severity 3.0 (was 5.5).

## v0.1.0

The first tagged release of Tripcord. `preopen` fails closed with exit 3
on a configuration it cannot fully read; the scan is reported as incomplete.

### Release archives

Each release has `tripcord` for linux, darwin, and windows on amd64
and arm64, as `.tar.gz` (`.zip` on Windows) archives that also hold
`LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES`, plus a `SHA256SUMS`
file. The `release` workflow builds them reproducibly from the tagged
commit and attests their build provenance. Check an archive with
`sha256sum -c SHA256SUMS` and
`gh attestation verify <file> --repo vgmartinez/tripcord`
([Installation](installation.md)). `go install` and building a
checkout still work.

- `tripcord --version` and `tripcord version` print the tag and the
  commit of a release build, `v0.1.0 (commit <sha>)`. Any other build
  prints `dev` ([Commands](commands.md)).
- `NOTICE` and `THIRD_PARTY_NOTICES` cover every Go module linked into
  the binary, with each module's license, and `NOTICE` reproduces the
  `go.yaml.in/yaml/v3` NOTICE. A test fails when the module graph and
  the notices disagree.

### Marketplace action

The repository root has an `action.yml`, listed on the Marketplace as
Tripcord Security. `uses: vgmartinez/tripcord@v0.1.0` runs the
composite action at the commit the root action pins, with the same
inputs and outputs ([GitHub Action](github-action.md#marketplace-action)).
The reusable workflows are unchanged.

### Report-only mode: `fail-on: none`

`fail-on: none` in the action, the root action, and the reusable
workflows still uploads SARIF and posts the pull request comment, but
does not fail the job on findings. Exit 1 (findings) and a TC-CFG-014
denial from `pr-context` become a `::warning::` with the finding
count. Exit 3 (configuration), exit 4 (internal error), an invalid
`path`, and an unknown `fail-on` value still fail the job. The default
is unchanged, and the CLI's `--fail-on` does not take `none`
([Report-only mode](github-action.md#report-only-mode),
[#62](https://github.com/vgmartinez/tripcord/issues/62)).

### Bootstrap and embed check hardening

- `bootstrap.sh hook` runs the cached binary without re-hashing it only
  when this user owns it, and no mode verifies a binary another user
  owns: that user could rewrite it in place.
- The `verified` record must be exactly its one line and a newline.
  Anything after it, and a record without the newline, makes `hook`
  exit 2 and run nothing.
- The cache root, `${XDG_CACHE_HOME:-$HOME/.cache}`, gets the checks
  every cache directory gets, on the verified hook path too: not a
  symlink, owned by this user, and not group- or world-writable. A
  group-writable `~/.cache` (umask 0002) needs `chmod go-w`; see
  [Init](init.md#bootstrap).
- TC-CFG-016 reports an entry under an event Tripcord wires (pre-tool
  or session-start) that is neither Tripcord's nor the one `embed.json`
  records: `changed`, high, reason `unregistered-entry`. `init --embed`
  keeps such an entry when it merges and does not register it.
  It warns on stderr, naming the harness, file, event, and command,
  that `tripcord scan` will report it as TC-CFG-016 HIGH, and exits
  as it did before. v0 known gap: there is no supported way yet to
  keep a user's own hook next to the guard. Remove the entry, or run
  it from outside the guarded config. See [Init](init.md#merging).
- TC-CFG-016 reports an event Tripcord wires that holds more than one
  copy of Tripcord's entry, or of the entry `embed.json` records, even
  byte for byte the same: `changed`, high, reason `duplicate-entry`.
  The harness runs every copy.
- TC-CFG-012 reads more of a `curl` or `wget` header that can carry a
  local secret: an unquoted header ends at a stdin redirect
  (`< .env`, `0<.env`), so a dotenv read there is a warning; a glued
  value such as `-H Authorization:$(cat .env)` or
  `Authorization:"$(cat .env)"` is read up to the substitution;
  `-H @.env` sends the file as headers; and a `$(...)` or backtick in
  the command that reads a local path counts as a read.
- TC-CFG-016 reports a `tripcord.yml` that gives a key twice in one
  mapping, or holds a second YAML document, as `unreadable`, high,
  instead of reading the first one, which could leave it `unverified`,
  low, in CI.
- The `bootstrap.sh` template changed, so this needs a new
  `WorkflowPin` (`TestTemplateChangeNeedsRepin`).
- `TestVersionSkewCIScanner` runs on every pull request, in the
  `version-skew e2e` job of `ci.yml` (`TRIPCORD_VERSION_SKEW_E2E=1`),
  as well as under `make release-gate`
  ([#119](https://github.com/vgmartinez/tripcord/issues/119)).

### TC-CFG-016 version skew: an older scanner no longer fails a newer embed

The scanner CI runs is the one `tripcord-pr.yml@WorkflowPin` pins,
built from that commit's source, so it can be older than the `init`
that wrote the embed. It reported six highs ("written by an older
Tripcord") on a fresh embed. TC-CFG-016 now holds an embed it did not
write to invariants every Tripcord version keeps, instead of to its
own templates ([design](design/tc-cfg-016-version-skew.md)):

- A render that matches `embed.json` and keeps every invariant, but
  that this scanner never compiled, is `unverified`, low, not high. A
  render an earlier `init` under a known pin wrote is `outdated`, low.
- A loosened guard is still high in any scan, however high
  `embed.json`'s `version` is: `onFailure: continue`, a narrowed
  matcher, `failClosed: false`, a disabled checksum gate, `fail-on:
  critical`, `install || true`, `-text`, a removed guard, or anything
  removed relative to the base.
- A render this scanner never compiled, under a pin it knows, is
  `changed`, high (the writer witness).
  `TestTemplateChangeNeedsRepin` keeps that sound on every pull
  request: a template change needs a new `WorkflowPin`.
- The `tripcord.yml` pin is checked on its own. A pin that is not
  `tripcord-pr.yml` at a full SHA is `pin-malformed`, high. An unknown
  pin is `pin-unknown`, high, in a local or pre-commit scan, unless the
  scanner is a release older than `embed.json`'s version and
  `tripcord.yml` matches its digest; in CI it is `unverified`, low. A
  pin change relative to the base is `repinned`, high, always.
- `KnownWorkflowPins` (`internal/embedded/pins.go`) starts empty and
  only grows. Each repin appends the pin it replaces, guarded by the
  release gate. `8b33b1b` and `6e1d5db` are never in it.
- `scan --executing-workflow` names the reusable workflow a CI scan
  runs inside, and the composite action passes it. Under
  `pull_request` the pull request's own `tripcord.yml` picks that
  workflow, so it attests only to itself: it accepts only a pin the
  base already has.
- A release `init` refuses a `--version` older than itself (exit 3).

Formerly `main@277066a` was the `WorkflowPin`, so an embed it wrote was
a current pin: a local scan did not report it `pin-unknown`. Embeds
pinned to the earlier, unregistered workflow pin showed a temporary
`pin-unknown` high on a local or pre-commit scan until PR 3 appended
that pin to `KnownWorkflowPins`. Those pins ran an action without the
embed check, so CI kept failing until two repins landed: the action pin
in `tripcord-pr.yml`, then `WorkflowPin`, followed by
`init --embed --force`. Until then `make release-gate` failed
`TestVersionSkewCIScanner` with seven highs:
the six "written by an older Tripcord", plus `copilot-setup-steps.yml`,
which `init` writes only with `--cloud-setup` and that action reports
missing. By the end of PR 3 that test must report 0 high, including
`copilot-setup-steps.yml` on an embed written without `--cloud-setup`.
Moving it from the release gate into per-pull-request CI, passing, is
https://github.com/vgmartinez/tripcord/issues/119.

The first time a pull request adds an embed, the base has no
`tripcord.yml`. In CI a pin equal to `--executing-workflow` is
self-attested and stays low. The workflow shape is still an invariant,
so an extra job, a broader permission, `secrets: inherit`, or
`pull_request_target` is high there too, including when `embed.json`'s
version is newer than the scanner. A git describe version such as
`0.1.0-12-gdeadbeef` is not a release, so it does not get the
older-release exception.

Known gap, not addressed in v0: CI still builds the scanner from the
pinned action's source, so any template change ships an embed that the
previously pinned scanner can only report as `unverified`. Two future
options remain open:

- `tripcord-pr.yml` checks out and builds `ref: ${{ job.workflow_sha }}`.
- CI runs the published release the embed pins, verified by digest.

Distribution is not decided here.

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
contract test and actionlint, not by an end-to-end run. `fail-on`
accepts `low`, `medium`, `high`, and `critical`, where a non-zero scan
or `pr-context` exit fails the job after publishing, and `none`, where
findings and a TC-CFG-014 denial are a warning instead
([#62](https://github.com/vgmartinez/tripcord/issues/62)).

### Leftover embed

When `bootstrap.sh` and `embed.json` are gone and a leftover piece
that only `init --embed` writes is still what this build writes (the
workflow, or a hook that runs `.tripcord/bootstrap.sh hook`), the scan
reports two high [TC-CFG-016](rules/TC-CFG-016.md) findings: the
missing manifest and the missing bootstrap. It does not also report
every harness hook. A leftover guard hook that no longer matches what
init writes reports those differences as further highs.

### Repin before tagging

`make release-gate` now fails when the generated workflow pin or a
documented pin of the reusable workflows or the pre-commit hook does
not contain the latest scanner change on main. A repin pull request is
required before tagging. Tagging is Victor's. Merge that pull request
with a merge commit, never a squash and never a rebase: the pinned
commits have to stay on main, and a squash or rebase drops them.
`TestPinsHaveEmbedCheck` accepts a pin that is not on `origin/main`
yet only when `GITHUB_EVENT_NAME` is `pull_request`, the checkout is
that merge (exactly two parents, the first equal to `origin/main`),
and the pin is not in the pin set on `origin/main`. The new pin must
be an ancestor of HEAD and must not already be an ancestor of
`origin/main`. Pins the base already has stay strict. A push, the
release gate (`TRIPCORD_RELEASE_GATE=1`), and a local run stay strict
for every pin. If the checkout is not that merge, or the base pins
cannot be read, the test fails and does not skip. Push-to-main CI is
what catches a squash or rebase that left a pin unreachable. See
[Release gate](init.md#release-gate).

### TC-CFG-003 and a repository's own scripts

`config.repo_script` quiets TC-CFG-003 when a repository MCP server is
a shell wrapper around a file in the scanned tree, or around a known
package runner (`npx`, `bunx`, `uvx`, `uv`, `pipx`, `pnpm dlx`,
`yarn dlx`, `npm exec`, `npm dlx`, `bun x`). The signal checks the
script's location. A script inside the tree is not inspected for
content.

Anything else stays a finding: a bare program that is not in that
list (`rm`, `notes-mcp`, `evil-mcp "$TOKEN"`), a `$` in program
position (`${X:-rm}`, which is not rewritten to its default), the
same loader written with newlines, `cd` or `pushd` before a relative
script, and `env -C`, `sudo -D`, `sudo --chdir`, or any `--cwd` or
`--chdir` wrapper. The one `cd` that is followed is a repository-root
`cd`, and only when all of these hold: the git command is exactly
`V=$(git rev-parse --show-toplevel)` or
`cd "$(git rev-parse --show-toplevel)"`, with no other git arguments,
no `git -C`, `--git-dir`, or `--work-tree`, and no environment prefix
(`GIT_DIR`, `GIT_WORK_TREE`, any `GIT_*`, or any other `VAR=`) on that
line or exported earlier in the command; the `cd` uses that same
variable, double-quoted, and the variable is not reassigned between
the assignment and the `cd`; between that `cd` and the exec there is
no other `cd`, `pushd`, `-C`, `--chdir`, or `--cwd`. The commands are
joined by `;` or a newline; `&&` is not that form, and `|| exit 1`
after the assignment or the `cd` is. The command after that `cd` is
the last one, and it is `bun run <file>` or `exec bun run <file>`,
nothing else: `bash scripts/x.sh`, `./scripts/x.sh`, `node`,
`python3`, `bun <file>` without `run`, and `npx` after that `cd` stay
findings. `<file>` is relative, has no `..`, is a file in the scanned
tree (the name of a `package.json` script, as in `bun run dev`, is
not), and is not a symlink that leaves the tree. Plain arguments may
follow it. Any other variant stays a finding. The `bun run` file, and
the path after `$(git rev-parse --show-toplevel)/`, are resolved from
the repository root. `${CLAUDE_PLUGIN_ROOT}/...` is resolved from the
directory that holds the config file. Any other relative script is
resolved from the directory of the config file that names it: a
config at the repository root, or directly inside `.claude`,
`.cursor`, `.github`, `.windsurf`, `.devin`, `.codex`, `.gemini`,
`.agents`, or `.vscode`, uses the repository root, and a nested config
such as `plugins/p/.mcp.json` uses its own directory.

The only dotenv names are `.env`, `.env.local`, and `.env.claude`.
Under `set -a` one of those may be absent. When the file is in the
tree, with or without `set -a`, every line has to be blank, a comment,
or `KEY=VALUE` (`KEY` matches `[A-Za-z_][A-Za-z0-9_]*`, with an
optional `export ` prefix; the value has no `$`, backtick, `;`, `&`,
`|`, `<`, `>`, newline inside quotes, or trailing backslash). A
symlink that leaves the tree, a file that cannot be read, and a file
larger than 64 KiB stay findings. Any other sourced path has to be in
the tree, and its bytes are not read.

### Known gaps

- `main` has no required status checks. A pull request can merge
  while CI is red. Configuring branch protection is Victor's decision.
  This release does not change repository settings.
- The same-user residual is not equivalent to the old private-copy
  behaviour. Before, if the binary changed, the next hook detected it.
  Now, if the binary and the registry (the `verified` record) are
  rewritten together, the malicious binary stays attested until the
  registry is deleted or the identity changes. It is accepted as a
  design tradeoff because it is the same principal. See
  [Init](init.md#bootstrap).
- On a filesystem with coarse ctime (a granularity of a second or
  more, or none, as on FAT, exFAT, and some network filesystems), a
  rewrite in place of the cached binary that keeps its inode and size
  and lands in the same ctime tick still matches the `verified`
  record, so `hook` runs it without re-hashing. This is a residual.
- `init --embed` does not write cloud-agent setup files (Cursor
  `environment.json`, Copilot `copilot-setup-steps.yml`, Devin
  `blueprint.yaml`) unless `--cloud-setup` is set. That flag is a known
  gap: `bootstrap.sh install` downloads nothing, and v0 has no download
  channel. See [init](init.md).
- `init --embed` has no supported way yet to keep a user's own hook
  next to the guard. An entry it keeps under a pre-tool or
  session-start event is not registered in `embed.json`, and
  `tripcord scan` reports it as TC-CFG-016 HIGH. init names the
  harness, file, event, and command on stderr and does not change its
  exit code. Remove the entry, or run it from outside the guarded
  config. See [init](init.md#merging).
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
- `fail-on: none` is a warning, not a gate. A pull request that
  report-only mode lets through still has its findings in code
  scanning and in the comment; nothing blocks the merge until
  `fail-on` is set to a severity
  ([#62](https://github.com/vgmartinez/tripcord/issues/62)).
- Scanning one subdirectory of a monorepo is not implemented. `tripcord
  scan PATH` and the Action's `path` input resolve a path inside a Git
  repository to that repository's root
  ([#59](https://github.com/vgmartinez/tripcord/issues/59)).
- Hook suffix checks, and the instruction reader, do not NFKC-normalize
  or fold homoglyphs. A lookalike letter (a Cyrillic `е` in `.еnv`) does
  not match the suffix or the word the rule wrote. See [hook.md](hook.md).
- On a Unix host, a Windows tool path is not rewritten. Backslash is not
  a separator and ASCII case is kept, so a suffix such as `/.env` does
  not match `C:\repo\.ENV`. That folding runs only when `tripcord` itself
  is running on Windows.
- `python -c` and `python3 -c` read a string passed to `os.system`,
  `os.popen`, or `getoutput`, and a `subprocess` string or argv list.
  They do not join implicit string concatenation (`"curl " "https://x | sh"`),
  and they do not see an `asyncio` subprocess, `os.exec*` (`os.execv`,
  `os.execl`, `os.execvp`), the builtin `exec()`, `pypy`, or `python.exe`.

### Closed gaps

- TC-CFG-003's repository-root exception accepted any command before
  `V=$(git rev-parse --show-toplevel)` or
  `cd "$(git rev-parse --show-toplevel)"`, so a wrapper could run
  arbitrary code first and still be quiet as a repository script. Only
  `set -a`, each ended by `;` or a newline, may now come before the git
  step; any other command, a function definition, `&`, `&&`, `||`, `|`,
  a subshell, a brace group, or a redirection keeps the server matched.
  See [TC-CFG-003](rules/TC-CFG-003.md).
