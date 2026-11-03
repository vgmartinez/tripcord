# Finding fingerprints

A finding fingerprint is stable across Tripcord versions. The same rule,
location, and evidence always hash to the same `tcf_` id. Golden tests in
`internal/model/fingerprint_test.go` fail if this algorithm changes.

Do not change the algorithm in place. A new digest needs a new `v` and
new golden tests.

## Input

The digest covers:

- the rule id
- the normalized location: harness, and, when set, session and path;
  scope is always present (an unset scope defaults to `repo`)
- the normalized evidence: for each item, the excerpt and/or the cited
  config id and, when set, its key

Two things that might look like identity are deliberately **not**
hashed, because each one can change without the underlying finding
changing:

- **`location.line`.** A line number is where the finding currently
  renders, not what it identifies. Adding a line above a hook, or
  reformatting the file, shifts every line number below it; none of
  that is a new finding. `line` still lives on `Finding.Location` for
  display and in the JSON Schema; it is simply excluded from the hash.
- **`evidence[].event`.** This is a record id, not content. `Event.id`
  is a ULID minted at ingest time, so the same occurrence re-derived
  from a reimported transcript, or from a hook event deduped against
  its transcript copy, mints a different ULID each time; hashing it
  would fragment one real occurrence into several fingerprints.

Two things that do look like metadata, but **are** hashed:

- **`location.scope`.** Before managed scope required an absolute path
  (see "Path scope" below), a managed-scope path had no required shape
  and could collide, as plain text, with a repo- or user-scope path
  that happened to use the same characters. Hashing scope removes any
  reliance on path shape alone to tell the three apart, and it keeps
  the rule simple: scope is always in the preimage, not only when a
  path happens to be ambiguous.
- **`evidence[].config`.** Unlike `event`, a config id
  (`ConfigItem.ID()`, the `id` field) is already content-stable:
  harness, scope, and normalized path, with no `sha256`, so nothing
  mints a new one per scan the way a ULID does. Leaving it unhashed let
  two findings that cite different config files collapse onto the same
  fingerprint whenever `Location.Path` was unset and the evidence
  carried no excerpt (the preimage reduced to just rule, harness, and
  an empty evidence array). Hashing the cited config id closes that
  collision without reopening the problem excluding `event` solves.
  `config.key`, when set, is hashed too. It is a content-derived
  sub-identifier for one entry inside the file — an MCP server name, a
  task label, or matcher+command for a hook — never a positional index.
  Two matching entries in the same file therefore get distinct
  fingerprints, and reordering those entries does not change them. See
  "Repeated occurrences" below for why this does not reintroduce
  reimport instability.

  The adapters under `internal/adapters/kit` (and the Claude adapter)
  enforce the "two matching entries get distinct fingerprints" half of
  that promise by construction: `kit.Source.Add` always appends a short
  digest of the entry's full sanitized payload to the key
  (`kit.PayloadDigest`), in addition to whatever human-readable fields
  the adapter already put there (a step's `uses`, a hook's first action
  field, ...). Without it, two entries that matched on those few fields
  but differed elsewhere — a second `uses: actions/github-script@v7`
  step with a different `with.script`, say — would collide on the same
  key and so the same fingerprint, and a tool that merges findings by
  fingerprint (GitHub's SARIF alert de-duplication, for example) could
  let a benign entry hide a hostile one. The digest is computed before a
  file-level, scan-dependent fact such as Codex's `project_trust` is
  folded into the payload, so it never makes a repository fingerprint
  depend on which scopes this scan happened to read.

  The digest is over the sanitized payload, so two entries that differ
  only in a value redaction replaced with `[REDACTED]` (a `--token` in a
  hook's `powershell` field, an `API_TOKEN` env value, ...) would share
  it. Every sanitizer in `kit` therefore records each raw value it
  removes while an entry is built, with the top-level payload field it
  came from, walking maps in sorted key order, and `kit.Source.Add`
  appends a `sig:` discriminator over that sequence; see "Secret
  discriminator" below. The Claude adapter, which keeps some values raw
  in its payloads, uses `kit.Source.EntryKey`: the digest of its payload
  as kit sanitizes it, and the same discriminator over its own removals
  (tagged with their field) and kit's.

Credential values, secret values, and network URLs are never inputs,
other than through the keyed k1 discriminator described below. Evidence
excerpts must already be redacted; this package does not search them for
secrets.

## Secret discriminator

An entry that lost nothing to redaction has no secret discriminator,
and its key and fingerprint are the same in both modes (see "Q2:
findings with nothing redacted" below). An entry that lost one or more
values gets one last key part. Its text names the mode, so a k1 key and
an s1 key for the same entry never collide, and a baseline recorded in
one mode never matches a secret-bearing finding from the other. The
public fingerprint format stays `tcf_` plus 16 hex characters. The mode
is visible in the evidence key, not in the fingerprint; see "Reporting
the mode" below for where it is surfaced instead.

| Mode | When | Key part | Different secret | Rotated secret | Identical duplicates |
| --- | --- | --- | --- | --- | --- |
| `k1` | A fingerprint key is set | `sig:k1:` + the first 16 hex characters of HMAC-SHA256(key, `tripcord.sig.k1` NUL JSON(removed values)) | Different fingerprint | Different fingerprint | Told apart only by the ordinal |
| `s1` | No key (the default in CI) | `sig:s1:` + `field[n],...` + `#` + ordinal | Same fingerprint | Same fingerprint | Told apart only by the ordinal |

In s1, `field[n]` is the top-level field of the final sanitized payload
(`args`, `env`, `command`, `headers`, `content`, ...; passed through the
output redactor, and memoized per field name since the same small set of
names recurs across every entry) under which `[REDACTED]` still appears,
and `n` counts earlier occurrences within that field, walking a map in
sorted key order and an array by index. It counts the *markers left in
the payload*, never how many sanitization passes produced them: a
provider-shaped secret (`ghp_`, `sk-`, `xoxb`, `AKIA`, a JWT, ...) and a
generic one that redact to the same shape get the same `field[n]` list,
because some adapters' redaction pipelines run more than one pass over
the same value and a provider-recognizable shape can match a pass a
generic one does not, even though both passes leave exactly one
`[REDACTED]` marker in the payload. Counting passes instead of markers
would have let s1 leak which kind of credential a value looked like, and
let rotating a secret to a different recognizable shape change the
fingerprint even though nothing about the finding changed; neither is
acceptable for a mode whose whole purpose is to never depend on the
secret's content. `internal/adapters/conformance` and the Claude adapter
each test this directly: the same position gets the same discriminator
across 13 secret shapes (a generic string and twelve provider-shaped
ones) and, independently, every adapter and harness.

The ordinal — `#` plus a number, present in both modes — counts earlier
entries of the same file (harness, scope, path, and kind) whose key up
to and including the `sig:k1:`/`sig:s1:` part was identical, in the
order the file lists them. It is the same rule in both modes so k1 and
s1 behave identically here: two entries that are identical after
sanitizing get `#0`, `#1`, ... in file order, so reordering such
duplicates swaps their fingerprints, whether or not a key is set.

No hash or other function of a removed value is used in s1. s1 therefore
keeps a baseline stable when a secret is rotated, which is what a
baseline wants.

A payload can show `sig:s1:#0` — an ordinal with no `field[n]` part at
all — when every value a sanitizer removed from the entry was deleted
outright rather than replaced with a marker: `kit.StripURLSecrets`
removes a URL's userinfo, query, and fragment rather than leaving
`[REDACTED]` in their place, so an entry whose only redaction was that
kind of URL component has a `Removal` (feeding k1) but no `[REDACTED]`
marker anywhere in the final payload (feeding s1's scan). Both modes
still produce a key — s1's structural part is simply empty — so this
entry is never confused with one that removed nothing at all; it keeps
a secret discriminator, just with no field list.

In k1 the HMAC is over the removed values only, in removal order, so the
same server with a different secret gets a different fingerprint, and
the key never has to leave the machine or CI secret store for that to
hold. The same key text gives the same fingerprints everywhere, so a
team that shares one key (for example as a CI secret and in each
developer's key file) gets matching fingerprints locally and in CI.

Neither mode depends on the home directory: removed values are
home-normalized in user scope before they are recorded, and the key file
location only decides which key is used.

### Local k1 vs CI s1

Without a shared key, a local scan (k1 with a per-machine key) and a CI
scan (s1, the default when `TRIPCORD_FINGERPRINT_KEY` is unset there)
will not match on secret-bearing entries: different modes produce
different `sig:` text by design, so a finding whose evidence carries a
discriminator gets a different fingerprint in each. This is accepted and
documented, not a bug to work around; sharing
`TRIPCORD_FINGERPRINT_KEY` as a CI secret (see "Fingerprint key" above)
is how a team gets matching fingerprints everywhere instead.

Two consequences worth calling out:

- A finding whose evidence carries **no** discriminator at all — nothing
  was redacted (Q2 below) — has the same fingerprint in every mode, so
  it is unaffected by this gap. Only secret-bearing findings diverge.
- Comparing fingerprints computed in different modes without realizing
  it — for example, a baseline recorded locally in k1 checked against a
  CI run in s1 — makes every secret-bearing finding look new, even one
  that was already triaged. v0 has no baseline or suppression feature
  built on top of fingerprints yet (see "Baselines and the fingerprint
  mode" below), so `tripcord scan` cannot warn about this today; treat a
  mismatched mode as a known limitation until that lands, and prefer a
  shared key over relying on fingerprints to compare across modes.

### Reporting the mode

The fingerprint itself never encodes which mode produced it — k1 and s1
both still render as `tcf_` plus 16 hex characters — but every finding's
evidence already carries the mode as the `sig:k1:`/`sig:s1:` prefix in
`evidence[].config.key` (see "Secret discriminator" above), and the
rendered output surfaces it explicitly too, as `fingerprintMode`:

- **SARIF**: each `result.properties.tripcord` object gets a
  `fingerprintMode` string property (`"k1"` or `"s1"`), alongside the
  existing `scope`/`path` properties. It is present whenever any of the
  finding's evidence carries a discriminator, even for a finding with no
  `location` to report `scope`/`path` for.
- **JSON / JSON Lines**: each finding object gets a top-level
  `"fingerprintMode"` string field. `tripcord.finding/v1` allows
  additional properties, so this does not require a schema version
  bump.

In both formats, a finding whose evidence carries no discriminator (Q2)
omits `fingerprintMode` entirely rather than emitting an empty string,
so existing consumers that do not know about this field see byte-for-byte
unchanged output for those findings. Text, Markdown, and GitHub Actions
output do not currently surface the mode.

### Baselines and the fingerprint mode

v0 has no baseline comparison or suppression feature keyed by
fingerprint; `internal/policy`'s exception mechanism suppresses a rule
by a hash of the whole config file's content, which is unrelated to
per-finding fingerprints or their mode.

**TODO (deferred to the baselines PR):** when a baseline feature is
built, it should record each stored fingerprint's `fingerprintMode`
alongside it and warn when a fingerprint being compared against the
baseline carries a different mode than the one it was recorded with —
considering only fingerprints whose evidence carries a `sig:` (Q2: a
mode-independent finding has nothing to warn about, by construction).
See "Questions for Researcher" in the pull request that introduced this
section for the open question tracking that work.

### Design decisions, for quick reference

A few choices here were open questions during review; each is already
reflected in the behavior described above, cross-referenced here for
anyone looking them up by number:

- **Findings with nothing redacted** (no `sig:` at all) are deliberately
  mode-independent: the same fingerprint in k1 and s1, since there is no
  secret to discriminate on either way. See "Reporting the mode" above
  and `model.FingerprintMode`'s doc comment.
- **Key file permissions** are enforced whenever the file is read, not
  only when it is created; see "Fail-closed vs s1 fallback" above.
- **Minimum key length** stays 16 bytes (`MinKeyBytes`), expressed as 32
  hex characters once the hex-format requirement is applied. A freshly
  created key file always gets 32 random bytes (64 hex characters), and
  32 bytes (`openssl rand -hex 32`) is what this document recommends for
  a hand-written key too.
- **Key format is hex-only**, for both `TRIPCORD_FINGERPRINT_KEY` and a
  key file, and the length must be even. The HMAC key is those
  characters decoded to bytes, not the hex text itself, so `AB` and
  `ab` are the same key and produce the same fingerprints. An odd
  number of hex characters cannot be decoded and the scan exits 3. A
  key file additionally has an exact-length rule a human-set env var
  does not; see "Fingerprint key" above. **k1 fingerprints change once
  in this PR** because older commits on this branch keyed the HMAC with
  the hex text; nothing is released yet, so this is the one safe point
  to normalize it.
- **s1 granularity** is top-level payload field plus index
  (`field[n]`), not a deeper structural path into nested values; see
  "Secret discriminator" above.
- **`tripcord init` does not create the key.** `tripcord scan` keeps
  creating it on first use outside CI.
- **A redacted value recorded more than once for the same occurrence**
  (for example, a hook's generic header-processing path and its
  header-specific path both recording the same removed value) no longer
  inflates the s1 discriminator: counting `[REDACTED]` markers left in
  the final payload, rather than how many sanitization passes fired,
  fixes this by construction (see "Secret discriminator" above). This
  already changes some fingerprints once, in this PR; see
  `docs/release-notes.md`.

### Fingerprint key

`tripcord scan` resolves the key once, in this order:

1. `TRIPCORD_FINGERPRINT_KEY`, when set and non-empty. Surrounding white
   space is trimmed. The remaining text must be a hex string (`0-9`,
   `a-f`, `A-F`) of at least 32 characters (16 bytes) and an even
   number of characters, or the scan exits 3. The HMAC key is that text
   decoded to bytes, so uppercase and lowercase are the same key. An
   odd length (33 characters, for example) cannot be decoded and is
   rejected rather than truncated. Example: `openssl rand -hex 32` (32
   bytes is also what a generated key file holds; see point 3).
2. `~/.tripcord/fingerprint.key`, when it exists. It holds the key text
   with the same trimming, hex alphabet, and decoded-bytes rule, but a
   stricter length rule: a key file's content must be exactly 64 hex
   characters, optionally followed by one trailing newline — exactly
   what point 3 writes. Nothing else legitimately writes this file, so
   any other length or any non-hex character means the file is
   truncated or corrupted, and the scan exits 3 rather than silently
   using it as a different, but still "valid", key. Uppercase hex of
   that length is accepted and matches the same key in lowercase.
3. Otherwise, outside CI, a new key file: 32 random bytes, hex-encoded,
   written atomically (see "Concurrent creation" below) with mode
   `0600` in a `0700` `~/.tripcord` directory. In CI (see "CI
   detection" below) the file is never created and the scan runs in s1,
   printing a note on stderr (see "Fail-closed vs s1 fallback" below).

**In CI, set `TRIPCORD_FINGERPRINT_KEY` from a secret** (a GitHub
Actions repository or organization secret, for example) rather than
relying on s1 by default. This gives CI the same k1 keyed discriminator
developers get locally, so a baseline built in CI and one built on a
developer's machine agree on secret-bearing findings too, as long as
both sides have the same key text. Without a shared key, local k1 and CI
s1 fingerprints for a secret-bearing entry will not match; see "Local k1
vs CI s1" below. Never put the key itself in a workflow file, a log
statement, or a committed secret-scanning allowlist; a GitHub Actions
secret is read into the environment only for the job that declares it.

No entropy check is performed on the key text beyond the hex-format and
minimum-length checks above (64 repetitions of the same hex digit would
pass): a short, low-entropy key weakens the keyed discriminator's
guarantee that a different secret produces a different k1 fingerprint.
Generate the key with a CSPRNG (`openssl rand -hex 32`, or just let
`tripcord scan` create `~/.tripcord/fingerprint.key` for you) rather
than typing one by hand.

#### Fail-closed vs s1 fallback

`tripcord scan` only ever falls back to s1 silently-by-design when there
is **no key source at all**: neither `TRIPCORD_FINGERPRINT_KEY` nor an
existing `~/.tripcord/fingerprint.key`, and either CI is detected (see
below) or a new key file could not be generated or created for an
environmental reason (no home directory, a read-only home, a full disk,
...). The scan continues in s1 and says so on stderr; nothing here is
fatal. In CI specifically, the note is exactly `CI detected:
fingerprint key not created, using s1` — that sentence alone, printed
once per scan after the `tripcord scan:` prefix, not wrapped in the
"fingerprint key file is unavailable" wording the other s1 fallbacks
use. A log can be grepped for it.

Once key material exists, the scan never silently changes fingerprint
mode. Any of the following make the scan **exit 3** with an actionable
message instead of falling back to s1:

- `~/.tripcord/fingerprint.key` exists but cannot be read, is not a
  regular file (for example a directory), or is a symlink (including a
  broken one, which gets its own "broken symlink" message).
- `~/.tripcord` exists but is not a directory, or is itself a symlink.
- The key file's content is not exactly 64 hex characters (optionally
  followed by one newline), is longer than the 4096-byte read cap, or
  otherwise fails `New`'s validation (the same check
  `TRIPCORD_FINGERPRINT_KEY` gets, less the exact-length rule; see
  "Fingerprint key" above): not hex (`0-9`, `a-f`, `A-F`), shorter than
  32 hex characters, or an odd number of hex characters. This also
  catches a corrupted or truncated key file — 40 random bytes, or the
  first half of a real key — that previously passed as a different,
  silently-accepted key instead of failing the scan closed.
- On Unix, `~/.tripcord` is owned by someone other than the current
  user, or is writable by group or other (mode `&0o022 != 0`); the key
  file is owned by someone other than the current user, or is readable
  or writable by group or other at all (mode `&0o077 != 0`, so only
  `0600` and narrower are accepted). A directory or file owned by uid 0
  gets its own message naming the likely cause and the fix: running
  `sudo tripcord scan` once with `HOME` preserved (macOS's default, and
  some Linux configurations) creates `~/.tripcord` as root, and every
  later unprivileged run then fails this check until someone runs
  `sudo chown -R $USER ~/.tripcord`.

None of these messages name the home directory; they refer to
`~/.tripcord` and `~/.tripcord/fingerprint.key` literally, the same way
this document does. The key's bytes are never printed either: no output
format, diagnostic, error message, or log carries it, and Go's
formatting of the key type prints a fixed placeholder (see
`fpkey.Key.Format`/`String`/`GoString`/`MarshalJSON`). In v0 the key is
a file or an environment variable. The OS keychain arrives with the v1
store. `tripcord init` does not create the key file; `tripcord scan`
creates it on first use outside CI as described above.

**Windows** reports every file's mode as a fixed `0666`/`0777` rather
than real Unix-style permissions, so the permission and ownership checks
above are skipped there entirely (`checkDirSecurity`/`checkFileSecurity`
are no-ops on Windows). Protecting `%USERPROFILE%\.tripcord\fingerprint.key`
on Windows relies on NTFS ACLs — the file inherits whatever access its
containing directory grants — rather than on anything `tripcord` checks
itself. The symlink and not-a-regular-file checks still apply on
Windows.

#### CI detection

A key file is only ever created outside CI. CI is detected from any of
these environment variables being set to anything other than empty,
`"0"`, or `"false"`: `CI`, `GITHUB_ACTIONS`, `JENKINS_URL`, `TF_BUILD`
(Azure Pipelines), `CODEBUILD_BUILD_ID` (AWS CodeBuild),
`TEAMCITY_VERSION`, `BUILDKITE`, `GITLAB_CI`, `CIRCLECI`. Running on an
unrecognized CI system without one of these set behaves like a
non-CI environment: `tripcord scan` will try to create a key file there
on first use, so set `TRIPCORD_FINGERPRINT_KEY` explicitly in that case
instead of relying on auto-detection.

#### Concurrent creation

Key file creation is atomic: `tripcord scan` writes the random key to a
temporary file (`.fingerprint.key.*.tmp`) in `~/.tripcord`, flushes it
to disk, and publishes it with a hard link to `fingerprint.key`, which
atomically fails rather than truncating or racing if the destination
already exists. A process that loses that race reads the file the
winner just finished instead, so every concurrent `tripcord scan`
invocation against the same home directory agrees on one key, and none
ever observes a partially written file. After the link, the directory
itself is fsynced too (best-effort; a failure here does not undo the
key file the link already published), so the new directory entry is not
left to a crash-dependent filesystem ordering.

A process killed (`SIGKILL`, a hard crash) between creating its
temporary file and removing it again leaves that file behind forever
otherwise. Every `tripcord scan` that finds `~/.tripcord` already
there, not only the path that goes on to create a new key, sweeps any
`.fingerprint.key.*.tmp` file older than a few minutes, or more than a
few minutes in the future. A small future skew is left alone: it can
come from another process's live write, or an NFS/SMB clock
difference. The sweep reads the directory and matches that pattern
against each name. It does not glob the path, so a home directory whose
own name contains `*`, `?`, or `[` cannot make the sweep touch a sibling
directory or silently match nothing. Only a regular file is removed.

## Canonical JSON

UTF-8 JSON, no extra whitespace. Object keys stay in the order below.
The encoder is `encoding/json` with HTML escaping disabled, so `&`, `<`,
and `>` stay literal. The encoder's trailing newline is removed.

```text
{"v":1,"rule":"<rule id>","location":{...},"evidence":[...]}
```

`v` is the integer 1.

### Rule id

The rule id bytes, unchanged. The id must be non-empty. Spaces are
significant. There is no case folding.

### Location

Keys, in this order:

| Key | Rule |
| --- | --- |
| `harness` | Required. Trim with `strings.TrimSpace`. No case folding. Must be a known harness or surface. |
| `session` | `strings.TrimSpace`. Omitted when empty. Internal spaces stay. |
| `scope` | Always present. An empty `location.Scope` becomes `"repo"`; any other value must be a known `Scope` (`repo`, `user`, `managed`), or `Fingerprint` errors. |
| `path` | `normalizeScopedPath(location.Scope, location.Path)` (see "Path scope" below). Omitted when `location.Path` is empty. |

`location.line` is never part of the hashed document; see "Input" above.

### Path scope

`internal/model/path.go`'s `normalizeScopedPath` normalizes a path and
checks its shape against the config scope (`repo`, `user`, or
`managed`) it belongs to. `ConfigItem.ID` and `Fingerprint`'s location
path both call it, so a path is validated the same way wherever it
names a config entry. An empty scope defaults to repo scope.

Normalization, in order: trim space; Unicode NFC (a decomposed and a
composed spelling of the same path are one path; ASCII is unchanged);
replace `\` with `/`; reject any `..` segment, in every scope, before
`path.Clean` (so `a/../b` is rejected rather than collapsed to `b`,
matching the finding schema); `path.Clean`, which removes `.` segments
(`a/./b` becomes `a/b`), collapses repeated `/`, and strips a trailing
`/` other than the root; then, if the result is a Windows drive path,
case-fold it (see below).

Windows paths are case-insensitive. A Windows drive path — one matching
`^[a-zA-Z]:($|/)` once `\` has become `/`, so `C:`, `C:/...`, or
`C:\...` — is absolute in every scope. It is lowercased in full and
then has just its drive letter uppercased, so `C:\ProgramData\x` and
`c:/programdata/x` both normalize to the same `C:/programdata/x`. This
project does not fold case anywhere else; a POSIX absolute path such as
`/etc/Cursor/Hooks.json` is left exactly as given.

A colon that is not that drive prefix is accepted. `a:b.json` is a
repo-relative path, and so is the same shape `C:foo` (a Windows
drive-relative path with no separator). That is a known limitation:
those two spellings cannot be told apart, so neither is rejected.

Scope rules, checked after that normalization:

| Scope | Rule | Rejected example |
| --- | --- | --- |
| `repo` (default) | Must be repo-relative: no leading `/`, no leading `~`, no Windows drive letter, and no `..` segment. | `/work/repo/.vscode/tasks.json`, `C:/Users/runner/x.json`, `C:\Users\x`, `\\server\share\hooks.json`, `~/.claude/settings.json`, `a/../b`, `../../etc/passwd` |
| `user` | Must be rooted at the user's home: exactly `~`, or starting with `~/`. A `..` segment is rejected. | `/home/dev/.claude/settings.json`, `.claude/settings.json`, `a/../b`, `~/../../x` |
| `managed` | Must be absolute: a leading `/`, or a Windows drive letter. A `..` segment is rejected. | `cursor/hooks.json`, `~/cursor/hooks.json`, `a/../b`, `../etc/cursor/hooks.json` |

Requiring an absolute shape for managed scope, on top of the
repo-relative and `~/`-rooted shapes for the other two, keeps the three
scopes' path shapes mutually exclusive: the same literal path text can
no longer name both a repo-scope and a managed-scope entry.

A path that violates its scope's rule is a `Fingerprint` error (and a
`ConfigItem.Validate` / `ConfigItem.ID` error): a CI-runner-specific
absolute path, a Windows drive path under repo scope, a path that
climbs out of the repo with `..`, or a bare relative path under managed
scope, does not name a stable config entry, so it must not reach the
hash at all.

### Evidence

An array of items built from each `Evidence`'s non-empty normalized
`config` and `excerpt`:

- `excerpt`: `strings.Fields`-joined with a single `U+0020` (Unicode
  white space collapsed, ends dropped). A TC-CFG-023 finding
  (`evidence: advisory`) puts the canonical package URLs and the
  matched TCA ids in that excerpt, so a new advisory id changes the
  fingerprint and an exception that named the old fingerprint stops
  covering the finding. The finding title and its reference list are
  not hashed. Alias, summary, and range edits that do not change the
  matched TCA ids leave the fingerprint alone.
- `config`: an object, omitted when `Evidence.Config` is absent. `id`
  is `strings.TrimSpace` of `Config.ID`. `key` is `strings.TrimSpace` of
  `Config.Key` and is omitted when that is empty. The object itself is
  omitted when both normalize to empty.

An item is dropped only when the excerpt, the config id, and the key
all normalize to empty — not when just the excerpt does, since a config
citation without an excerpt is valid and common (see "Input" above).
`Evidence.Event` is never part of an item. Items are sorted by
`(config.id, config.key, excerpt)` as raw strings (byte order), with a
missing config sorting as empty id and empty key, for a deterministic
order. Identical items are then dropped, so N repeats of the same
normalized excerpt and config citation produce the same preimage as
one. The array is `[]` when nothing remains,
never null. Because the sort key is the content-derived `key` and not
the entry's position in the file, listing the same entries in a
different order produces the same preimage.

## Digest

SHA-256 over the canonical UTF-8 bytes. Lowercase hex. The fingerprint is
`tcf_` plus the first 16 hex characters, and no other length.
`Finding.Validate` and `tripcord.finding/v1` both require
`^tcf_[0-9a-f]{16}$`. `Fingerprint` encodes the first 8 bytes of the
digest, which is exactly those 16 digits.

`Finding.Validate` recomputes `Fingerprint` and requires the stored
value to match. That is possible because every preimage input is on the
finding: the rule, the location (harness, session, scope, and path),
and each evidence excerpt and config id/key. `location.line` and
`evidence[].event` are also on the document, and they are not inputs,
so omitting them from the hash does not leave a gap that Validate would
have to fill from somewhere else.

`location.path` must already be `normalizeScopedPath`'s result, the
same rule a config id's path follows. `a/./b`, `./x`, and `a//b` fail
Validate. `Fingerprint` still canonicalizes those spellings, so hashing
`a/./b` produces the digest of `a/b`. `a:b.json` is already canonical
and is accepted; see "Path scope" above.

## Config item ids

`ConfigItem.ID()` is a separate, non-cryptographic id used by
`Evidence.Config.ID`: `"<harness>:<scope>:<path>"`, where `path` is
`normalizeScopedPath(scope, path)`. It excludes `sha256` on purpose, so
the same config file (for example, `.claude/settings.json` in the
repo) keeps the same id across edits to its content. Unlike
`Evidence.Event`, it IS part of the fingerprint preimage; see "Input"
above for why that is safe. `Finding.Validate` parses
`Evidence.Config.ID` back into those three parts and checks each one:
a known harness, a known scope, and a path that is already
`normalizeScopedPath`'s result for that scope. An id that is not that
shape, such as `/abs/../junk`, is rejected.

`Evidence.Config.Key` is not part of that id. The id names the file.
The key names one entry inside it, derived from the entry's content
(an MCP server name, a task label, or matcher+command for a hook),
never from the entry's index. It is optional: a citation of the file
as a whole leaves it unset. When set, it is part of the preimage.

## Repeated occurrences

Because occurrence-identifying fields (the event id) are excluded, a
command that recurs across a session — the same shell command run
twice, or a hook that fires on every matching tool call — produces
evidence with the same normalized excerpt both times, so those
repeated occurrences hash to the same fingerprint rather than minting a
new one per repetition. Identical items are also removed from the
preimage, so listing that command N times produces the same canonical
document as listing it once. A store can dedup on that fingerprint, both
within one scan and across a reimport of the same transcript.

This holds for a config citation too, as long as the cited config id,
key, and excerpt are themselves unchanged: a `ConfigItem.ID()` does not
depend on `sha256`, so editing the file's body without moving it does
not mint a new fingerprint for a finding that already pointed at it by
id and key. Pointing at a different config file, or at a different key
inside the same file, does change the fingerprint (see the examples
below). Reordering the entries does not, because the preimage sorts by
key rather than by position.

## Examples

Rule `TC-SEC-018`, harness `claude`, session `00893aaf-19fa-41d2`, evidence
excerpt `cat /proc/$PPID/environ` (event id omitted from the hash):

```json
{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2","scope":"repo"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"}]}
```

Fingerprint: `tcf_c761c03b24e7b179`

`internal/model/testdata/finding.json` stores this value.

Rule `TC-CFG-002`, harness `vscode`, repo-scope path `.vscode/tasks.json`
(a `line` of 12, if set on `Finding.Location`, has no effect on this
digest):

```json
{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","scope":"repo","path":".vscode/tasks.json"},"evidence":[{"excerpt":"a && b < c"},{"excerpt":"runOn: folderOpen"}]}
```

Fingerprint: `tcf_591bc1431fb15369`

Rule `TC-CFG-001`, harness `generic`, no evidence:

```json
{"v":1,"rule":"TC-CFG-001","location":{"harness":"generic","scope":"repo"},"evidence":[]}
```

Fingerprint: `tcf_0877dad3c1549226`

Rule `TC-CFG-007`, harness `claude`, user-scope path
`~/.claude/settings.json`:

```json
{"v":1,"rule":"TC-CFG-007","location":{"harness":"claude","scope":"user","path":"~/.claude/settings.json"},"evidence":[{"excerpt":"hooks: SessionStart -> curl | bash"}]}
```

Fingerprint: `tcf_be9d29a5dd7a25fd`

Rule `TC-CFG-016`, harness `cursor`, managed-scope path
`/etc/cursor/hooks.json`, no evidence:

```json
{"v":1,"rule":"TC-CFG-016","location":{"harness":"cursor","scope":"managed","path":"/etc/cursor/hooks.json"},"evidence":[]}
```

Fingerprint: `tcf_87e0e591cef79388`

Rule `TC-CFG-020`, harness `cursor`, managed-scope path, no evidence.
`C:\ProgramData\cursor\hooks.json` and `c:/programdata/cursor/hooks.json`
both normalize to `C:/programdata/cursor/hooks.json` and hash to the
same value:

```json
{"v":1,"rule":"TC-CFG-020","location":{"harness":"cursor","scope":"managed","path":"C:/programdata/cursor/hooks.json"},"evidence":[]}
```

Fingerprint: `tcf_fbae6525ff920e63`

Two findings for rule `TC-CFG-003`, harness `claude`, each citing a
different config file with no excerpt and no `location.path`. The cited
config id is now part of the hash, so these do not collide:

```json
{"v":1,"rule":"TC-CFG-003","location":{"harness":"claude","scope":"repo"},"evidence":[{"config":{"id":"claude:repo:.claude/settings.json"}}]}
```

Fingerprint: `tcf_301e4605a5ed0534`

```json
{"v":1,"rule":"TC-CFG-003","location":{"harness":"claude","scope":"repo"},"evidence":[{"config":{"id":"claude:repo:other/settings.json"}}]}
```

Fingerprint: `tcf_27c7eaa6b414761d`

Two findings for the same rule and the same config file, distinguished
only by `key`. `filesystem` is an MCP server name; `PreToolUse|curl` is
matcher+command for a hook entry. Neither key is an index, so the
fingerprints stay put if those entries trade places in the file:

```json
{"v":1,"rule":"TC-CFG-003","location":{"harness":"claude","scope":"repo"},"evidence":[{"config":{"id":"claude:repo:.claude/settings.json","key":"filesystem"}}]}
```

Fingerprint: `tcf_30f590ab0e43e08e`

```json
{"v":1,"rule":"TC-CFG-003","location":{"harness":"claude","scope":"repo"},"evidence":[{"config":{"id":"claude:repo:.claude/settings.json","key":"PreToolUse|curl"}}]}
```

Fingerprint: `tcf_fd9d1e862f831120`

One finding that cites both entries. Listing `filesystem` first or
`PreToolUse|curl` first produces this same document, because items sort
by `(id, key, excerpt)`:

```json
{"v":1,"rule":"TC-CFG-003","location":{"harness":"claude","scope":"repo"},"evidence":[{"config":{"id":"claude:repo:.claude/settings.json","key":"PreToolUse|curl"}},{"config":{"id":"claude:repo:.claude/settings.json","key":"filesystem"}}]}
```

Fingerprint: `tcf_b88dd3cb84d5dde8`

A repo-scope path such as `/home/runner/work/acme/acme/.vscode/tasks.json`
(an absolute, CI-runner-specific path), or one containing a `..`
segment, is rejected by `Fingerprint` rather than hashed as-is; see
"Path scope" above.
