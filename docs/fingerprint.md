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
  it. Every sanitizer in `kit` therefore records the raw text it removes
  while an entry is built, walking maps in sorted key order, and
  `kit.Source.Add` appends `sig:` plus `kit.KeyDiscriminator` of that
  whole sequence (8 hex characters of SHA-256). The Claude adapter,
  which keeps some values raw in its payloads, uses
  `kit.Source.EntrySignature`: the digest of its payload as kit
  sanitizes it, and the same discriminator over its own removals and
  kit's. The discriminator is a truncated hash of removed text, never
  the text itself; it is home-normalized in user scope, so it does not
  depend on the scanning machine.

  The discriminator is the first 32 bits of an unsalted SHA-256. It is
  not a secret-safe commitment: anyone holding a candidate secret can
  hash it and compare, and a short or guessable secret (a PIN, a
  dictionary password) can be confirmed by brute force from a report.
  32 bits is enough to keep entries apart within one repository, which
  is all it is for; the chance of two different removals sharing it is
  about one in four billion per pair. There is deliberately no
  per-install salt: the same configuration must produce the same
  fingerprint on every machine and in CI, so a baseline or an
  acceptance recorded on one machine matches the finding on another. A
  salt would make every fingerprint machine-specific. Treat a report
  that carries `sig:` keys as you would the configuration it came from.

Credential values, secret values, and network URLs are never inputs,
other than through the truncated-hash discriminator described above.
Evidence excerpts must already be redacted; this package does not search
them for secrets.

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
  white space collapsed, ends dropped).
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
