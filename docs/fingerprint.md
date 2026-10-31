# Finding fingerprints

A finding fingerprint is stable across Tripcord versions. The same rule,
location, and evidence always hash to the same `tcf_` id. Golden tests in
`internal/model/fingerprint_test.go` fail if this algorithm changes.

Do not change the algorithm in place. A new digest needs a new `v` and
new golden tests.

## Input

The digest covers only:

- the rule id
- the normalized location (harness and, when set, session and path)
- the normalized evidence excerpts

Three things that might look like identity are deliberately **not**
hashed, because each one can change without the underlying finding
changing:

- **`location.line`.** A line number is where the finding currently
  renders, not what it identifies. Adding a line above a hook, or
  reformatting the file, shifts every line number below it; none of
  that is a new finding. `line` still lives on `Finding.Location` for
  display and in the JSON Schema; it is simply excluded from the hash.
- **`evidence[].event` and `evidence[].config`.** These are record ids,
  not content. `Event.id` is a ULID minted at ingest time, so the same
  occurrence re-derived from a reimported transcript, or from a hook
  event deduped against its transcript copy, mints a different ULID
  each time; hashing it would fragment one real occurrence into several
  fingerprints. `ConfigItem.id` (see below) is comparatively stable,
  but is excluded for the same reason: a finding's identity is the
  rule, the location, and what the evidence says, not which record
  happens to cite it. Only `evidence[].excerpt`, normalized, is hashed.
- **`location.scope`.** Not hashed, but not lost either: scope is
  already implied by the normalized path's own shape (repo-relative,
  `~/`-rooted, or a managed absolute path), so hashing it separately
  would not disambiguate anything further. See "Path scope" below.

Credential values, secret values, and network URLs are never inputs.
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

Keys, in this order, omitted when empty:

| Key | Rule |
| --- | --- |
| `harness` | Required. Trim with `strings.TrimSpace`. No case folding. Must be a known harness or surface. |
| `session` | `strings.TrimSpace`. Omit when empty. Internal spaces stay. |
| `path` | `normalizeScopedPath(location.Scope, location.Path)` (see "Path scope" below). Omit when `location.Path` is empty. |

`location.line` and `location.scope` are never part of the hashed
document; see "Input" above.

### Path scope

`internal/model/path.go`'s `normalizeScopedPath` normalizes a path and
checks its shape against the config scope (`repo`, `user`, or
`managed`) it belongs to. `ConfigItem.ID` and `Fingerprint`'s location
path both call it, so a path is validated the same way wherever it
names a config entry. An empty scope defaults to repo scope.

Normalization, in order: trim space, replace `\` with `/`, collapse
repeated `/` into one `/`, and strip a trailing `/` unless the result is
`/` or `~`. Dot segments (`.` or `..`) are not resolved.

Scope rules, checked after normalization:

| Scope | Rule | Rejected example |
| --- | --- | --- |
| `repo` (default) | Must be repo-relative: no leading `/`, no leading `~`, no Windows drive letter (`C:\`, `C:/`). | `/home/runner/work/acme/acme/.vscode/tasks.json`, `C:\Users\runner\acme\.vscode\tasks.json`, `~/.claude/settings.json` |
| `user` | Must be rooted at the user's home: exactly `~`, or starting with `~/`. | `/home/dev/.claude/settings.json`, `.claude/settings.json` |
| `managed` | Not restricted. Managed config files (the spec's adapter table lists, for example, `/etc/cursor/hooks.json`) are fixed absolute system paths. | — |

A path that violates its scope's rule is a `Fingerprint` error (and a
`ConfigItem.Validate` / `ConfigItem.ID` error): a CI-runner-specific
absolute path, or a Windows drive path, does not name a stable config
entry, so it must not reach the hash at all, machine-specific or not.

### Evidence

An array of the normalized, non-empty excerpts, sorted as raw strings
(byte order); duplicates are kept. Each item is `{"excerpt": "..."}`.
`strings.Fields` joins the excerpt's words with a single `U+0020`
(Unicode white space collapsed, ends dropped). An item that normalizes
to an empty excerpt is dropped. The array is `[]` when nothing remains,
never null.

## Digest

SHA-256 over the canonical UTF-8 bytes. Lowercase hex. The fingerprint is
`tcf_` plus the first 16 hex characters.

## Config item ids

`ConfigItem.ID()` is a separate, non-cryptographic id used by
`Evidence.Config`: `"<harness>:<scope>:<path>"`, where `path` is
`normalizeScopedPath(scope, path)`. It excludes `sha256` on purpose, so
the same config entry (for example, `.claude/settings.json` in the
repo) keeps the same id across edits to its content. It is not part of
the fingerprint preimage (see "Input" above).

## Examples

Rule `TC-SEC-018`, harness `claude`, session `00893aaf-19fa-41d2`, evidence
excerpt `cat /proc/$PPID/environ` (event id omitted from the hash):

```json
{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"excerpt":"cat /proc/$PPID/environ"}]}
```

Fingerprint: `tcf_bf8994fdb9dc73ed`

Rule `TC-CFG-002`, harness `vscode`, repo-scope path `.vscode/tasks.json`
(a `line` of 12, if set on `Finding.Location`, has no effect on this
digest):

```json
{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","path":".vscode/tasks.json"},"evidence":[{"excerpt":"a && b < c"},{"excerpt":"runOn: folderOpen"}]}
```

Fingerprint: `tcf_4dbb91737d62173a`

Rule `TC-CFG-001`, harness `generic`, no evidence:

```json
{"v":1,"rule":"TC-CFG-001","location":{"harness":"generic"},"evidence":[]}
```

Fingerprint: `tcf_6dcfe79827b07f1b`

Rule `TC-CFG-007`, harness `claude`, user-scope path
`~/.claude/settings.json`:

```json
{"v":1,"rule":"TC-CFG-007","location":{"harness":"claude","path":"~/.claude/settings.json"},"evidence":[{"excerpt":"hooks: SessionStart -> curl | bash"}]}
```

Fingerprint: `tcf_1a124c7ffb40127b`

Rule `TC-CFG-016`, harness `cursor`, managed-scope path
`/etc/cursor/hooks.json`, no evidence:

```json
{"v":1,"rule":"TC-CFG-016","location":{"harness":"cursor","path":"/etc/cursor/hooks.json"},"evidence":[]}
```

Fingerprint: `tcf_de048560c3426d6c`

A repo-scope path such as `/home/runner/work/acme/acme/.vscode/tasks.json`
(an absolute, CI-runner-specific path) is rejected by `Fingerprint`
rather than hashed as-is; see "Path scope" above.

The spec sample stores `fingerprint` as `tcf_8c1e77`. That field shows the
`tcf_` prefix. The digest this algorithm computes for the sample's rule,
location, and evidence is `tcf_bf8994fdb9dc73ed`, not that literal value;
see `schemas/README.md` and the finding schema's lenient `pattern` for why
the stored sample value still passes schema validation.
