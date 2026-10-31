# Finding fingerprints

A finding fingerprint is stable across Tripcord versions. The same rule,
location, and evidence always hash to the same `tcf_` id. Golden tests in
`internal/model/fingerprint_test.go` fail if this algorithm changes.

Do not change the algorithm in place. A new digest needs a new `v` and
new golden tests.

## Input

The digest covers only:

- the rule id
- the normalized location
- the normalized evidence

Credential objects, secret values, and network URLs are not inputs.
Evidence excerpts must already be redacted. This package does not search
excerpts for secrets.

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
| `path` | Trim space, replace `\` with `/`, collapse repeated `/` into one `/`, and strip a trailing `/` except when the path is `/`. Do not resolve `.` or `..`. Omit when empty. |
| `line` | Include only when the pointer is non-nil and the value is >= 1. A non-nil value below 1 is an error. |

No other location field is hashed.

### Evidence

An array sorted by `event`, then `excerpt`, compared as raw strings
(byte order). Duplicates stay. Each object keeps only:

| Key | Rule |
| --- | --- |
| `event` | `strings.TrimSpace`. Omit the key when empty. |
| `excerpt` | Split on Unicode white space (`strings.Fields`) and join with one U+0020. Omit the key when empty. |

Drop an item when both keys are empty. The array is `[]` when nothing
remains.

## Digest

SHA-256 over the canonical UTF-8 bytes. Lowercase hex. The fingerprint is
`tcf_` plus the first 16 hex characters.

## Examples

Rule `TC-SEC-018`, harness `claude`, session `00893aaf-19fa-41d2`, evidence
`evt_01JD7Q2M9X` / `cat /proc/$PPID/environ`:

```json
{"v":1,"rule":"TC-SEC-018","location":{"harness":"claude","session":"00893aaf-19fa-41d2"},"evidence":[{"event":"evt_01JD7Q2M9X","excerpt":"cat /proc/$PPID/environ"}]}
```

Fingerprint: `tcf_c95f982d5479e942`

Rule `TC-CFG-002`, harness `vscode`, path `.vscode/tasks.json`, line 12:

```json
{"v":1,"rule":"TC-CFG-002","location":{"harness":"vscode","path":".vscode/tasks.json","line":12},"evidence":[{"event":"evt_a","excerpt":"a && b < c"},{"event":"evt_b","excerpt":"runOn: folderOpen"}]}
```

Fingerprint: `tcf_420dd950a238d29b`

Rule `TC-CFG-001`, harness `generic`, no evidence:

```json
{"v":1,"rule":"TC-CFG-001","location":{"harness":"generic"},"evidence":[]}
```

Fingerprint: `tcf_6dcfe79827b07f1b`

The spec sample stores `fingerprint` as `tcf_8c1e77`. That field shows the
`tcf_` prefix. The digest this algorithm computes for the sample's rule,
location, and evidence is `tcf_c95f982d5479e942`.
