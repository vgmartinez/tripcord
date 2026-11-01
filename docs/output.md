# Output sinks

`internal/output` renders findings for people and CI. A finding's rule,
title, fix, excerpt, and path are attacker-controlled. Each sink redacts,
publishes only the path `locate` allows, and escapes control and bidi
characters for its format. The fingerprint field is copied as stored.
Rendering never recomputes it and never writes back into the finding.

## Paths

Repository paths are repository-relative, or omitted when they are
absolute and outside the repository root. User paths stay under `~`.
Managed paths are kept. A managed path under a home directory is shown
as `~/...` in every sink:

- `/Users/<name>/...`
- `/home/<name>/...`
- `<drive>:\Users\<name>\...` or `<drive>:/Users/<name>/...`, in any case

The model stores a Windows home path as `C:/users/<name>/...`. A sink
also rewrites the other slash and case spellings when it is handed them.
`<name>` is one path segment. The rest of the path keeps its spelling.
`/etc/cursor/hooks.json` and `C:/ProgramData/...` are unchanged. This is
presentation only.

The same rewrite applies to the path in `evidence[].config.id`
(`harness:scope:path`) when that scope is `managed`. A Linux id
`cursor:managed:/home/<name>/...` and a Windows id
`cursor:managed:C:/users/<name>/...` are shown as `cursor:managed:~/...`.
The stored id and the fingerprint stay as stored. Other scopes are
unchanged.

`c:x.json` and a bare `C:` are absolute, the same as `C:/...`. A
repository path in that form is omitted.

## Limits

Each displayed field is capped at 1024 bytes (`MaxFieldBytes`) after
redaction and after that sink's escaping. Markdown inserts its `@`
mention breaker before this cap, so the breaker counts toward the
limit. The marker is
`…[truncated N bytes]`, where N is the number of bytes dropped. The cut
is on a UTF-8 boundary and does not split an escape such as `\n`,
`\xNN`, `\uXXXX`, or `\UXXXXXXXX`.

A Markdown comment is also capped at 60000 bytes (`MaxMarkdownBytes`),
under GitHub's 65536-character limit. Findings that do not fit are
omitted whole. The comment then ends with `N more findings omitted`.

## Format characters

Unicode format characters (category Cf, including U+00AD, U+200B–U+200D,
U+2060, and U+FEFF) and tag characters U+E0000–U+E007F are escaped in
every sink. The Markdown mention breaker U+200B is inserted after that
escape, so `@org/team` still cannot notify.

## SARIF text

`message`, `shortDescription`, `fullDescription`, and `help` escape `[`
and `]` after the control escape, so a finding cannot embed a Markdown
link.

## Diagnostics

When discovery is incomplete, or a rule could not be evaluated on a file,
every format includes the diagnostics after
the same redaction and field cap as finding text. User paths stay under
`~`. A raw credential in a diagnostic is replaced with `[REDACTED]`.

JSONL appends one `tripcord.diagnostic/v1` document per diagnostic, with
`"incomplete": true`. It is not a finding document. Markdown adds a
Diagnostics section that says the scan is incomplete. Text prints a
`diagnostic:` line and `scan incomplete`. GitHub Actions output prints
`::error::`. SARIF sets `runs[0].invocations[0].executionSuccessful` to
false and describes each diagnostic in `toolExecutionNotifications`.
A report with no diagnostics is unchanged, including a SARIF run that
omits `invocations`.

## JSONL

`json` and `jsonl` write one `tripcord.finding/v1` document per line.
`encoding/json` replaces each invalid UTF-8 byte with U+FFFD. Controls,
bidi characters, and format characters are escaped and decode back to
the same string. A field longer than `MaxFieldBytes` is truncated, so
that field does not round-trip. The location path is the display path
above, and so is the path inside a managed config id, not a second copy
of the stored path. The fingerprint is the one stored on the finding.

A finding whose evidence carries a `sig:k1:`/`sig:s1:` discriminator
also gets a top-level `"fingerprintMode"` field (`"k1"` or `"s1"`); a
finding with nothing redacted omits it. See
[fingerprint.md](fingerprint.md#reporting-the-mode).

## SARIF

A managed path under a home directory uses `uriBaseId` `USERHOME`.
Any other managed path uses `MANAGED`. `properties.tripcord.path` and
a logical location's `name` and `fullyQualifiedName` use the same field
cap as other displayed text.

A finding whose evidence carries a `sig:k1:`/`sig:s1:` discriminator
gets `properties.tripcord.fingerprintMode` (`"k1"` or `"s1"`), present
even on a result with no location (and so no `scope`/`path`
properties); a finding with nothing redacted omits it. See
[fingerprint.md](fingerprint.md#reporting-the-mode).

Rule `fullDescription`, `help`, and `helpUri` come from `Options.Rules`
when that rule is present and the field is set. Otherwise they come
from the finding's title, fix, and first http(s) ref. PR 5 fills
`Options.Rules` from the rule catalog; the fallback stays.

An empty tool version, or any version that is not SemVer, is reported
as driver `version` `dev` (or the given text) and `semanticVersion`
`0.0.0-dev`.

## Markdown

Attacker-controlled text appears only inside code spans or fenced code
blocks. `@` is followed by U+200B so it does not become a mention.

Summary-table cells keep backslashes as written, so a Windows path
appears once (`C:\dir`). A literal `|` is escaped as `\|` so it cannot
end the cell. Detail sections show the same backslashes.

A run of n literal backslashes before an escape body (`n`, `r`, `t`,
`xNN`, `uXXXX`, `UXXXXXXXX`) or before a character that will be escaped
is rendered as 2n backslashes, so literal text and real control
characters never render the same. For example, `C:\temp` renders as
`C:\\temp`, and literal text `\x1b` renders as `\\x1b`, distinct from an
actual ESC byte, which renders as `\x1b`. A backslash that does not
precede an escape, such as `C:\dir`, is unchanged.
