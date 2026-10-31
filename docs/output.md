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

`<name>` is one path segment. The rest of the path keeps its spelling.
`/etc/cursor/hooks.json` and `C:/ProgramData/...` are unchanged. This is
presentation only.

## JSONL

`json` and `jsonl` write one `tripcord.finding/v1` document per line.
`encoding/json` replaces each invalid UTF-8 byte with U+FFFD. Every
other value round-trips: controls and bidi characters are escaped and
decode back to the same string. The location path is the display path
above, not a second copy of the stored path.

## SARIF

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

Summary-table cells double every backslash. A GitHub-flavored table
cell treats `\\` as an escaped backslash before it looks for `|`, so a
single backslash would not keep a `|` inside the cell. The detail
sections under the table show backslashes literally.
