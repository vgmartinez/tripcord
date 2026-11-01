# TC-CFG-011: Hidden Unicode in an agent instructions file

| | |
| --- | --- |
| Severity | high |
| Harnesses | generic (`AGENTS.md`), Claude Code, Gemini CLI, Windsurf, GitHub Copilot, Cursor, Devin |
| Files | `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md` (any depth), nested `.claude/rules/**/*.md`, `.cursor/rules/**/*.md(c)`, and `.windsurfrules`, plus root `.cursorrules`, `.github/copilot-instructions.md`, `.github/instructions/**/*.md`, `.github/agents/**/*.agent.md`, and the maintenance commands and knowledge entries of `.devin/blueprint.yaml` (repository scope) |
| Rule | [`rules/TC-CFG-011.yaml`](../../rules/TC-CFG-011.yaml) |

## What it detects

Some code points are invisible in an editor and in a pull-request diff,
but the model reads them. A bidi control reorders what a reviewer sees
(Trojan Source). Tag characters (U+E0000-U+E007F) mirror ASCII, so a run
of them spells text no one sees. Zero-width code points hide or split
words. In an instructions file, any of them can carry an instruction a
reviewer cannot see.

One finding per file that holds any of:

| Class | Code points |
| --- | --- |
| bidi control | U+202A-U+202E, U+2066-U+2069 |
| tag character | U+E0000-U+E007F |
| zero-width | U+200B, U+200C, U+200D, U+2060, U+FEFF |

The whole file is read as bytes, frontmatter included. A U+FEFF that
starts the file is a byte order mark and is not counted; one anywhere
else is.

A U+200D between two Extended_Pictographic characters is a normal emoji
ZWJ sequence and is not reported. U+FE0F and skin tones
(U+1F3FB-U+1F3FF) may sit between the joiner and either character, so
sequences such as 🏳️‍🌈 and 🐈‍⬛ are quiet. A U+200D beside ASCII, or at
the start or end of a file, is reported.

Not reported:

- U+200E and U+200F (left-to-right and right-to-left marks), which
  change no order on their own and are common in right-to-left text.
- User-scope files.

## Evidence

The evidence names each run of consecutive hidden code points by its
first code point, line, and column, and how many are in the run:

```
2 hidden code points: U+202E (bidi control) at line 3, column 34; U+202C (bidi control) at line 3, column 41
```

Lines are counted from 1 and split on `\n`. Columns count code points
from 1, so a CJK character or an emoji before the run is one column. An
invalid UTF-8 byte counts as one column. The first five runs are listed,
then how many more there are. The finding's location line is the first
run's line. SARIF and GitHub annotation output carry that line but no
evidence excerpt, as for every rule.

The evidence never includes the text: not the characters a bidi run
reorders, and not what a tag run spells. A tag run is named by its
block, not by its code points, because each tag code point maps to one
ASCII character and listing them would spell the hidden text.

The fingerprint is the file, hidden code-point sequence, and its
ordinal within the file. Line and column are evidence only, so moving
the same hidden sequence does not create a new finding.

A file that is not valid UTF-8 is still checked in its valid parts, and
the scan reports a diagnostic and exits 3 (incomplete), but only for a
file this rule reads.

## Examples

Reported (the escapes stand for the raw code points):

```
Run `make test` before you push. \u202e;)(nuR\u202c Never skip it.
```

```
Use the stan\u200bdard formatter.
```

Not reported: a file that starts with a byte order mark and has no
other hidden code point.

## How to fix

Remove the hidden code points (the finding names each one's line and
column), then review the instructions as they read without them. If a
non-Latin script needs a direction mark, use U+200E or U+200F.

## References

- [Trojan Source](https://trojansource.codes/)
- [Unicode bidirectional algorithm (UAX #9)](https://www.unicode.org/reports/tr9/)
- [Unicode tags block](https://www.unicode.org/charts/PDF/UE0000.pdf)
- [Hiding and finding text with Unicode tags](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/)
