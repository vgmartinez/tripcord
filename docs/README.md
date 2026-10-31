# Documentation

Design notes for this private pre-release.

## Policy defaults

[policy.md](policy.md) defines the mode and fail-on used when a repo has
no policy file, and how an explicit policy overrides them. The value
depends on the surface: scans fail on high, and the hook warns.

## Scan CLI

[scan.md](scan.md) documents `tripcord scan`, its static-only behavior,
formats, flags, policy interaction, examples, and exit codes.

## Adapters

[adapters/claude.md](adapters/claude.md) documents the Claude Code
configuration adapter and its scope boundaries.
[adapters/codex.md](adapters/codex.md), [adapters/cursor.md](adapters/cursor.md),
and [adapters/copilot.md](adapters/copilot.md) document the Codex, Cursor,
and GitHub Copilot adapters.
[adapters/gemini.md](adapters/gemini.md),
[adapters/opencode.md](adapters/opencode.md), and
[adapters/windsurf.md](adapters/windsurf.md) document the Gemini CLI,
OpenCode, and Windsurf adapters, and
[adapters/devcontainer.md](adapters/devcontainer.md) the Dev Container
adapter (`devcontainer`).
[adapters/generic.md](adapters/generic.md) documents the shared-files
adapter (`generic`) and which adapter owns a file several harnesses read.

## Finding fingerprints

[fingerprint.md](fingerprint.md) defines the canonical finding fingerprint.
The digest is stable across versions. Golden tests lock it.

## Output

[output.md](output.md) defines how sinks display paths, the JSONL UTF-8
contract, SARIF rule text, and Markdown table cells.

## Decisions

A finding's `decision` is `allow`, `deny`, `warn`, `audit`, or `ask`.
Policy mode (`enforce`, `warn`, `audit`) is a separate vocabulary.

In hook mode, `ask` maps to the harness's native human-confirmation
prompt where that harness supports one (Claude Code, Cursor) and
degrades to `deny` with an explanatory message elsewhere. The mapping
itself is implemented later, in the hook PR. This package only records
`ask` as a valid decision.

## Repository identity

The GitHub owner and repository name are defined in one place: `Repository`
in `internal/project`.

The module path in `go.mod` is the import path (`github.com/` plus that
constant). A test checks that the two stay in sync. To move the project to
another owner, change those two and leave every other file alone.
