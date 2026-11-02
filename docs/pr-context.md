# `tripcord pr-context`

`tripcord pr-context` runs in CI and reports whether a pull request looks
agent-authored. It does not fail the job when it detects an agent: the
result is evidence for a later diff scan. Exit 0 means the command could
read its inputs, whether or not `agent` is true.

## Signals

Four signals are checked. A match on any of them sets `agent` to true.

| Signal | `type` | What is matched |
| --- | --- | --- |
| Bot login | `bot-login` | The pull request author's login, and each commit's author and committer name or GitHub noreply address. A login matches only with the `[bot]` suffix. When the event includes `user.type`, the pull request author matches only if that type is `Bot`. Commit authors have no `user.type`, and an event that omits it is matched on the login alone. |
| `Co-authored-by` | `co-authored-by` | Trailer addresses and bot logins in the trailing trailer block of a commit message. A mention earlier in the message is not a trailer. |
| Branch prefix | `branch-prefix` | The head branch name starts with a known prefix, including the slash. The comparison is case-sensitive. |
| git-ai note | `git-ai` | An authorship log on `refs/notes/ai` ([git-ai](https://github.com/git-ai-project/git-ai)) whose session or legacy prompt record names an agent tool. The raw tool is `signals[].value`; `signals[].agent` is the canonical id. |

The identity tables are **unverified** ([#34](https://github.com/vgmartinez/tripcord/issues/34)). They are one list each in
`internal/prcontext/identities.go`, and each list carries:

```
// TODO(#34): Verify the unverified agent identity tables (botLogins, trailerEmails, branchPrefixes) and replace 0 with the tracking issue.
```

A value that only resembles an entry does not match. `claude-bot` is not
`claude[bot]`, `feature/claude-fix` does not have the prefix `claude/`, and
`Co-authored-by: Claude Shannon <shannon@example.com>` is a human. A GitHub
noreply address matches a bot login only when it is
`<digits>+<login>@users.noreply.github.com` or
`<login>@users.noreply.github.com`; a non-numeric `+` prefix is refused.

### Bot logins

| Login | Agent |
| --- | --- |
| `copilot-swe-agent[bot]` | copilot |
| `copilot[bot]` | copilot |
| `chatgpt-codex-connector[bot]` | codex |
| `claude[bot]` | claude |
| `cursor[bot]` | cursor |
| `devin-ai-integration[bot]` | devin |
| `google-labs-jules[bot]` | jules |

Review bots such as `gemini-code-assist[bot]` are not listed. They comment
on pull requests but do not author the changes.

GitHub's Copilot coding agent is an exception to the `[bot]` suffix rule: it
opens pull requests as the literal login `Copilot`, with no suffix (see
[gh-aw project issue #1972](https://github.com/githubnext/gh-aw/issues/1972)).
Because a human account can also be named "Copilot", this login matches
**only** the pull request author, and only when the event's `user.type` is
exactly `Bot`; a missing or `User` type does not match. It is matched
separately from the table above and is not checked against commit authors
or committers, which have no `user.type`.

| Login | Requires `user.type` | Agent |
| --- | --- | --- |
| `Copilot` (pull request author only) | `Bot` | copilot |

### Trailer addresses

| Address | Agent |
| --- | --- |
| `noreply@anthropic.com` | claude |
| `cursoragent@cursor.com` | cursor |
| `copilot@github.com` | copilot |
| `noreply@opencode.ai` | opencode |
| `windsurf@codeium.com` | windsurf |

Codex has no trailer address. It is recognized only as
`chatgpt-codex-connector[bot]` and the `codex/` branch prefix.

### Branch prefixes

| Prefix | Agent |
| --- | --- |
| `claude/` | claude |
| `cursor/` | cursor |
| `copilot/` | copilot |
| `codex/` | codex |
| `devin/` | devin |

### Canonical agent ids

`agents[]` and `signals[].agent` use these ids. Logins, trailer addresses,
and branch prefixes come from the tables above. A git-ai tool is mapped
through `canonicalAliases` in `internal/prcontext/identities.go`; a tool
that is not listed passes through lowercased, so `claude` stays `claude`
and an unknown tool such as `amp` stays `amp`. The raw tool string is
kept in `signals[].value`.

| Canonical id | Logins | Trailer addresses | Branch prefixes | git-ai aliases |
| --- | --- | --- | --- | --- |
| claude | `claude[bot]` | `noreply@anthropic.com` | `claude/` | `claude-code` |
| codex | `chatgpt-codex-connector[bot]` | | `codex/` | |
| copilot | `copilot-swe-agent[bot]`, `copilot[bot]` | `copilot@github.com` | `copilot/` | |
| cursor | `cursor[bot]` | `cursoragent@cursor.com` | `cursor/` | |
| devin | `devin-ai-integration[bot]` | | `devin/` | |
| jules | `google-labs-jules[bot]` | | | |
| opencode | | `noreply@opencode.ai` | | |
| windsurf | | `windsurf@codeium.com` | | |

A tool name that is not a single token (letters, digits, and `._+-`) is
ignored. A note that records only humans is not a signal.

## Inputs

By default the GitHub `pull_request` event is read from `GITHUB_EVENT_PATH`.
The file may be the whole workflow event or the pull request object.

| Flag | Description |
| --- | --- |
| `--event <file>` | Event JSON file, instead of `GITHUB_EVENT_PATH`. |
| `--base <rev>` | Base revision. Overrides `pull_request.base.sha`. |
| `--head <rev>` | Head revision. Overrides `pull_request.head.sha`. When no branch name was in the event and this is not a full commit id, it is also the branch name. |
| `--repo <path>` | Repository to read. Default: the current directory. |
| `--format text\|json\|gha` | Text (default), one JSON document, or text plus `GITHUB_OUTPUT`. |

`--base` and `--head` together are enough when there is no event file.
The branch prefix then comes from `--head` unless it is a 40- or
64-character commit id. The pull request author is only known from the
event.

Commit ids are `git rev-list` of `base..head`; each raw object is then
streamed one at a time with `git cat-file --batch`, rather than formatted by
`git log`. `git notes --ref=ai show` streams each authorship note and keeps
only the validated tool ids, never the note text. Nothing is fetched. A
missing note is skipped.
A base or head the clone does not contain (a shallow checkout) is a
warning: author and branch signals are still reported, and the command
still exits 0. At most 5000 commits are read (the newest). Each
commit message keeps its first 64KiB and its last 64KiB, which is enough
for `Co-authored-by` trailers; a longer message drops the middle, and
that trim is silent. Across every field of every commit record, at most
128MiB is retained. Past that budget a later message keeps only its
trailer tail, shortened to whatever budget remains, or is dropped when
nothing remains, and one warning is emitted. An authorship note larger
than 2MiB is skipped; malformed git-ai notes are summarized in one warning
with their count. Neither cap fails the command.

A checkout action that defaults to a shallow clone (one commit) will
usually miss `base` entirely, turning every commit and note signal into a
warning and leaving only the pull request's login and branch to go on. Use
`fetch-depth: 0` (or a depth large enough to reach `base`) when checking
out the pull request so commit and note signals are not silently skipped:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Once `base` and `head` are known (from the event or from `--base`/`--head`),
the pull request's login and branch are judged and, when `GITHUB_OUTPUT`
is set, written before any commit is read. A failure to read commits or
notes — git is missing, the repository is unusable, or a log record
cannot be read — does not undo that write. It is reported as a warning,
commit and note signals are simply absent, and stdout still carries the
login and branch verdict. The command still exits non-zero in that case
(see Exit codes below). If the read succeeds and the commits add agents,
`GITHUB_OUTPUT` is appended again; GitHub Actions keeps the last value of
each name. The first write is what remains if the process is killed
while the commits are being read.

A revision that starts with `-` or contains git revision syntax (`..`,
`^`, `:`, `~`, `@`, and globs) is rejected before git runs.

Every git invocation uses the hardened environment and `-c` overrides in
`internal/gitrun`: inherited `GIT_*` variables and `SSH_ASKPASS` are
dropped, global and system config are not read, hooks, fsmonitor,
attributes, askpass, credential helpers, templates, and LFS filters are
disabled, and every transport other than https, ssh, and file is denied.
`GIT_NO_LAZY_FETCH=1` and `GIT_TERMINAL_PROMPT=0` are set. Commands also
pass `--no-pager` and `--no-optional-locks`.

## Output

Text:

```
agent: true
agents: claude, cursor
signals:
- type: branch-prefix
  agent: cursor
  value: cursor/add-thing
  source: pull_request.head.ref
```

JSON is one indented document with the same fields. `agent` is a boolean,
`agents` is the sorted agent ids, and each signal has `type`, `agent`,
`value`, and `source`. `source` is the pull request field (`pull_request.user.login`,
`pull_request.head.ref`) or the commit (`commit <sha> author`,
`commit <sha> committer`, `commit <sha> trailer`, `commit <sha> refs/notes/ai`).
`warnings`, when present, describes evidence that could not be read.

`--format gha` prints the text form and requires `GITHUB_OUTPUT`. Whenever
`GITHUB_OUTPUT` is set, whatever the format, these lines are appended:

```
is_agent=true
agents=claude,cursor
```

`agents` has no spaces. The login and branch lines are written before
commits are read. When commits add an agent those lines did not already
name, the same two lines are appended again and the second value wins;
when they do not, the file is left as the single block. `GITHUB_OUTPUT`
is opened refusing to follow a symlink and is required to be a regular
file (so a FIFO cannot hang the command); either case is refused with
exit 3, before commits are read. If the file already has content that
does not end in a newline, a newline is written first, so appending
never runs into a previous line (`agents=...is_agent=false` without one).

## Exit codes

| Exit | Meaning |
| --- | --- |
| `0` | The inputs were read. An agent may or may not have been detected. |
| `3` | Invalid flags, event, revision, or repository, or `GITHUB_OUTPUT` is missing for `--format gha` or is a symlink. |
| `4` | Git is not installed, or reading or writing failed. |

## Example

```sh
tripcord pr-context --format json
tripcord pr-context --repo "$GITHUB_WORKSPACE" --event "$GITHUB_EVENT_PATH" --format gha
```
