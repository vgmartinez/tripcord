# `tripcord pr-context`

`tripcord pr-context` runs in CI and reports whether a pull request looks
agent-authored. It does not fail the job when it detects an agent: the
result is evidence for a later diff scan. Exit 0 means the command could
read its inputs, whether or not `agent` is true.

## Signals

Four signals are checked. A match on any of them sets `agent` to true.

| Signal | `type` | What is matched |
| --- | --- | --- |
| Bot login | `bot-login` | The pull request author's login, and each commit's author and committer name or GitHub noreply address. |
| `Co-authored-by` | `co-authored-by` | Trailer addresses and bot logins in the trailing trailer block of a commit message. A mention earlier in the message is not a trailer. |
| Branch prefix | `branch-prefix` | The head branch name starts with a known prefix, including the slash. The comparison is case-sensitive. |
| git-ai note | `git-ai` | An authorship log on `refs/notes/ai` ([git-ai](https://github.com/git-ai-project/git-ai)) whose session or legacy prompt record names an agent tool. |

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

### Trailer addresses

| Address | Agent |
| --- | --- |
| `noreply@anthropic.com` | claude |
| `cursoragent@cursor.com` | cursor |
| `copilot@github.com` | copilot |
| `noreply@opencode.ai` | opencode |
| `windsurf@codeium.com` | windsurf |

### Branch prefixes

| Prefix | Agent |
| --- | --- |
| `claude/` | claude |
| `cursor/` | cursor |
| `copilot/` | copilot |
| `codex/` | codex |
| `devin/` | devin |

git-ai tool names are not in these tables. The tool string from the note
is the agent id, lowercased (`cursor`, `claude`, `copilot`, ...). A tool
name that is not a single token (letters, digits, and `._+-`) is ignored.
A note that records only humans is not a signal.

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

Commits are `git rev-list` / `git log` of `base..head` and
`git notes --ref=ai show`. Nothing is fetched. A missing note is skipped.
A base or head the clone does not contain (a shallow checkout) is a
warning: author and branch signals are still reported, and the command
still exits 0. At most 5000 commits are read (the newest), and a commit
message or authorship note past its size cap is skipped with a warning
rather than failing the command.

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

`agents` has no spaces. A symlink `GITHUB_OUTPUT` is refused.

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
