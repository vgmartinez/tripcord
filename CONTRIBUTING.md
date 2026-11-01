# Contributing

This repository is a private pre-release. The license is Apache-2.0
([LICENSE](LICENSE)).

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a contributor license agreement.

Every commit must include a `Signed-off-by` trailer that matches the commit author:

```
git commit -s
```

That adds a trailer of this form:

```
Signed-off-by: Your Name <you@example.com>
```

CI rejects pull requests whose commits are missing that trailer.

## First contributions

Three ways to start, once the corresponding code exists:

1. Add a rule from a public incident, with positive fixtures, negative fixtures, and a link to the incident or to official documentation.
2. Add fixtures for a new version of a harness that already has an adapter.
3. Add an adapter for a harness that is not covered yet.

## Rules

A rule is one YAML file, `rules/<ID>.yaml`, plus fixtures in
`rules/<ID>.test/`. Rules are data: the condition is a CEL expression,
and CEL cannot read files, use the network, or run commands.

```yaml
id: TC-CFG-002
pack: tripcord/core
title: "VS Code task that runs when the folder opens (also Cursor and Windsurf)"
severity: high                       # low | medium | high | critical
harness: [vscode]
files: [".vscode/tasks.json"]        # repo-relative or ~/ globs; ** is allowed
when: >-
  has(task.runOptions) && has(task.runOptions.runOn) &&
    task.runOptions.runOn == "folderOpen"
fix: "Remove runOn: folderOpen or move the task to an explicit script. Cursor and Windsurf open this same .vscode/tasks.json."
refs:
  - https://workos.com/blog/npm-worm-coding-agent-config-credentials
```

Every key except `severity_when` is required. `refs` needs at least one
https link to the incident or to official documentation; a rule without
`refs` is not accepted. `pack` is the pack name, `<namespace>/<name>`.
The version lives only in `rules/pack.yaml` (for example
`tripcord/core@2026.11`); a rule inherits it. `rules/REGISTRY` is what
stops a rule id from being reused.

`severity` is the rule's catalog severity and the floor a policy lock
refuses to lower. `severity_when` is an optional list of
`{severity, when}` clauses tried in order once `when` is true. The
first true clause is that match's severity, so one permissions object
can be high and another medium. An item no clause accepts is not a
match, so `when` holds only what the clauses share and each pattern is
written once. A policy severity override replaces the per-match
result. A clause may also set `title`, which replaces the rule title on
its findings when the rule title does not say why that match fired.

`when` sees these variables:

- `config`: the config item (`id`, `harness`, `scope`, `path`, `sha256`, `kind`), `missing_scripts`: on a repository hook, how many project-relative scripts it runs are not in the scanned tree (0 otherwise; see `internal/scriptcheck`), and `script_locations`: the location classes of project scripts whose symlink resolves outside the repository.
- `payload`: the item's parsed content.
- `task`: the same as `payload` when `config.kind == "task"`, otherwise empty.
- `event`: a `tripcord.event/v1` event, for event rules. Every
  non-list event field is present; omitted strings are `""`.

Besides the standard CEL and string extension functions, `when` can
call `shell.risks(command)`, which reads a command line (a string, or
an argv list of strings) as a POSIX, PowerShell, or cmd shell would and
returns the risks it found: `"fetch"` (a downloader in command position
with a non-loopback target), `"pipe"` (output piped into a shell, or a
fetch piped into Invoke-Expression), `"encoded"` (`powershell
-EncodedCommand`, or decoded content fed to Invoke-Expression), and
`"nested"` (payloads nested deeper than it follows). It follows `-c`, `-Command`, and `/c` payloads, `$( )`,
backticks, and `eval`, and costs one unit per byte it reads at each
nesting level, so prefer it to long regexes over hook commands.

`shell.locations(command)` reads the line the same way and returns
where the programs it runs live: the program of each simple command,
and the script an interpreter is given (`bash x.sh`, `python x.py`,
`node x.js`, `pwsh -File x.ps1`, `source x`). The classes are
`"network"` (a non-loopback URL or a UNC share), `"home"` (`~`,
`$HOME`, `%USERPROFILE%`, `/home/<user>`, ...), `"temp"` (`/tmp`,
`$TMPDIR`, `%TEMP%`, ...), `"absolute"` (any other absolute path,
except a binary without a script extension under a system directory
such as `/usr/local/bin`), and `"parent"` (`../x.sh`). Relative paths,
`$CLAUDE_PROJECT_DIR`, `$CLAUDE_PLUGIN_ROOT`, `$GEMINI_PROJECT_DIR`,
`$CURSOR_PROJECT_DIR`, and `$PWD` are the project directory; other
variables, substitutions, and programs on `PATH` have no location.
Arguments are not read, so `cat ~/.ssh/config` is not a home program.
It costs what `shell.risks` costs.

`hook.commands(payload)` returns the string values of a hook's command
fields (`command`, `exec`, `bash`, `powershell`, `commandWindows`,
`command_windows`, `windows`, `linux`, `osx`), skipping missing and
non-string ones. `hook.argv(payload)` returns `[exec or command] +
args`, with number and bool args as their text, and `[]` when there are
no `args`. When `args` is not a list or holds an object, list, or null,
it is an evaluation error ("hook args are not strings, numbers, or
bools"), not an empty argv, so the scan reports that rule and file as
incomplete and exits 3 instead of passing over the hook. Use them
instead of restating the field list in every clause: a long expression
is parsed again on every scan.

Reading a field that is missing makes the whole expression false, not
an error. That fails open for negations and deny rules:
`!(payload.tools.size() > 0)` would be false for a server with no
`tools`. So the loader rejects any read below `payload`, `task`, a
comprehension variable (`x` in `payload.servers.exists(x, ...)`), or an
event field outside the schema, unless a `has()` test (or `"key" in x`)
proves it present first: on the left of `&&`, negated on the left of
`||`, or in the condition of `?:`. Guard every level:
`has(task.runOptions) && has(task.runOptions.runOn) && ...`. Index
only with constant string keys; use `exists()` or `all()` for lists.

A match cites the config file by id. When the payload has a stable
entry name, that name is the evidence key: `label` for a task, `name`
for an MCP server, and `matcher|command` for a hook. Two entries in
one file then get different fingerprints. Other kinds have no key.
`matches()` uses RE2: no backreferences or lookaround. Each evaluation
has a cost limit (20M units in scans, 2M on the hook path, where the
input is capped at 64 KiB). Cost is counted, not timed, so a rule gives
the same result on a loaded machine. Every core rule on a 1 MiB config
file stays under 10M. The timeouts (10 s in scans, 1 s on the hook
path, and a 5 s budget for one hook event's rules) are only a safety
net for a cost model that underestimates a rule. They are cooperative:
CEL checks them between steps, so one `matches()` over a large string
finishes before it notices. The input caps bound that case. A rule that fails to evaluate on a file, for
example over the cost limit, does not stop the scan: the other rules and
files are reported, with a diagnostic naming the rule and file, and the
scan exits 3 as incomplete.

### Rule ids

Rule ids are never reused. `rules/REGISTRY` lists every id ever
allocated. When you add a rule, append a line:

```
TC-CFG-002 active tripcord/core@2026.11
```

To withdraw a rule, delete its YAML and change the line to `retired`.
Do not remove lines. CI compares the file with the pull request base.

### Fixtures

`rules/<ID>.test/positivos/` holds inputs that must trigger the rule and
`rules/<ID>.test/negativos/` inputs that must not. Each needs at least
one fixture. A fixture is either of:

- A directory: a repository tree of real config files, sanitized. The
  test runs every adapter on it, autodetected as `tripcord scan` does,
  and fails if the adapters report the tree as incomplete. Prefer this
  form, with one directory per case, for example
  `positivos/claude-sessionstart-curl/.claude/settings.json`.
  A directory named `_home` is that fixture's home directory, with user
  scope on and an empty environment, so a host `COPILOT_HOME` or
  `XDG_CONFIG_HOME` cannot redirect it. Use it for user-scope files such
  as `~/.copilot/mcp-config.json`.
- A `.json` engine fixture: a config item, or an array of them, with
  `sha256` optionally left empty. Use it for payloads an adapter would
  not produce from a real file, such as a field of the wrong type:

```json
{"harness": "vscode", "scope": "repo", "path": ".vscode/tasks.json", "sha256": "",
 "kind": "task", "payload": {"label": "setup", "runOptions": {"runOn": "folderOpen"}}}
```

A positive and a negative both fail when no discovered item is inside
the rule's harness and file globs. A negative that only holds an
out-of-scope file would otherwise pass without testing `when`.

`rules/<ID>.test/expect.yaml` says what each fixture must produce, keyed
by its directory or file name. A positive lists the distinct severities
of its matches (`curl-pipe: high`, `two-hooks: [high, medium]`); a rule
with `severity_when` needs an entry for every positive, and a positive
of any other rule must match at the rule's severity. A negative may be
marked `error`: the rule must fail to evaluate it, as for a hook whose
`args` hold an object. An entry for a fixture that does not exist
fails. `TestSeverityClausesAreCovered` disables each `severity_when`
clause in turn and fails when the fixtures still pass, so every clause
needs a fixture whose severity it decides.

Fixture configs use `.invalid` or `example` hosts and placeholder
secrets only.

Run one rule:

```sh
make test-rule ID=TC-CFG-002
```

`go test ./internal/rules` runs every rule's fixtures.

## Policy

The org policy comes from sources the repository does not control: the
managed file (`/etc/tripcord/policy.yaml` on Linux,
`/Library/Application Support/Tripcord/policy.yaml` on macOS,
`%ProgramData%\Tripcord\policy.yaml` on Windows) and any file passed
explicitly, as the `--org-policy` flag or the GitHub Action input will.
In CI, the Action input is only as trustworthy as the managed file: it
comes from the repository's own workflow file, which the repository
controls, so a repo that wants an org layer it cannot bypass in CI
needs the runner-managed file or an org-level required workflow the
repo cannot edit, not the Action input alone.
`.tripcord/policy.yaml` is the repo policy. Its `extends` adds layers
after the org layer; it cannot replace or skip it.
`.tripcord/policy.local.yaml` is the per-checkout layer and is not
committed. `tripcord init`, when it lands, must add
`.tripcord/policy.local.yaml` to the `.gitignore` it writes.

With no policy file, `scan`, `preopen`, `pr-context`, and the Action
run in `enforce` and fail on `high`. The hook defaults to `warn` with
the same fail-on, so it shows findings, including high and critical,
and does not block. A finding only blocks (exit 1, or a hook block)
when mode is `enforce` and its severity is at or above fail-on: `audit`
and `warn` never block, whatever fail-on is. `DefaultsFor` in
`internal/policy` is the only definition of the no-policy defaults. An
explicit `mode` or `fail-on` replaces it. See
[docs/policy.md](docs/policy.md).

`locked` can freeze `mode`, `rules`, and `exceptions`. A locked rule
stays enabled even if a later `rules.include` leaves it out, and a
later layer cannot add an exception for it, pin its pack below the
version in effect at the lock, or remove a harness the rule covers
from `harnesses`. Locking `mode` also locks `fail-on` to a ceiling, the
value in effect at the lock: a later layer may lower it but a raise is
rejected.

## Dependencies and licenses

Every dependency must use a license on the CI allowlist: Apache-2.0,
MIT, BSD-2-Clause, BSD-3-Clause, or ISC. The `dependency licenses` job
fails on anything else, including AGPL, GPL, SSPL, and licenses it
cannot identify.

TruffleHog is AGPL-3.0. It must never be linked into Tripcord, and no
code may be copied from it. Secret detection uses gitleaks rules (MIT).

## Development

```sh
make fmt
make lint
make test
make build
```

`make build` sets `CGO_ENABLED=0`. `make test` runs the race detector, which needs a C toolchain and cgo; the module itself does not use cgo.
