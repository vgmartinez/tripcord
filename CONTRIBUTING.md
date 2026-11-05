# Contributing

The license is Apache-2.0 ([LICENSE](LICENSE)). Using the scanner is in
the [README](README.md). Package layout, link-time version, and Make
targets are in [docs/development.md](docs/development.md).

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

Three ways to start:

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

Every key except `severity_when` and `evidence` is required. `refs` needs at least one
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
its findings when the rule title does not say why that match fired, and
`fix`, which replaces the rule fix on them the same way.

`evidence: hidden_chars` is the only optional evidence. It adds an
excerpt naming the file's hidden code points by code point, line, and
column (see `internal/hiddenchar`), never the text between them, and
sets the location line to the first one. TC-CFG-011 fingerprints the
file and hidden-code-point sequence, not presentation coordinates.

`when` sees these variables:

- `config`: the config item (`id`, `harness`, `scope`, `path`, `sha256`, `kind`), `missing_scripts`: on a repository hook, how many project-relative scripts it runs are not in the scanned tree (0 otherwise; see `internal/scriptcheck`), `script_locations`: the location classes of project scripts whose symlink resolves outside the repository, `checksum_files`: on a repository env-setup entry, a map from each committed sums file its `sha256sum -c` checks name to the file names it lists (missing, out-of-tree, symlinked, and malformed sums files are left out; see `internal/scriptcheck`), `checksum_symlinks`: the fetched or run checksum-grammar filenames that are repository symlinks, and `hidden_chars`: on a markdown file, how many bidi controls, tag characters, and zero-width code points it holds (a leading BOM is not counted; an isolated U+200B, U+200C, or U+200D is not counted only when both neighbors are whitespace, a line boundary, or the edge of a quote or code fence; a quoted string or bracket class made only of zero-width characters is not counted when that span has at most 8 code points and no code point repeats; 0 otherwise).
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

`shell.unpinned(command)` returns what `shell.risks` returns, or `[]`
when every fetch in the line is pinned (see `shellcmd.Unpinned`): each
downloader target is an allowlisted https URL (GitHub raw, archive,
codeload, or gist; jsDelivr `gh@<sha>`; or GitLab `/-/raw/<sha>`;
never a `sha256:` digest, which curl and wget do not verify) with no userinfo and no `.`
or `..` path segment (decoded or not), or the whole line is a script
the checksum grammar accepts (see `checksumScript` and
`docs/rules/TC-CFG-009.md`): curl/wget fetches to plain
current-directory filenames, checks that cover them (an `echo`/`printf`
entry, or `sha256sum -c <sums>` where `<sums>` is never fetched or run),
`sh`/`bash` runs of the fetched files, a leading `set -e`, and restricted
`mkdir`/`chmod`/`rm`, with nothing else. `cd`, `export`, and assignments
do not receive checksum credit. Package runners, git
clone, variable targets, and version tags are never pinned. It costs
what `shell.risks` costs. `shell.unpinned(command, config.checksum_files,
config.checksum_symlinks)` also lets a `sha256sum -c <sums>` check cover
the files a committed final regular `<sums>` file lists, unless a fetched
or run target is a repository symlink; with one argument such a check
covers nothing.

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

`shell.mcp([program, arg, ...])` is the command line TC-CFG-003 judges.
A POSIX shell `-c` or `cmd /c`, `/k`, or `/r` (a path, `.exe`, or a
flag cluster such as `-lc` or `/s /c`) whose payload is one simple
command is replaced by that command, and the replacement is read again
up to the same depth `shell.risks` follows. A simple command is one
literal bare word or path and its arguments, or `cd <dir> &&` that
command, after `env`, `sudo`, `exec`, `command`, and assignments are
dropped. The payload is left wrapped when it contains `$`, `%`, a
backtick, or `^`, and a `cmd` payload is left wrapped when `&`, `|`,
`<`, or `>` remains after quotes are removed. A pipe, `;`, `||`, an
extra `&&`, a substitution, a redirection, or a downloader the lexer
sees is left wrapped too. It costs one unit per argv byte at each
level it may read.

`hook.commands(payload)` returns the string values of a hook's command
fields (`command`, `exec`, `bash`, `powershell`, `commandWindows`,
`command_windows`, `windows`, `linux`, `osx`), skipping missing and
non-string ones. `hook.argv(payload)` returns `[exec or command] +
args`, with number and bool args as their text, and `[]` when there are
no `args`. A map argument is an opaque marker that never matches a
command value. A list argument is recursively coerced like JavaScript
`Array#toString`: nested lists join with commas and null inside a list
becomes empty text. This reflects the argv text JavaScript harnesses
pass to `spawn`, so `["-e"]` is evaluated as `-e` rather than hidden.
Both a map marker and a coerced list emit a warning with its JSON
pointer without making the scan incomplete. When `args` is not a list,
or holds top-level null, it is an evaluation error ("hook args are not
strings, numbers, or bools"), not an empty argv, so the scan reports
that rule and file as incomplete and exits 3 instead of passing over
the hook. Use them instead of restating the field list in every clause:
a long expression is parsed again on every scan.

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
file stays under 10M. The timeouts (15 s in scans, 1 s on the planned hook
path, and a 5 s budget for one hook event's rules on the planned hook path) are only a safety
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

`rules/ADVISORIES.json` is the offline package-advisory list used by
TC-CFG-023. It ships in the free core pack. Ids are `TCA-YYYY-NNNN`,
append-only, and never reused; set `withdrawn` to a date instead of
deleting an entry. CI checks the file next to `REGISTRY`: ids are
unique, the document matches the schema, and an id is not removed or
un-withdrawn. A critical advisory ships in a pack patch. Every other
advisory ships in the monthly release. The list is embedded. Querying
OSV is future work, and v0.1 has no online mode.

### Fixtures

`rules/<ID>.test/positivos/` holds inputs that must trigger the rule and
`rules/<ID>.test/negativos/` inputs that must not. Each needs at least
one fixture. A fixture is either of:

- A raw fixture: a repository tree of real config files, sanitized,
  committed as one text archive `<name>.txtar`. Each file of the tree
  follows a `-- path --` line, in path order, with its bytes unchanged.
  The tests unpack it into a temp directory named `<name>`, run every
  adapter on it, autodetected as `tripcord scan` does, and fail if the
  adapters report the tree as incomplete. Prefer this form, with one
  archive per case, for example
  `positivos/claude-sessionstart-curl.txtar` holding
  `-- .claude/settings.json --`. The archive keeps the config files
  from being loaded by a harness that opens this repository, and holds
  no file modes, so no fixture script is executable.
  A directory named `_home` is that fixture's home directory, with user
  scope on and an empty environment, so a host `COPILOT_HOME` or
  `XDG_CONFIG_HOME` cannot redirect it. Use it for user-scope files such
  as `~/.copilot/mcp-config.json`.
  Do not commit a symlink. GitHub's action download fails on any
  tracked symlink, so `TestNoTrackedSymlinks` rejects them. Add the link
  to `fixtureSymlinks` in `internal/rules/fixture_symlinks_test.go`
  instead; the fixture tests copy the pack to a temp directory and
  create it there. A link whose target is outside the repository goes
  in a test of its own, such as `TestTCFG006OutsideSymlinks`.
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
by its archive name without `.txtar`, or its `.json` file name. A positive lists the distinct severities
of its matches (`curl-pipe: high`, `two-hooks: [high, medium]`); a rule
with `severity_when` needs an entry for every positive, and a positive
of any other rule must match at the rule's severity. A negative may be
marked `error`: the rule must fail to evaluate it, as for a hook whose
`args` hold an object. An entry for a fixture that does not exist
fails. `TestSeverityClausesAreCovered` disables each `severity_when`
clause in turn and fails when the fixtures still pass, so every clause
needs a fixture whose severity it decides.

Fixture configs use `.invalid` or `example` hosts and placeholder
secrets only. `go test ./internal/corpus` lints every file in `rules/`
and in `internal/adapters/*/testdata` with the corpus checks. Adapter
fixture trees (`repo`, `home`, `managed`, `policy`) live in a
harness-version directory under `testdata/`, as archives such as
`testdata/claude-baseline/repo.txtar`. No release version is recorded
for the fixtures that were already here, so those directories are named
`<harness>-baseline`. A new harness version adds a directory and does
not edit an old one. `kittest.CopyTree` unpacks an archive into a temp
directory and `kittest.ReadFixture` reads one member. The discover
golden test walks every version directory. `discover.golden` is
regenerated only with `go test ./internal/adapters/... -update`;
without `-update` a diff fails the test. Rule YAML, README files, and the other pack
files outside `<ID>.test/` skip the host, IOC, and entropy checks. A
finding that must stay, such as a real host a rule matches, needs a
line in `internal/corpus/allowlist.tsv` with its reason; a stale line
fails too, and a secret or fetch-and-exec finding can never be listed.
Third-party benign snippets go in `corpus/benign/vendored/` with a
`THIRD_PARTY_NOTICES` entry; see `corpus/benign/README.md`.

Run one rule:

```sh
make test-rule ID=TC-CFG-002
```

`go test ./internal/rules` runs every rule's fixtures.

## Policy

The org policy comes from sources the repository does not control: the
managed file (`/etc/tripcord/policy.yaml` on Linux,
`/Library/Application Support/Tripcord/policy.yaml` on macOS,
`%ProgramData%\Tripcord\policy.yaml` on Windows) and `--org-policy`.
A GitHub Action input for that layer is planned. A workflow file the
repository can edit is not a substitute for the managed file.
`.tripcord/policy.yaml` is the repo policy. Its `extends` adds layers
after the org layer; it cannot replace or skip it.
`.tripcord/policy.local.yaml` is the per-checkout layer and is not
committed. `tripcord init` is planned. When it exists, it must add
`.tripcord/policy.local.yaml` to the `.gitignore` it writes.

With no policy file, `scan` runs in `enforce` and fails on `high`.
`preopen`, `pr-context`, and the Action are planned; `DefaultsFor` in
`internal/policy` already gives those surfaces `enforce` and fail-on
`high`. The hook command is planned; that surface defaults to `warn`
with the same fail-on, so it would show findings, including high and
critical, and would not block. A finding only blocks (exit 1, or a hook
block) when mode is `enforce` and its severity is at or above fail-on:
`audit` and `warn` never block, whatever fail-on is. `DefaultsFor` is
the only definition of the no-policy defaults. An explicit `mode` or
`fail-on` replaces it. See [docs/policy.md](docs/policy.md).

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
code may be copied from it. CI rejects a module graph that contains it.
Secret detection is planned and is not in this build. The intended
rules are gitleaks (MIT), not TruffleHog.

## Development

```sh
make fmt
make lint
make test
make build
```

`make build` sets `CGO_ENABLED=0`. `make test` runs the race detector, which needs a C toolchain and cgo; the module itself does not use cgo.
