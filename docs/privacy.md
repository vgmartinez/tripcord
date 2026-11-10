# Privacy and redaction

Everything tripcord prints or writes goes through one redactor,
`output.DefaultRedactor` in `internal/output/redact.go`, and a length
cap. Config text, hook events, policy text, and errors can all hold
credentials, and an attacker can choose them. This page lists every
surface v0 emits, where each one is redacted, and how long an excerpt
can be.

## What the redactor claims

`DefaultRedactor` replaces each of these with `[REDACTED]`, in this
order:

| Class | Example | Code |
| --- | --- | --- |
| `Authorization:` header value | `-H "Authorization: Bearer X"` | `authorizationPattern` |
| Secret flag value, after `=` or whitespace (S1) | `--token=X`, `--api-key X` | `RedactSecretFlags` |
| `-u` / `--user` value of the form `user:pass` (S2) | `curl -u admin:X` | `RedactUserFlags` |
| A tool's own short password or token flag (S2) | `sshpass -p X`, `redis-cli -a X`, `mysql -pX`, `docker login -p X`, `openssl -k X`, `vercel -t X` | `RedactToolFlags` |
| A quoted value, as a whole (S3) | `--password "a b X"` | all flag and assignment classes |
| A shell-escaped quoted value (`\"...\"`) | `echo "token: \"X\""`, `TOKEN=\"X\"`, `--password \"X\"` | `indexEscapedQuotes`, every value reader |
| URL userinfo, with an empty username or percent-encoded too (S4) | `https://u:X@host`, `redis://:X@host`, `https://u:p%40X@host` | `RedactURLUserinfo` |
| MCP argv with the value in the next element (S4) | `["--token", "X"]` | `RedactToolArgv` (source side) |
| Token shapes | private key blocks, `AKIA…`, AWS secret keys, `ghp_…`, `github_pat_…`, `glpat-…`, `sk-…`, `sk_live_…`, `xox?-…`, `xapp-…`, `npm_…`, `hf_…`, `ya29.…`, `AIza…`, JWTs, `bearer X`, Slack webhook URLs | `secretPatterns` |
| An assignment to a credential name, `=` or `:` | `SECRET_KEY=X`, `api_key: X`, `"api_key": X` | `RedactAssignments`, `CredentialName` |
| A YAML block scalar, nested mapping, or comment gap under a credential name, as a whole | `api_key: \|-` then `  X`, `token:` then `  "pw":X`, `token: # secret` then `  X` | `redactColonAssignments` (`blockScalarHeader`, `nestedMappingStart`, `commentGapStart`) |
| A YAML value that continues on later lines: a quoted scalar that closes later, or a more-indented line after the value, a comment, or a commented-out key | `token: "q" # c` then `  X`, `token: "abc` then `  X"`, `# token: # c` then `  X` | `redactColonAssignments` (`valueContinuation`, `multilineQuotedValue`, `commentHeadBodyEnd`) |
| The word `password` or `passwd` and the word after it (netrc) | `machine h login u password X`, `setup password X` | `RedactToolFlags` (`redactPasswordWords`) |
| `-p X` in a command that also names a user (`-u`, `-U`, `-l`, `--user`, `--username`, `--login`, or a `login` subcommand), for any tool. A value containing `:` is redacted too, except a port on `docker run` or `podman run` (including `container run`) | `docker login -u bot -p X`, `regcli --user bot -p deadbeef:22`, `ssh -l alice -p deadbeef:22` | `RedactToolFlags` (`redactUserContextPassword`) |

A shell line continuation (`\` and a newline) between a flag, a header,
or `bearer` and its value is skipped, as the shell deletes it. A value
whose quotes are themselves escaped (`echo "token: \"X\""`,
`TOKEN=\"X\"`, `--password \"X\"`) is read as one value, quotes kept
around `[REDACTED]`. The pair does not cross a newline.

A credential name's value may start on the next line. If that line is
a key, the more-indented lines are a nested mapping and are redacted
as one. An unquoted key needs a space, tab, CR, LF, or the end of the
text after its colon, so a glued `sk:X` or a URL stays the outer key's
own plain scalar. A quoted key is a key even when its value is glued
on (`"pw":X`). A `#` comment between the key and a more-indented value
(`token: # secret` then `  X`, or a comment line between them) is
part of the credential value: the redaction begins at the value start,
including the header and every gap comment, and replaces the whole
span through the indented body with one marker. A `#` with nothing
indented after it is the value itself.

A key that starts its line (after blanks and `- `) also owns the
more-indented lines after its value: `token: "q" # c` followed by
`  X` redacts `X`, and a quoted scalar is read with YAML's rules (a
`\"` or a `''` does not close it) through a closing quote on a later
line. A key inside a shell command keeps the text after it. A
commented-out key whose header comment is followed by content redacts
the first content line and the lines indented deeper than it, since
the original key's indentation is unknown. `-p X` is not redacted
without a user in the command, so `mkdir -p`, `cp -p`, `ssh -p 22`,
`useradd -p HASH`, and `docker run -p 8080:80` keep their value. A
value that contains `:` stays only for `docker run` and `podman run`,
including `docker container run` and `podman container run`
(`docker run -u 1000 -p 8080:80`). Any other command that names a user
redacts `-p` even when the value contains `:`, so
`ssh -l alice -p deadbeef:22` does not pass as a port, and
`ssh -l alice -p 22` is redacted too. `password` matches only as a
whole word: `--password-stdin`,
`db_password`, and `password: x` are other classes. The word after
`password` in free text (`echo password reset`) is redacted too: a
hidden word costs less than a leaked password.

The home directory classes (S5 to S7) are not redactor patterns but path
folding: the running user's home directory is shown as `~` in every
error (`foldHome` in `cmd/tripcord`, matched case-insensitively on
Windows, with or without a trailing separator), user-scope locations are
shown under `~/`, and a managed policy permission error, which names the
resolved file behind a symlink, is folded the same way.

Adapters also redact at the source (`kit.Source.Sanitize`, and
`output.RedactCommand` in the Claude adapter), so findings, evidence
keys, and fingerprints are built from sanitized text. An entry that
lost a value to redaction carries a `sig:` discriminator, so two
different secrets in the same place keep distinct fingerprints
(`fingerprintMode` `s1` or `k1`; see [fingerprint.md](fingerprint.md)).
Every sink then redacts again, in `redactFinding`, the one function
every sink and `output.PublishFinding` publish a finding through. An
evidence key is a JSON array that includes the entry's command, and
JSON escaping (`\n`, `\"`, `\u`) hides what the redactor keys on, so
`redactFinding` decodes a key that is JSON, redacts each string in it as
plain text, and encodes it again only when one changed. A test fills
every plain string field of a finding with a sentinel and fails when
`redactFinding` or `PublishFinding` leaves it, so a field added without
redaction cannot ship.

## Output inventory

Caps are in bytes and include the truncation marker. "Message" is
`output.Message`: the redactor, then a cut at 4096 bytes on a UTF-8
boundary, line breaks kept. "Field" is the redactor, the sink's escaping,
then a cut at 1024 bytes (`MaxFieldBytes`).

| Surface | Redaction point | Cap |
| --- | --- | --- |
| `scan --format text` | `output.sink.Write` (`redactFinding`, every finding string), `sink.SetDiagnostics`; `renderText` escapes each field with `present` | field |
| `scan --format json` / `jsonl` | `redactFinding`; `renderJSONL` applies `capFinding` to every finding string and caps each diagnostic field | field |
| `scan --format sarif`: result `message.text` | `redactFinding`; `sarifText` (escapes controls and `[` `]`) | field per part |
| `scan --format sarif`: `properties.tripcord`, `partialFingerprints` | `redactFinding`; scope and path from the capped location; fingerprint is a hash | field |
| `scan --format sarif`: rule text, notifications | catalog text through `sarifText`; diagnostics through `sink.SetDiagnostics` and `sarifText` | field |
| `scan --format gha` annotations | `redactFinding`; `ghaData` and `ghaProperty` encode `%`, CR, LF (and `:` `,` in properties), then `truncateGHA` | field |
| `scan --format md` (the PR comment body) | `redactFinding`; `markdownValue`, `inlineCode`, `fencedCode` escape controls and break `@` mentions | field, and 60000 for the comment (`MaxMarkdownBytes`) |
| PR comment artifact (the action's `--format md --output` file, posted by `github-script`) | the same Markdown sink, written by `publishSink` | as Markdown |
| Code scanning upload (the action's `--format sarif --output` file) | the same SARIF sink | as SARIF |
| Job summary | none: v0 never writes `GITHUB_STEP_SUMMARY` | - |
| `scan` diagnostics on stderr | `output.TerminalLine` (redactor, then one escaped line) | field |
| `scan` and other CLI errors on stderr | `errorText` = `output.Message(foldHome(err))`; `scanTarget.redactError` also replaces a `--staged` temporary tree path with `.`; Git stderr through `sanitizeGitStderr` and `gitrun.Sanitize` (redactor before the cut) | message (Git stderr 1024 before it) |
| Unknown command error (`tripcord <argv>`) | `output.Message(foldHome(args[0]))` on the raw argument, then quoted: quoting first would turn a line continuation into a literal `\n` the redactor no longer sees | message |
| `scan` path that does not exist | `scanRoot` names the argument as given, through `output.Message(foldHome())`, then quoted, not the cleaned absolute path, whose `://` `filepath.Abs` turns into `:/`; then `scanTarget.redactError` | message |
| `tripcord hook`, Claude Code: stdout `permissionDecisionReason` / `systemMessage`, stderr reason | `hookReason` (`output.Message(foldHome(reason))`) for a decision; `hookFailure` (`errorText`) for a failure | message |
| `tripcord hook`, Cursor: stdout `user_message` / `agent_message`, stderr reason | the same | message |
| `tripcord hook`, Copilot: stderr reason or warning | the same | message |
| Deny reason from a custom rule `message` | `hookReason`. `message` is static policy text: v0 has no interpolation of event fields | message |
| Echoed command, `tool_input`, or path | none echoed: no hook output carries the event, its command, `tool_input`, or paths. An input error names the field (`hook_event_name is not PreToolUse`), not its value | - |
| Policy or CEL error (syntax, type check, evaluation, such as a `matches` error that quotes the event value) | `hookFailure` / `errorText` | message |
| Exit-4 panic (`hook`, and every other command through `run`) | the panic value is dropped: `tripcord: internal error` or `tripcord hook: internal error` (`tripcord hook failed closed: internal error` under `--on-failure block`). No stack, no event, no environment | fixed text |
| `init` progress and errors | `errorText` | message |
| `init` path (missing, not a directory, inside a repository, or `--embed` with no `.git`) | `initRoot` and the `--embed` check name the argument as given, through `output.Message(foldHome())`, then quoted, not the cleaned absolute path, whose `://` `filepath.Abs` turns into `:/` | message |
| `init --dry-run` diff | `output.PreviewLines`: each JSON string decoded, redacted, and re-encoded (`RedactJSONText`), then the redactor over the text; each line escaped when it holds a control, bidi, or invalid byte | field per line |
| `preopen` (scan output and errors) | the scan sinks; the target URL and Git stderr through `errorText` and `gitrun.Sanitize` | as scan, message |
| pre-commit (`scan --staged`) | the scan sinks and errors above | as scan |
| `pr-context` text, json, gha, and `GITHUB_OUTPUT` | `publishedPrContext`: every signal value and source, warning, outcome reason and path through `output.Message(foldHome())`, the TC-CFG-014 finding through `output.PublishFinding`; `GITHUB_OUTPUT` carries only `is_agent` and validated agent ids | message, field |
| Git notes report (`refs/notes/ai` signals in `pr-context`) | tripcord only reads notes; tool ids are kept only when `validTool` accepts them (64 bytes at most), then `publishedPrContext` | 64 |
| `bootstrap.sh` errors on stderr | `fail` prints fixed text with the home directory folded to `~` (`fold_home`); no event, environment value, or command is printed | fixed text and a path |
| `--verbose` / `--debug` logs | none: v0 has neither flag | - |
| Events | never emitted: an event exists only as the CEL input of the hook's rules (`rules.EventInput`); its `redactions` field is always `0` in v0, since the event is that unredacted CEL input and is never itself written to any output (see the schema's `redactions` description) | - |

## What is persisted

Nothing from an event or an excerpt. `scan` writes only the report it
was asked for (stdout or `--output`) and, outside CI, the per-machine
fingerprint key (`~/.tripcord/fingerprint.key`). `scan --staged`
removes its temporary tree, and `preopen` its clone. The hook writes
nothing. `bootstrap.sh` `install` and `session-start`, and a `hook`
that has not been verified yet, run a private copy of the binary from
the cache's `.run` directory and remove it. A later `hook` whose
verification record still matches runs the cached file and does not
write. The record is the file's identity and the pinned digest, written
by `install`, `session-start`, or that first hook. `init` writes only
its wiring and merges into existing settings files, keeping the user's
own content.

## `privacy.redact`

`privacy.redact` is reserved, and always on in v0: every surface above
redacts regardless of what a policy sets. The key is still parsed
(`policy.Privacy.Redact`) and merged into `policy.Effective.Redact`
with its provenance, default `true`, so a v1 that honors it does not
need a new key and a policy already carrying `redact: false` for that
future release does not fail validation now.

`scan` and `init` each warn once, to stderr and never to stdout, when
the policy they load (or, for `init`, the `.tripcord/policy.yaml` they
read or write) sets `redact: false`: `privacy.redact is false in
<file>, but v0 always redacts; the key is reserved for a later release
and has no effect`. `<file>` is the repo or org policy file that set
it (`policy.Effective.Provenance["privacy.redact"].Source` for `scan`).
`tripcord hook` does not warn: each run is a fresh process deciding one
tool call, so any warning there would be once per tool call, not once
per run, and stdout there is a harness's own structured output, which
the warning must never join (`warnRedactFalse` in `cmd/tripcord`).

## Known limits

- A token shape split by a raw newline is not reassembled: each half is
  shown if it no longer matches the shape on its own.
- Base64 and URL-encoded forms of a credential are not decoded, except
  percent-encoded URL userinfo.
- A credential with no credential name, flag, or known shape, such as a
  bare positional argument, is not recognized.

## Tests

`cmd/tripcord/redaction_canary_test.go` is the gate: one canary per
class above, written plainly, fully `\u`-escaped, and split by a JSON
escape, in config files, in the command, path, and URL of every hook
harness, in custom rule messages and policy errors, in a panic, in an
unknown command, as a scan path argument, and as an init path argument.
No canary may appear in any output format, every finding's fingerprint
must, and
`redact: false` changes nothing. `internal/output`'s
`TestRedactionScalesLinearly` and `TestBlockScalarCandidatesScaleLinearly`,
and `TestDiscoverHookHeavyBudget` in the CI perf job, hold redaction to
linear cost on long lines of near-miss candidates.
`cmd/tripcord/redaction_persist_unix_test.go` checks that scan, the hook
through `bootstrap.sh`, and init leave no canary in the repository,
`HOME`, the cache, or `TMPDIR`, and an empty `.run` directory. The
verification record in the cache is the file identity and the pinned
digest, not an event.
