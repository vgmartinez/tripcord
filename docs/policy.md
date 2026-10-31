# Policy defaults

`internal/policy` merges policy layers and picks the mode and fail-on
for the surface that is about to run. The CLI commands consume that
result; they are not in this change.

## Surfaces

`DefaultsFor` is the only place the no-policy defaults are defined. The
surfaces are `scan`, `preopen`, `pr-context`, `action`, and `hook`.

| Surface | Mode | Fail-on |
| --- | --- | --- |
| scan, preopen, pr-context, action | `enforce` | `high` |
| hook | `warn` | `high` |

A finding blocks the run (exit 1, or a hook block) only when mode is
`enforce` and the finding's severity is at or above fail-on. `audit`
and `warn` never block, on any surface, whatever fail-on is set to.
Fail-on is inclusive: `high` blocks on a high or critical finding and
lets low and medium through. The hook defaults to `warn`, so it shows
findings, including high and critical, without blocking; an explicit
policy or an org lock that raises it to `enforce` then blocks on high
and critical using that same default fail-on.

## What overrides them

A policy layer that sets `mode` or `fail-on` replaces the surface
default. A layer that omits one of them leaves that one at the default,
so a repo can change the mode and keep fail-on `high`.

For `tripcord scan`, `--fail-on` is an invocation-level threshold applied
after the policy is loaded. It uses the same ceiling as a policy layer.
When mode is locked, the flag may only tighten fail-on (`high` to
`medium`). Loosening it (`medium` to `critical`) is rejected with exit
3. Policy mode still decides whether findings can fail the command.

```yaml
version: 1
mode: audit
fail-on: critical    # low | medium | high | critical
```

`fail-on` uses the same four severities as a finding. Setting `fail-on`
alone does nothing on the hook unless `mode` is also `enforce`, since
`warn` never blocks.

`locked.mode` still applies. A lock with no explicit mode locks the
surface default: `enforce` on a scan, `warn` on the hook. A later layer
can tighten that floor and cannot weaken it.

Locking `mode` also locks `fail-on` to a ceiling: the value in effect
when the mode was locked. A later layer may lower it, stricter (`high`
to `medium`), but raising it, weaker (`high` to `critical`), is
rejected with exit 3, the same as a mode that tries to weaken a lock.

## Layers

The org policy comes from the managed file and from files passed in
explicitly. The repository does not control those. What
`.tripcord/policy.yaml` extends is a later layer, then the repo file,
then `.tripcord/policy.local.yaml`. See the `policy` package docs for
locks on rules, exceptions, packs, and harnesses.
