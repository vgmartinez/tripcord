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
| hook | `warn` | none |

Fail-on is inclusive. `high` fails the run (exit 1) for a high or
critical finding and lets low and medium through. The hook default has
no fail-on: it shows findings and does not block, including on high and
critical.

## What overrides them

A policy layer that sets `mode` or `fail-on` replaces the surface
default. A layer that omits one of them leaves that one at the default,
so a repo can change the mode and keep fail-on `high`.

```yaml
version: 1
mode: audit
fail-on: critical    # low | medium | high | critical
```

`fail-on` uses the same four severities as a finding. The hook honors
an explicit `mode: enforce` or `fail-on: high` the same way a scan does.

`locked.mode` still applies. A lock with no explicit mode locks the
surface default: `enforce` on a scan, `warn` on the hook. A later layer
can tighten that floor and cannot weaken it. `fail-on` is not locked.

## Layers

The org policy comes from the managed file and from files passed in
explicitly. The repository does not control those. What
`.tripcord/policy.yaml` extends is a later layer, then the repo file,
then `.tripcord/policy.local.yaml`. See the `policy` package docs for
locks on rules, exceptions, packs, and harnesses.
