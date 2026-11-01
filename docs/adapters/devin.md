# Devin adapter

The Devin adapter (harness `devin`) discovers a git-backed Devin
blueprint statically. It never runs a command, starts a build, syncs a
blueprint, or invokes git. Every repository file is treated as
attacker-controlled.

`.devin/hooks.json` stays on the [Windsurf](windsurf.md) adapter.

## Locations

Repository scope only (`--scope repo`, the default). There is no user
or managed blueprint file.

| Location | Normalized kinds |
| --- | --- |
| `.devin/blueprint.yaml` (any depth) | `env-setup`, `instructions` |

Path matching is case-insensitive. A blueprint in a subdirectory is
read when its path ends in `.devin/blueprint.yaml`.

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, and, when sanitizing removed anything, a
[secret discriminator](../fingerprint.md#secret-discriminator) (`sig:k1:` with a
fingerprint key, `sig:s1:` without one); see
[fingerprint.md](../fingerprint.md#input).

- `initialize` and `maintenance`. One `env-setup` item per command.
  A string section is one command (`form: string`, `command` the
  text). A list entry that is a string is the same. A mapping with
  `run` is one command (`form: run`, plus `name` when set). The item's
  line is the command's line in the file. Rules read `command` as
  written; the payload is sanitized.
- `uses`. A mapping with `uses` is one `env-setup` item (`form: uses`,
  `uses`, and `with` when set). It is not a shell command, so
  TC-CFG-009 does not read it.
- Maintenance text and `knowledge` `contents`. One `instructions` item
  per string (`role` `maintenance` or `knowledge`, `content` the
  text). The doc surfaces maintenance commands and loads knowledge
  into the agent's context. `initialize` is documented as build-only,
  so its text is not an instruction item. Hidden code points in the
  surfaced text are located for TC-CFG-011. Maintenance text stays
  shell input: TC-CFG-012 reads only the `knowledge` items.

A blueprint that is not one YAML mapping, or a section whose shape is
not a string or a list, is reported and does not stop the rest of the
scan.

## Not scanned in v0

- `post-build`, `clone`, and any other key.
- Multi-document YAML (`---`). The decoder reports it as not one
  document.
- `.devin/hooks.json` and the rest of Devin Local configuration.

## Sources

- [Devin environment blueprints](https://docs.devin.ai/onboard-devin/environment/blueprints)
