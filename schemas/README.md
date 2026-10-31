# Schemas

JSON Schema for Tripcord records. SPDX-License-Identifier: Apache-2.0.
The repository license covers these files.

| File | Schema | `$id` |
| --- | --- | --- |
| `tripcord.event.v1.schema.json` | `tripcord.event/v1` | `https://schemas.tripcord.invalid/tripcord.event/v1` |
| `tripcord.finding.v1.schema.json` | `tripcord.finding/v1` | `https://schemas.tripcord.invalid/tripcord.finding/v1` |
| `tripcord.session.v1.schema.json` | `tripcord.session/v1` | `https://schemas.tripcord.invalid/tripcord.session/v1` |

The `schema` column is the document's own self-declared `"schema"` field
value (for example, every event carries `"schema": "tripcord.event/v1"`).
`$id` is the separate JSON-Schema identifier a validator (this repo's own
test validator, or an external one like ajv or check-jsonschema) uses to
resolve `$ref`; `tripcord.session.v1.schema.json`'s `events[].$ref` points
at the event schema's `$id`. `$id` must be a syntactically absolute URI
for `$ref` resolution to work reliably. It uses the `.invalid` TLD
(reserved for this purpose by RFC 2606) because the value only needs to
identify the schema, not resolve over the network, and the project does
not control a real `tripcord.*` domain.

Dialect: JSON Schema 2020-12.

## Objects are open

Every object in these schemas sets `additionalProperties: true`
(equivalently, omits the keyword). A reader must ignore a property it
does not recognize. This is what makes "adding an optional property"
below a safe, additive v1.x change: a document from a newer minor
version still validates against an older reader's copy of the schema,
and vice versa. `schemas/compat_test.go`'s `TestSchemaObjectsStayOpen`
walks every schema file and fails the build if any object node sets
`additionalProperties: false`, so this stays true going forward.

## Compatibility

`schemas/testdata/baseline/` holds the accepted copy of each v1 schema.
`schemas/compat_test.go` compares the current files with that baseline.
A change to these files, or to `schemas/testdata/baseline/`, needs
review from the owner named in `.github/CODEOWNERS`, since merging a
baseline change is what freezes the next contributor's floor.

A v1 schema may only change additively. The test fails when a change:

- removes or renames a property
- changes a type, `const`, `pattern`, or `format`
- adds a required field, or starts requiring a field that was optional
- narrows an enum or a type union
- tightens a numeric, length, or array bound
- closes `additionalProperties` that were open
- changes `$id` or `$schema`

Breaking changes require a new schema, for example `tripcord.event/v2`,
in a new file with its own baseline. Leave the v1 file and its baseline
compatible.

Allowed on v1:

- add an optional property
- add an enum value or a type alternative
- relax or remove a bound, pattern, or format
- stop requiring a field
- edit `title`, `description`, or `$comment`

When you make an allowed change, replace the matching file under
`schemas/testdata/baseline/` in the same change. The baseline is the
floor for the next edit. If you skip that copy, a later removal of the
new optional property is not detected.

Dropping a constraint such as `items` or `minLength` is treated as a
relaxation and is allowed. Replacing `additionalProperties: false` with
a schema is rejected, because that is not a plain relaxation.

## Minimal required fields

`tripcord.event/v1` requires only `schema`, `id`, `ts`, `source.harness`,
`session.id`, and `kind`. Everything else (`tool`, `command`, `paths`,
`net`, `credentials`, `redactions`, `raw_ref`, `source.surface`,
`source.version`, `source.origin`, and `session.repo` / `branch` /
`actor` / `parent`) is optional, so a minimal local event — for example,
one from a session outside a git repository, with no corresponding
branch or actor to report — still validates.

## What this schema cannot express

`tripcord.finding/v1`'s `evidence` items cite exactly one of `event` (an
`Event.id`) or `config` (a `ConfigItem.id`), per the spec's "findings
reference events or config by id." This project's hand-written test
validator (`internal/model/schema_validate_test.go`) supports a
deliberately small keyword subset and does not implement `oneOf`, so
this schema cannot express "exactly one of two properties is set." That
rule is enforced in Go, by `Finding.Validate` in `internal/model`, not
by this JSON Schema. A general-purpose validator (ajv,
check-jsonschema) checking only this schema will accept a finding with
both `event` and `config`, or with neither; Tripcord's own code will
not.
