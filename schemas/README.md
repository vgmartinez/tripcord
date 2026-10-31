# Schemas

JSON Schema for Tripcord records. SPDX-License-Identifier: Apache-2.0.
The repository license covers these files.

| File | Schema |
| --- | --- |
| `tripcord.event.v1.schema.json` | `tripcord.event/v1` |
| `tripcord.finding.v1.schema.json` | `tripcord.finding/v1` |
| `tripcord.session.v1.schema.json` | `tripcord.session/v1` |

Dialect: JSON Schema 2020-12.

## Compatibility

`schemas/testdata/baseline/` holds the accepted copy of each v1 schema.
`schemas/compat_test.go` compares the current files with that baseline.

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
