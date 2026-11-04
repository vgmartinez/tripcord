# Versioned adapter fixtures

Each subdirectory is one harness release. It holds that release's
fixture archives (`repo.txtar`, and `home.txtar`, `managed.txtar`, or
`policy.txtar` when that scope is part of the fixture) and
`discover.golden`.

No release version is recorded for the fixtures that were already here,
so the current directory is named `windsurf-baseline`.

A new harness version adds a directory. Do not edit an existing one.

`discover.golden` is regenerated only with:

    go test ./internal/adapters/... -update

Without `-update`, a golden diff fails the test.
