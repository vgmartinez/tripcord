# Documentation

Design notes for this private pre-release.

## Finding fingerprints

[fingerprint.md](fingerprint.md) defines the canonical finding fingerprint.
The digest is stable across versions. Golden tests lock it.

## Repository identity

The GitHub owner and repository name are defined in one place: `Repository`
in `internal/project`.

The module path in `go.mod` is the import path (`github.com/` plus that
constant). A test checks that the two stay in sync. To move the project to
another owner, change those two and leave every other file alone.
