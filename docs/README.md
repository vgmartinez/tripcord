# Documentation

Design notes will be added here. This repository is a private pre-release.

## Repository identity

The GitHub owner and repository name are defined in one place: `Repository`
in `internal/project`.

The module path in `go.mod` is the import path (`github.com/` plus that
constant). A test checks that the two stay in sync. To move the project to
another owner, change those two and leave every other file alone.
