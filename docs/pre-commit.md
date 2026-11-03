# Pre-commit hook

Tripcord ships the `tripcord-config` hook for
[pre-commit](https://pre-commit.com/). It requires Go 1.27.3 or newer,
the minimum version in this repository's `go.mod`.

```yaml
repos:
  - repo: https://github.com/vgmartinez/tripcord
    rev: 6944e28af57eeb613172555ed62827b240960249 # main@6944e28
    hooks:
      - id: tripcord-config
```

The hook runs `tripcord scan --staged`. It builds a private temporary tree
from the Git index, not the working tree: partially staged files use their
staged contents, staged deletions produce no findings, and an unstaged-only
edit does not affect the decision. Symlinks are preserved and resolved under
that temporary tree.

All index files are materialized because rules can cross file boundaries.
For example, staged policies, approval exceptions, review data, skill hook
scripts, and setup links are read from the same proposed commit. An approval
added in the same commit applies to that commit's finding.

The hook reports only findings located in the files pre-commit passes to it.
Any reported finding blocks the commit, including one that was already present
in an edited config file. This deliberately fails closed; filtering for only
new findings is a follow-up.

An incomplete scan (exit 3) or internal failure (exit 4) also blocks the
commit. Fix the problem and rerun the hook. The emergency bypass is
`git commit --no-verify`.
