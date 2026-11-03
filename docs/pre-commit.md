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
from the Git index: partially staged files use their staged contents, staged
deletions produce no findings, and an unstaged-only edit does not affect the
decision. Symlinks are preserved and resolved under that temporary tree.

The tree holds the paths a repository scan opens, under the same file, byte,
and walk caps as that scan: adapter discovery files, `.tripcord` policy and
review files (including files an in-repo `extends` chain names), hook and
skill scripts and TC-CFG-009 checksum files those rules follow, and symlink
targets inside the repository. A gitlink is an empty directory, matching an
uninitialized submodule in a checkout scan. A path the index does not contain
is missing, the same result as a scan of a checkout of that commit. Staged
policies, approval exceptions, review data, skill hook scripts, and setup
links are read from that same proposed commit, so an approval added in the
commit applies to that commit's finding.

`tripcord scan --staged` with no paths exits 3 and reports
`--staged needs the staged file paths (pre-commit passes them)`. After the
tree is materialized, an interrupt closes it and exits 3 with the bypass
line below.

The hook reports only findings located in the files pre-commit passes to it.
Any reported finding blocks the commit, including one that was already present
in an edited config file. This deliberately fails closed; filtering for only
new findings is a follow-up.

An incomplete scan (exit 3) or internal failure (exit 4) also blocks the
commit. Fix the problem and rerun the hook. The emergency bypass is
`git commit --no-verify`.
