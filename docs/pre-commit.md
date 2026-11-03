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

The hook has no `files:` regex and runs on every commit (`always_run: false`
with `pass_filenames: true`): Tripcord, not a path pattern, decides what
counts as configuration. A config file can be discovered only by its content
(for example a Claude plugin manifest's `"mcpServers": "./cfg/servers.json"`
reference) or by a symlink target, so a regex over paths would miss both the
file that introduces a finding and the file pre-commit needs to pass for the
hook to report it.

The hook reports a finding when any file in that finding's **source set** is
among the paths pre-commit passes to it, not only when the finding's own
location is passed. A finding's source set is the union of:

- the file the finding is located in;
- every file in that file's symlink chain;
- for a finding read through a manifest (such as a Claude plugin manifest),
  the manifest itself and every file it references by path;
- the hook or skill scripts, and TC-CFG-009 checksum files, a rule reads to
  produce the finding.

This means editing only `cfg/servers.json` reports a finding located in the
manifest that references it, and editing only a symlink's target reports a
finding located at the symlink path. pre-commit may split a large changeset
into several hook invocations ("batches") of file paths; each invocation
scans the same full proposed commit and applies this same source-set check
against only the paths in its own batch, so a finding is reported in
whichever batch's paths intersect its source set, and not duplicated across
batches that don't.

Any reported finding blocks the commit, including one that was already present
in an edited config file. This deliberately fails closed; filtering for only
new findings is a follow-up.

An incomplete scan (exit 3) or internal failure (exit 4) also blocks the
commit. Fix the problem and rerun the hook. The emergency bypass is
`git commit --no-verify`.
