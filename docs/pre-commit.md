# Pre-commit hook

Tripcord ships the `tripcord-config` hook for
[pre-commit](https://pre-commit.com/). It requires Go 1.27.3 or newer,
the minimum version in this repository's `go.mod`.

```yaml
repos:
  - repo: https://github.com/vgmartinez/tripcord
    rev: 277066a292b8717d4d91393a10d00c5dd2d51cdb # main@277066a
    hooks:
      - id: tripcord-config
```

The hook runs `tripcord scan --staged`. It builds a private temporary tree
from the Git index: partially staged files use their staged contents, and an
unstaged-only edit does not affect the decision. Symlinks are preserved and
resolved under that temporary tree. A staged deletion produces no finding at
its own path, but it can still surface a finding elsewhere whose source set
names the deleted file; see the source-set bullets below.

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

An interrupt during materialization closes the temporary tree and exits 3
with the bypass line below.

The hook's manifest sets `pass_filenames: true`, `always_run: true`, and
`require_serial: true`. `pass_filenames` stays on so `pre-commit run
--all-files` and `pre-commit run --from-ref FROM --to-ref TO` — the way
pre-commit.ci and other CI run hooks, when nothing is staged — pass the
files they are reviewing. With `pass_filenames: false` those commands
invoked the hook with no paths and an empty index, and the scan reported
nothing. `always_run` keeps the hook from being skipped when no filename is
passed. A deletion looks like that: pre-commit requires the path to exist,
so a deleted file is never a filename, and the hook would otherwise print
`(no files to check) Skipped`.

`tripcord scan --staged` reports findings against the **union** of the
paths it was given and the staged change set from
`git diff-index --cached --name-status -z --no-renames`, diffed against
`HEAD` (or, on a repository's first commit, the empty tree). That change
set covers every added, modified, deleted, type-changed (for example a
symlink retarget), and mode-changed path in the proposed commit. A commit
with nothing staged and no paths reports nothing. Passing paths does not
replace the diff-index set; it adds to it. pre-commit may split a large
changeset into several hook invocations ("batches") of file paths. Every
batch unions the same diff-index set, so a finding whose staged path landed
in a different batch is still reported, and the same finding can be printed
more than once. That duplication is harmless: any reported finding blocks
the commit.

`types` is `[]` and `types_or` is `[file, symlink]`. `types` is an AND
filter, and its default `[file]` would exclude every symlink: identify tags
a symlink `symlink`, not `file`, so a path is never both. An empty `types`
list matches every tag, and `types_or` then keeps a regular file or a
symlink. `types: [file, symlink]` would match nothing, because that list
still requires every tag. Under `--all-files`, a symlink path is therefore
passed, including one whose target is outside the repository or not a
tracked file. When the target is outside the repository, the target is not
read and the hook exits 3 with `symlink resolves outside the repository`,
the same result `tripcord scan --staged` reports for that symlink. A
deletion is still absent from the filenames; the diff-index change set, or
the from-ref/to-ref diff, supplies it.

The hook reports a finding when any file in that finding's **source set** is
in the change set, not only when the finding's own location changed. A
finding's source set is the union of:

- the file the finding is located in, whether or not that path still exists
  in the proposed commit (a staged deletion is itself in the change set, so
  a finding whose location is a file the commit deletes — a TC-CFG-009
  checksum file that was covering a download, or a TC-CFG-006 hook script a
  commit no longer provides — is still reported);
- every file in that file's symlink chain;
- for a finding read through a manifest (such as a Claude plugin manifest),
  the manifest itself and every file it references by path, whether or not
  the referenced file exists;
- the hook or skill scripts, and TC-CFG-009 checksum files, a rule reads to
  produce the finding, named whether or not they exist;
- for a Claude plugin, every hook, skill, agent, and command file discovered
  under that plugin's root by convention (`hooks/hooks.json`,
  `skills/*/SKILL.md`, `agents/*.md`, `commands/*.md`), and the plugin's
  marketplace entry if one names its root. Those convention files may already
  be committed from an earlier commit; staging only the plugin manifest (or
  only a marketplace entry that first names an existing plugin root) still
  reports every finding those already-committed files produce, because the
  manifest is part of their source set too.

This means editing only `cfg/servers.json` reports a finding located in the
manifest that references it, retargeting only a symlink reports a finding
located at the symlink path, deleting only a checksum file reports the
finding it was covering, and adding only a plugin manifest reports every
finding its already-committed hooks, skills, agents, and commands produce.

When `PRE_COMMIT_FROM_REF` and `PRE_COMMIT_TO_REF` are both set
(`pre-commit run --from-ref` / `--to-ref`, which is how pre-commit.ci
invokes hooks), the change set also includes
`git diff --name-status -z --no-renames FROM...TO`. That is the three-dot
form pre-commit 4.7.0 uses in `get_changed_files`: changes on `TO` since
the merge base with `FROM`. If that diff fails — newer git does this when
the two revisions have no merge base — the hook retries `FROM..TO`, the
same fallback pre-commit uses. Deletions in the range are in that diff
even though pre-commit does not pass a path that no longer exists. In this
mode the scan reads the working tree, which is the checkout pre-commit
left at `TO`, and not the Git index.

Any reported finding blocks the commit, including one that was already present
in an edited config file. This deliberately fails closed; filtering for only
new findings is a follow-up.

An incomplete scan (exit 3) or internal failure (exit 4) also blocks the
commit. Fix the problem and rerun the hook. The emergency bypass is
`git commit --no-verify`.

## What the hook does not cover

Git does not invoke the `pre-commit` hook for a merge that completes without
a conflict (a clean merge or a fast-forward). A merge that introduces an
unsafe configuration change through either side, with no conflicting hunk on
the affected file, lands with that hook never having run. To scan a merge
that creates a commit, including one with no conflicts, also install
pre-commit's `pre-merge-commit` stage:

```sh
pre-commit install --hook-type pre-merge-commit
```

Git runs `pre-merge-commit` after the merge has been carried out and before
it creates the merge commit. A non-zero status from this hook aborts that
commit. The manifest does not set `stages`, so the hook runs in
`pre-merge-commit` once that hook type is installed. A fast-forward that
does not create a commit still does not run it. CI's scan of the merged
tree is the backstop wherever the stage is not installed.

The repository walk stops after 200,000 directory entries, the same cap as
a checkout scan. Past that limit the scan is incomplete and exits 3, so
this hook blocks every commit in a repository that large, including a
commit that does not touch configuration. Skip the hook there
(`SKIP=tripcord-config`, or leave it out of `.pre-commit-config.yaml`).
`tripcord scan` of a path inside a Git repository starts at that
repository's root and hits the same cap, so a tree that large has to be
scanned as its own checkout, not as a subdirectory of a bigger one.

A commit that only changes a `.tripcord` policy file (an exception, a
severity override, a scope change) and touches no configuration file can
report no findings even though it changes what a later commit will be
allowed to introduce. This is intentional, not a gap: policy review is a
different concern from configuration review, and the hook evaluates the
proposed commit as it stands, not a hypothetical future one under the new
policy. Review changes to `.tripcord` policy files the same way you would
review any other change to what the scanner is allowed to pass.
