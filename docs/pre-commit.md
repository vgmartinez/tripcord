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

The hook's manifest sets `pass_filenames: false` and `always_run: true`:
pre-commit invokes `tripcord scan --staged` on every commit with no file
arguments at all, regardless of which paths changed or what kind of change
they are. This matters because pre-commit's own default file-type filtering
(`types: [file]`) would otherwise skip a commit that only retargets a
symlink or only deletes a file — pre-commit reports `(no files to check)
Skipped` for those without ever invoking the hook. With no paths given, the
hook computes its own staged change set directly from the Git index, with
`git diff-index --cached --name-status -z --no-renames` diffed against
`HEAD` (or, on a repository's first commit, the empty tree). That change set
covers every added, modified, deleted, type-changed (for example a symlink
retarget), and mode-changed path in the proposed commit. Passing explicit
paths to `tripcord scan --staged` still works, for direct or manual use
outside pre-commit; given paths replace the self-computed change set instead
of extending it.

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
With `pass_filenames: false`, pre-commit invokes the hook exactly once per
commit with no arguments, instead of batching file paths across several
invocations the way a `pass_filenames: true` hook would; `tripcord scan
--staged` always sees the whole proposed commit's self-computed change set
in that one invocation.

Any reported finding blocks the commit, including one that was already present
in an edited config file. This deliberately fails closed; filtering for only
new findings is a follow-up.

An incomplete scan (exit 3) or internal failure (exit 4) also blocks the
commit. Fix the problem and rerun the hook. The emergency bypass is
`git commit --no-verify`.

## What the hook does not cover

Git does not invoke any local hook, including `pre-commit`, for a merge that
completes without a conflict (a clean merge or a fast-forward). A merge that
introduces an unsafe configuration change through either side, with no
conflicting hunk on the affected file, lands with the pre-commit hook never
having run. CI's own scan of the merged tree is the backstop for that case,
not this hook.

A commit that only changes a `.tripcord` policy file (an exception, a
severity override, a scope change) and touches no configuration file can
report no findings even though it changes what a later commit will be
allowed to introduce. This is intentional, not a gap: policy review is a
different concern from configuration review, and the hook evaluates the
proposed commit as it stands, not a hypothetical future one under the new
policy. Review changes to `.tripcord` policy files the same way you would
review any other change to what the scanner is allowed to pass.
