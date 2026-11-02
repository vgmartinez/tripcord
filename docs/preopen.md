# `tripcord preopen`

`tripcord preopen <git-url|path>` fetches a repository into a private
temporary directory without running anything the repository controls,
scans it exactly as [`tripcord scan`](scan.md) would, and removes the
directory. Use it before opening an unfamiliar repository in an editor or a
coding agent: a normal clone and checkout can already run code through Git
hooks, `.gitattributes` filter drivers, Git LFS, and submodules.

The target is an `https://`, `ssh://`, or `file://` URL, an scp-style ssh
address (`git@host:owner/repo.git`), or a local directory. A local directory
is cloned through the `file://` transport like any other repository, so the
scan sees its latest commit and never reads the working tree in place;
uncommitted changes are not scanned.

## What is fetched, and how

1. `git clone --bare --depth 1 --single-branch --no-tags --template=` into
   `tripcord-preopen-*` under the system temporary directory. A bare clone
   has no work tree, so nothing is checked out: no smudge, clean, or process
   filter runs, no `post-checkout` hook fires, and no submodule is cloned.
2. The `HEAD` tree is written out with `git ls-tree -r -z` and
   `git cat-file --batch`. Those commands return raw object bytes and never
   consult `.gitattributes`, so even a filter driver the repository names
   cannot run. `git archive` is not used, because `export-ignore` attributes
   in the repository could hide configuration files from the scan.
   Submodules become empty directories, as in a checkout that did not
   initialize them. Symlinks are recreated as symlinks and are not followed.
3. The tree is scanned with the scan pipeline, then the temporary directory
   is removed, also on error and on `SIGINT`, `SIGTERM`, or `SIGHUP`.
   An interrupt is reported as an interruption. A write error from stopping
   `cat-file`, such as a broken pipe, is not.

Every Git invocation runs with:

- an environment that drops every inherited `GIT_*` variable and
  `SSH_ASKPASS`, sets `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL` to the
  null device (so neither the system nor the user's Git configuration is
  read), and sets `GIT_TERMINAL_PROMPT=0`, `GIT_LFS_SKIP_SMUDGE=1`,
  `GIT_NO_LAZY_FETCH=1`, and `GIT_ALLOW_PROTOCOL=https:ssh:file`;
- `-c` overrides: `core.hooksPath` and `core.attributesFile` set to the null
  device, `core.fsmonitor=false`, an empty `core.askPass`,
  `credential.helper`, and `init.templateDir`,
  `core.sshCommand=ssh -o BatchMode=yes`, `protocol.allow=never` with only
  `https`, `ssh`, and `file` allowed, `submodule.recurse=false`,
  `fetch.recurseSubmodules=false`, the `filter.lfs.*` drivers cleared, and
  `transfer.fsckObjects=true`.

Credential helpers are disabled (`credential.helper` is empty and Git is
not given a prompt), so a private `https` repository cannot authenticate.
An `ssh` remote works when an agent already holds the key; Git does not
ask for a passphrase.

Targets using any other transport (`ext::`, `git://`, `http://`, `fd::`, or
any other `transport::address` form) are refused before Git runs, and again
by the protocol settings if one reached Git. A target starting with `-` is
refused.

The tree is checked as it is written: a path with an empty, `.`, or `..`
component, a `.git` component under any spelling a case-insensitive or
Windows filesystem treats as `.git`, or a parent that is not a directory is
refused, and no file is written through a symlink. A path with more than
64 components, matching the scan's nesting depth, or a tree-relative path
longer than 4096 bytes, is refused. Every directory created counts toward
the entry limit. A tree with more than 200,000 entries, counting those
directories, or more than 1 GiB of content is refused.

## Flags, policy, and exit codes

`preopen` takes the [scan flags](scan.md#flags) and produces the same output
formats. `--since` is refused, because only the latest commit is fetched, and
`--scope` must be `repo`, because only the fetched repository is scanned.

The repository's own `.tripcord/policy.yaml` and `.tripcord/policy.local.yaml`
are not read: a repository under review cannot grant itself exceptions or
switch to `audit`. `--policy`, `--org-policy`, managed policy, and
`--fail-on` apply as they do for `scan`, with the scan defaults of `enforce`
and `high`.

| Exit | Meaning |
| --- | --- |
| `0` | No finding at or above the threshold. |
| `1` | A finding at or above the threshold. |
| `3` | Invalid usage, a refused or unreachable target, a refused tree, or an incomplete scan. |
| `4` | Git is not installed, the run was interrupted, or another internal error. |

## Examples

```sh
tripcord preopen https://github.com/example/project.git
tripcord preopen --format sarif --output preopen.sarif git@github.com:example/project.git
tripcord preopen ../downloaded-project
```
