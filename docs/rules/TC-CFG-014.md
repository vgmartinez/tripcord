# TC-CFG-014: agent-config change without human approval

| | |
| --- | --- |
| Status | Evaluated by `tripcord pr-context`, not by the CEL pack |
| Severity | high |
| Exit | `1` on a match, `3` when the decision cannot be made |

## What this is

An agent or bot opens a pull request that changes a coding-agent
configuration file, and no human has approved it. That is the shape of
the configuration-worm reports: the agent's own instructions, hooks, or
MCP config are edited in a change the agent authored, and the change
merges on the agent's authority.

This is not a property of one config file, so there is no
`rules/TC-CFG-014.yaml` and no `rules/REGISTRY` line. The CEL fixture
runner only accepts a rule file whose fixtures match. The decision
needs the pull request author, the review list, and the diff.

## How it is decided

`pr-context` reuses its own agent detection. This rule does not keep a
second identity table. It also runs for any bot, which is wider than
`agent`: a pull request author with `user.type` `Bot` or a login ending
in `[bot]`, and a commit author, committer, or `Co-authored-by` trailer
with a `[bot]` login. That includes `github-actions[bot]` and
`dependabot[bot]`. `is_agent` and `agents` are unchanged; a bot that is
not in the agent tables still leaves `agent` false.

A changed path is agent config when one of the installed adapters
classifies it. Classification is the adapter's existing path check. The
file is not opened, and Claude plugin files that match only after a
plugin root has been discovered are not included.

The diff is `git diff -z --raw base...head`: files the pull request
changed relative to the merge base, with the raw file modes. Both
sides of a rename or copy are included. A deletion counts. A changed
path that contains a control character is rejected (exit 3) and is not
printed.

A symlink (`120000`) or gitlink (`160000`) that is added or modified
at a directory an adapter covers, or inside one, counts as agent
config. Covered directories include `.claude`, `.github`, `.cursor`,
`.devin`, `.gemini`, and `.windsurf`. When one of those directories is
already a symlink in the base or the head, paths the pull request
changes under the link target are classified as if they were under the
directory. If that target cannot be resolved, the rule is incomplete.

## Shallow clones

`pr-context` does not fetch. `actions/checkout` defaults to a single
commit, so `base` is often missing. When an agent signal or a bot
identity is already known from the event (the author, or the branch),
the missing diff is incomplete and the command exits 3. A human pull
request with the same missing base still exits 0. A bot that appears
only as a commit author, committer, or `Co-authored-by` trailer is not
detected in that shallow clone, so the rule does not run. Check the
pull request out with `fetch-depth: 0`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Human approval is one user's latest review that is not `COMMENTED`,
and that review has all of:

- `state` `APPROVED`, compared case-insensitively (`approved` counts)
- `commit_id` equal to the pull request head SHA, so an approval of
  the base or of an earlier commit does not survive a later push
- `user.type` exactly `User`
- `user.login` not ending in `[bot]`
- `user.login` different from the pull request author, ignoring case

Reviews are ordered by `submitted_at` when it is present on the reviews
being compared, and by array order otherwise. A later
`CHANGES_REQUESTED` from the same user replaces an earlier approval.
`COMMENTED` does not.

A `reviews` array, including an empty array, is the complete set.
`--reviews-file` is that array when the event does not carry one: a
JSON array of review objects, the same shape as
`GET /pulls/{n}/reviews` concatenated across pages. `pr-context` does
not call the GitHub API. A missing file, a file that is not a regular
file, a file over 8MiB, and JSON that is not an array exit 3. A single
`review` object is not the complete set. It clears the rule only
when that object itself is a qualifying approval. Otherwise, and when
the event has no reviews array and `--reviews-file` was not passed, the
rule is incomplete. Incomplete is a diagnostic on stderr and exit 3. It
is not a pass.

An author `pr-context` does not classify as an agent is clear, including
when they change agent config. An agent-authored pull request that does
not change a classified path is clear, even when reviews are missing.

## Output

Text and `gha` keep the pr-context report. A match or an incomplete
result adds a `tc-cfg-014:` section. JSON adds `tc_cfg_014` and, for a
match, one `tripcord.finding/v1` document. The finding's severity
defaults to high and its decision follows the repository policy, the
same way `scan` applies a merged policy: `pr-context` loads
`.tripcord/policy.yaml` and the relative files it extends from the
pull request's base revision, for the `pr-context` surface. It does
not read the checkout, and it never reads `.tripcord/policy.local.yaml`.
With no policy file on base, when base is not in the clone, or when
the directory is not a git repository, the mode is `enforce` and
fail-on is `high`, so the decision is `deny` and a match exits 1.
That missing layer is not an internal error. A `mode` or `fail-on`
already on base replaces those defaults. `mode: audit`, `mode: warn`, and `fail-on: critical` on base
still report the match and `tc_cfg_014=match`, and exit 0. The same
values added by the pull request do not. The machine-managed org policy
is still applied, and a lock there rejects a weaker base policy.
`GITHUB_OUTPUT` gains `tc_cfg_014=match` or
`tc_cfg_014=incomplete` only when the result is not clear.

## What this does not do

- It does not scan the contents of the changed file. The other rules do
  that.
- It does not call the GitHub API. Pass `--reviews-file` with the
  review array, or include a `reviews` array on the event. If neither
  is present, the result is incomplete whenever a classified path
  changed. Fetching the reviews is left to the workflow.
- It does not change the composite action. Callers of `tripcord
  pr-context` see the exit code directly.

## References

- [WorkOS: the npm worm and coding-agent config](https://workos.com/blog/npm-worm-coding-agent-config-credentials)
- [pr-context](../pr-context.md)
