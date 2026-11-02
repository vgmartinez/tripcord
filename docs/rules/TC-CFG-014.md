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
second identity table. The author is an agent when that detection's
`agent` field is true.

A changed path is agent config when one of the installed adapters
classifies it. Classification is the adapter's existing path check. The
file is not opened, and Claude plugin files that match only after a
plugin root has been discovered are not included.

The diff is `git diff --name-status -z base...head`: files the pull
request changed relative to the merge base. Both sides of a rename or
copy are included. A deletion counts.

Human approval is one review the event exposes with all of:

- `state` exactly `APPROVED`
- `user.type` exactly `User`
- `user.login` not ending in `[bot]`
- `user.login` different from the pull request author, ignoring case

A `reviews` array, including an empty array, is the complete set. A
single `review` object is not the complete set. It clears the rule only
when that object itself is a qualifying approval. Otherwise, and when
the event has no reviews array, the rule is incomplete. Incomplete is a
diagnostic on stderr and exit 3. It is not a pass.

An author `pr-context` does not classify as an agent is clear, including
when they change agent config. An agent-authored pull request that does
not change a classified path is clear, even when reviews are missing.

## Output

Text and `gha` keep the pr-context report. A match or an incomplete
result adds a `tc-cfg-014:` section. JSON adds `tc_cfg_014` and, for a
match, one `tripcord.finding/v1` document. The finding's decision is
`deny`. `pr-context` does not load repository policy, so a policy
ceiling is not applied. `GITHUB_OUTPUT` gains `tc_cfg_014=match` or
`tc_cfg_014=incomplete` only when the result is not clear.

## What this does not do

- It does not scan the contents of the changed file. The other rules do
  that.
- It does not call the GitHub API. If the workflow event has no
  `reviews` array, the result is incomplete whenever a classified path
  changed.
- It does not change the composite action. Callers of `tripcord
  pr-context` see the exit code directly.

## References

- [WorkOS: the npm worm and coding-agent config](https://workos.com/blog/npm-worm-coding-agent-config-credentials)
- [pr-context](../pr-context.md)
