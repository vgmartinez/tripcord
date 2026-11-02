# TC-CFG-013: agent workflow triggered by a non-collaborator

| | |
| --- | --- |
| Status | No v0 coverage; no `rules/TC-CFG-013.yaml` in this pack |
| Proposed detector | [`zizmor`](https://docs.zizmor.sh/)'s unreleased `agentic-actions` audit |

## What this is

A GitHub Actions workflow that invokes an AI coding agent action
(`anthropics/claude-code-action`, an OpenAI Codex action, a Gemini CLI
action, a Copilot-related action) and is triggered by an event an
outside, non-collaborator user can produce — `issues`, `issue_comment`,
`discussion`, `discussion_comment`, or `pull_request_target` — lets
that user's issue or comment text reach the agent's prompt. The agent
interprets that text semantically and has tool access (shell, `gh`,
file writes); an attacker who controls the triggering text can steer
the agent into running commands or exfiltrating secrets the workflow's
permissions make reachable. Public writeups ("Trusting Claude with a
Knife", PromptPwnd) demonstrate this against Claude Code, Gemini CLI,
Codex, and GitHub AI Inference.

This differs from classic GitHub Actions template injection
(`${{ github.event.issue.title }}` interpolated into a shell command):
the standard mitigation, pass the value through an environment
variable instead of interpolating it, does not help here, because the
agent reads the *content* of that variable and can be steered by it
regardless of how it reaches the prompt.

## Why this pack does not implement a CEL rule for it

Every other rule in this pack (`TC-CFG-001` through `TC-CFG-012`,
`TC-CFG-015`, `TC-CFG-016`) runs over `model.ConfigItem`s that an
existing Tripcord adapter already normalizes from a repository's AI
agent configuration files. No adapter in this codebase reads arbitrary
`.github/workflows/*.yml` files or models GitHub Actions triggers,
permissions, or expressions; the one workflow file an adapter does read
(`.github/workflows/copilot-setup-steps.yml`, via the
[Copilot adapter](../adapters/copilot.md)) is a narrow, fixed-name file
for environment setup, not general workflow analysis.

Building that analysis properly — a new harness or surface, a new
adapter package for arbitrary workflow YAML (GitHub Actions expression
syntax, anchors and aliases, reusable and matrix workflows,
`pull_request_target` versus `pull_request` semantics, actor and
`author_association` gating, a registry of known agent actions and
their permissive-user settings) — is a feature-sized addition in its
own right, not a small, reviewable rule change, and it substantially
overlaps a proposed tool that is not released yet.

[`zizmor`](https://docs.zizmor.sh/) is a static analyzer for GitHub
Actions security. Its proposed `agentic-actions` audit
([zizmorcore/zizmor#1605](https://github.com/zizmorcore/zizmor/issues/1605),
[zizmorcore/zizmor#1655](https://github.com/zizmorcore/zizmor/pull/1655))
is still open and unreleased as of 2026-11-02; it is absent through
zizmor v1.31.1. Today zizmor only partly covers this risk through
`dangerous-triggers` and `template-injection`. TC-CFG-013 therefore has
no coverage in v0 rather than claiming a delegation that users cannot run.

## How to use it

Run `zizmor` over the repository's workflows for its currently released
checks, for example:

```sh
zizmor .github/workflows/
```

or, in CI (not added to this repository's own `.github/workflows/` by
this pack; see [zizmor's GitHub Actions integration
docs](https://docs.zizmor.sh/integrations/) for a workflow to add):

```yaml
- uses: zizmorcore/zizmor-action@f9597c869b2e67095f9b527070297a13a6efe928 # v0.7.0
```

If `agentic-actions` is released, it will report findings in zizmor's
own output formats (plain text, SARIF, GitHub annotations); it is not
normalized into Tripcord's finding format or fingerprint scheme.

## If this changes

If a future Tripcord release adds a GitHub Actions workflow adapter for
other reasons (for example to cover plain, non-agentic
`pull_request_target` risks that are out of `zizmor`'s scope, or
because `rules/TC-CFG-014` — out of scope for this change, since it
needs `pr-context` to tell an added trigger apart from an existing one
— ends up needing one too), `TC-CFG-013` could move to a real
`rules/TC-CFG-013.yaml` built on it. Until then, `TC-CFG-013` is
reserved as an id with no rule file and no `rules/REGISTRY` line, per
that file's own convention ("Add a line when you add
`rules/<ID>.yaml`").

## References

- [zizmor](https://docs.zizmor.sh/)
- [zizmor: Audit Rules](https://docs.zizmor.sh/audits/)
- [zizmor#1605: New audit: `agentic-actions`](https://github.com/zizmorcore/zizmor/issues/1605)
- [zizmor#1655: feat: new audit: agentic-actions](https://github.com/zizmorcore/zizmor/pull/1655)
- [zizmor: GitHub Actions integration](https://docs.zizmor.sh/integrations/)
