# TC-CFG-013: agent workflow triggered by a non-collaborator

| | |
| --- | --- |
| Status | Delegated to an external tool; no `rules/TC-CFG-013.yaml` in this pack |
| Detector | [`zizmor`](https://docs.zizmor.sh/)'s `agentic-actions` audit |

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
overlaps a tool that already exists and is purpose-built for this
exact job.

[`zizmor`](https://docs.zizmor.sh/) is a static analyzer for GitHub
Actions security. Its `agentic-actions` audit
([zizmorcore/zizmor#1605](https://github.com/zizmorcore/zizmor/issues/1605))
covers precisely this risk: it maintains a registry of known AI agent
actions, flags attacker-controllable triggers, permissive user
settings (`allowed_non_write_users: "*"`, `allow-users: "*"`), attacker
expressions flowing into prompt inputs, and excessive sandbox or
permission settings on the same actions, with a severity scale that
accounts for whether the workflow also gates on an actor check. Rather
than duplicate a narrower version of that analysis here, this pack
delegates to it.

## How to use it

Run `zizmor` over the repository's workflows, for example:

```sh
zizmor .github/workflows/
```

or, in CI (not added to this repository's own `.github/workflows/` by
this pack; see [zizmor's GitHub Actions integration
docs](https://docs.zizmor.sh/integrations/) for a workflow to add):

```yaml
- uses: zizmorcore/zizmor-action@f9597c869b2e67095f9b527070297a13a6efe928 # v0.7.0
```

`zizmor`'s `agentic-actions` audit reports findings in its own output
formats (plain text, SARIF, GitHub annotations); it is not normalized
into Tripcord's finding format or fingerprint scheme.

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
