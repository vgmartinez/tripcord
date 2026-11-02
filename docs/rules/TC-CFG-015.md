# TC-CFG-015: WebFetch allowlist includes a host with a public read-back channel

| | |
| --- | --- |
| Severity | high |
| Harnesses | Claude Code |
| Files | `.claude/settings.json` (any depth, repository scope) |
| Rule | [`rules/TC-CFG-015.yaml`](../../rules/TC-CFG-015.yaml) |

## What it detects

A `permissions.allow` entry that narrows `WebFetch` to one domain looks
reviewed and safe, so it draws less scrutiny than a wildcard
(`WebFetch(*)` or `WebFetch(domain:*)`, which TC-CFG-004 already flags).
But some domains are themselves a two-way channel: anyone can publish
content there, which is the prompt-injection delivery vector, and the
publisher can later observe that the content was fetched, through a
public counter or a service purpose-built for exactly that, which is
the exfiltration vector.

CVE-2026-54316 is this exact shape. Claude Code pre-approved the bare
host `huggingface.co` for `WebFetch`, bypassing both the permission
prompt and `--allowedTools`. An attacker who gets untrusted content
into the agent's context (a model card, a pulled issue thread) could
steer a `WebFetch` call to an attacker-controlled Hugging Face
repository path such as `/resolve/main/config.json`; Hugging Face
counts that server-side as a download, so the repository owner can
read back data the agent encoded into the path or query string. The
rule flags a repository committing that same shape itself: a
`WebFetch(domain:...)` allow entry naming one of a short list of hosts
with that write-then-observe design.

| Host | Why it is listed |
| --- | --- |
| `huggingface.co`, `hf.co` | Model, dataset, and Space repos are open to any account; per-file access is counted server-side as a download (CVE-2026-54316). |
| `pypi.org`, `files.pythonhosted.org` | Anyone can publish a package; per-release download counts are public. |
| `npmjs.com`, `registry.npmjs.org` | Anyone can publish a package; per-version download counts are public. |
| `pastebin.com` | An anonymous paste that anyone can later read is the product. |
| `webhook.site` | A disposable endpoint that records and replays every request it receives is the product. |

This list is deliberately narrow: it is the hosts with a documented or
purpose-built read-back channel, not every third-party site an agent
might legitimately fetch. A much larger set of domains can host
attacker-reachable content without giving the attacker any way to
observe that a fetch happened.

Matching is case-insensitive, with or without a leading `*.` wildcard
segment (`WebFetch(domain:*.huggingface.co)` is also reported).

Not reported:

- A domain not on the list, such as `WebFetch(domain:docs.anthropic.com)`
  or `WebFetch(domain:raw.githubusercontent.com)`. GitHub's raw-content
  host serves attacker-reachable content too, but this rule's list is
  scoped to hosts with a known read-back channel, not content hosting in
  general; see "Limits" below.
- A bare `WebFetch` or `WebFetch(domain:*)` allow, which is TC-CFG-004's
  broad-rule finding, not this one.
- `settings.local.json`, which is personal and is not part of this
  rule's files.

## Limits

- The host list above is a starting set, chosen conservatively from
  hosts with a demonstrated or purpose-built read-back channel. It is
  not a general content-hosting blocklist, and it does not cover every
  host that could serve as a side channel (for example, a host with
  public visit analytics the repository owner can view). Extending it
  is a product decision for the rule's maintainer, not something this
  rule infers from a domain's general popularity.
- Only `permissions.allow` entries of the exact `WebFetch(domain:...)`
  shape are read; a wrapper script that fetches the same host through
  `Bash` is not analyzed by this rule.

## Examples

Reported, high:

```json
{"permissions": {"allow": ["WebFetch(domain:huggingface.co)"]}}
```

```json
{"permissions": {"allow": ["WebFetch(domain:*.pastebin.com)"]}}
```

Not reported:

```json
{"permissions": {"allow": ["WebFetch(domain:docs.anthropic.com)"]}}
```

```json
{"permissions": {"allow": ["WebFetch(domain:*)"]}}
```

## How to fix

Remove the host from `permissions.allow`, or scope the fetch further
than `WebFetch` can express, for example a wrapper script that only
reads one fixed, pinned file. If the project genuinely needs to fetch
Hugging Face card text or a package index page, treat the result as
untrusted input, the way a browsed web page is treated, rather than
pre-approving the fetch.

## References

- [NVD: CVE-2026-54316](https://nvd.nist.gov/vuln/detail/CVE-2026-54316)
- [Novee: Permissive List of Allowed Inputs Leading to Out-of-Band Data Exfiltration in Claude Code](https://novee.security/vulnerabilities/permissive-list-of-allowed-inputs-leading-to-out-of-band-data-exfiltration-in-claude-code/)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
