# TC-CFG-015: Network or WebFetch allowlist includes a host with a public read-back channel

| | |
| --- | --- |
| Severity | high |
| Harnesses | Claude Code |
| Files | `.claude/settings.json` (any depth, repository or user scope) |
| Rule | [`rules/TC-CFG-015.yaml`](../../rules/TC-CFG-015.yaml) |

## What it detects

A `permissions.allow` entry that narrows `WebFetch` to one domain, or a
`sandbox.network.allowedDomains` entry that lets sandboxed `Bash` curl one,
looks
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
rule flags a repository or user settings file committing that same shape: a
`WebFetch(domain:...)` or sandbox network allow entry naming one of a short list of hosts
with that write-then-observe design.

| Host | Why it is listed |
| --- | --- |
| `huggingface.co`, `hf.co` | Model, dataset, and Space repos are open to any account; per-file access is counted server-side as a download (CVE-2026-54316). |
| `pypi.org`, `files.pythonhosted.org` | Anyone can publish a package; per-release download counts are public. |
| `npmjs.com`, `registry.npmjs.org` | Anyone can publish a package; per-version download counts are public. |
| `pastebin.com` | An anonymous paste that anyone can later read is the product. |
| `webhook.site` | A disposable endpoint that records and replays every request it receives is the product. |
| `gist.githubusercontent.com` | Anyone can publish a gist, and this host serves that file to a fetch. |

This list is deliberately narrow: it is the hosts with a documented or
purpose-built read-back channel, not every third-party site an agent
might legitimately fetch. A much larger set of domains can host
attacker-reachable content without giving the attacker any way to
observe that a fetch happened.

Matching is case-insensitive, with or without a leading `*.` wildcard
segment (`WebFetch(domain:*.huggingface.co)` and
`sandbox.network.allowedDomains: ["*.hf.co"]` are reported). Sandbox
entries may include a trailing dot and port. The sandbox branch includes
only Hugging Face, Pastebin, webhook.site, and gists; PyPI/npm registry
hosts are deliberately excluded so sandboxed package installs remain usable.

Not reported:

- A domain not on the list, such as `WebFetch(domain:docs.anthropic.com)`,
  `WebFetch(domain:raw.githubusercontent.com)`, or
  `WebFetch(domain:*.github.io)`. Those last two serve
  attacker-reachable content, and they are left off on purpose:
  `raw.githubusercontent.com` and `github.io` show up in ordinary
  allowlists often enough that flagging them would be a false positive.
  Revisiting the list with real allowlists is
  [issue #38](https://github.com/vgmartinez/tripcord/issues/38).
- A bare `WebFetch` or `WebFetch(domain:*)` allow, which is TC-CFG-004's
  broad-rule finding, not this one.
- `settings.local.json`, which is personal and is not part of this
  rule's files.

## Limits

- The host list above is a starting set. v0 includes
  `gist.githubusercontent.com` and excludes `raw.githubusercontent.com`
  and `github.io` because those two are common in real allowlists.
  Extending or shrinking the list is a product decision, tracked in
  [issue #38](https://github.com/vgmartinez/tripcord/issues/38), not
  something this rule infers from a domain's popularity. It is not a
  general content-hosting blocklist.
- Only `permissions.allow` entries of the exact `WebFetch(domain:...)`
  shape and `sandbox.network.allowedDomains` are read; a wrapper script that
  fetches another host through `Bash` is not analyzed by this rule.
- A raw user-scope fixture is not in the pack. The host list is real
  names, and a new fixture file would be a new corpus-lint host finding.
  `TestCFG015UserScope` covers `~/.claude/settings.json` allowing
  `WebFetch(domain:huggingface.co)`.

## Examples

Reported, high:

```json
{"permissions": {"allow": ["WebFetch(domain:huggingface.co)"]}}
```

```json
{"permissions": {"allow": ["WebFetch(domain:*.pastebin.com)"]}}
```

```json
{"permissions": {"allow": ["WebFetch(domain:gist.githubusercontent.com)"]}}
```

```json
{"sandbox": {"enabled": true, "network": {"allowedDomains": ["huggingface.co", "*.hf.co"]}}}
```

Not reported:

```json
{"permissions": {"allow": ["WebFetch(domain:docs.anthropic.com)"]}}
```

```json
{"permissions": {"allow": ["WebFetch(domain:raw.githubusercontent.com)"]}}
```

```json
{"permissions": {"allow": ["WebFetch(domain:*.github.io)"]}}
```

```json
{"permissions": {"allow": ["WebFetch(domain:*)"]}}
```

## How to fix

Remove the host from `permissions.allow` or
`sandbox.network.allowedDomains`, or scope the fetch further than those
allowlists can express, for example a wrapper script that only reads one
fixed, pinned file. If the project genuinely needs to fetch Hugging Face
card text or a package index page, treat the result as untrusted input,
the way a browsed web page is treated, rather than pre-approving the fetch.

## References

- [NVD: CVE-2026-54316](https://nvd.nist.gov/vuln/detail/CVE-2026-54316)
- [Novee: Permissive List of Allowed Inputs Leading to Out-of-Band Data Exfiltration in Claude Code](https://novee.security/vulnerabilities/permissive-list-of-allowed-inputs-leading-to-out-of-band-data-exfiltration-in-claude-code/)
- [Claude Code settings](https://code.claude.com/docs/en/settings)
