# Release notes

## v0 (unreleased)

### Fingerprints of secret-bearing entries change

Findings on a configuration entry that lost a value to redaction (a
`--token`, a secret `env` value, a bearer token, a URL query, ...) get
new fingerprints. Findings on entries with nothing redacted keep theirs.

Before, the evidence key of such an entry ended in `sig:` plus 8 hex
characters of an unkeyed SHA-256 of the removed values, so a short or
guessable secret could be confirmed by brute force from a published
report. That part is now one of:

- `sig:k1:<16 hex>`: HMAC-SHA256 of the removed values under the
  fingerprint key. The key is the hex text decoded to bytes, so the
  same key in uppercase and lowercase is one key. The same entry with a
  different secret gets a different fingerprint. Identical duplicates
  are told apart only by their ordinal in the file, the same rule s1
  uses. **k1 fingerprints change once in this PR** because earlier
  commits on this branch keyed the HMAC with hex text rather than its
  decoded bytes; nothing is released yet, so this is the safe time to
  normalize it.
- `sig:s1:<field[n],...>#<ordinal>`: used when no key is available
  (the default in CI). No function of the secret is used. A rotated
  secret, or a secret with a different recognizable shape (a
  provider-prefixed token versus a generic one), keeps the fingerprint:
  `field[n]` counts `[REDACTED]` markers left in the final sanitized
  payload, never how many sanitization passes produced them, so two
  secrets that redact to the same shape always get the same key even
  when one of them also happened to match an extra detection pass.
  Entries that are identical after sanitizing are told apart only by
  their ordinal in the file.

The key comes from `TRIPCORD_FINGERPRINT_KEY` or
`~/.tripcord/fingerprint.key`. A local scan creates that file with mode
`0600` on first use, writing it atomically so a concurrent scan never
observes a partial file. A CI scan never creates it. Key material that
exists but is broken — unreadable, corrupt, too short, not hex, an odd
number of hex characters, a symlink, owned by someone else, or wider
than its expected permissions (checked on Unix; Windows relies on
ACLs) — now fails the scan closed with exit 3
and an actionable message, instead of silently falling back to `s1`.
In v0 the key is a file or an environment variable; the OS keychain
arrives with the v1 store.

SARIF and JSON/JSONL output now report which mode produced each
secret-bearing finding's fingerprint, as a `fingerprintMode` property
(SARIF) or field (JSON); see
[fingerprint.md](fingerprint.md#reporting-the-mode). A finding with
nothing redacted omits it, so existing output for those findings is
unchanged.

What to do: re-record any baseline, exception, or alert dismissal keyed
by a fingerprint of a secret-bearing finding — this version changes
those fingerprints three ways (the `sig:` format itself, the s1
shape-leak fix above, and decoded-byte k1 keys), all as part of this
same change, so a second re-record is not needed later for any of
them. Record CI baselines in CI (`s1`, or `k1` if CI sets
`TRIPCORD_FINGERPRINT_KEY`; see "Recommended: share the key in CI"
below). A local `k1` baseline matches CI only when both use the same
key. See
[fingerprint.md](fingerprint.md#secret-discriminator).

**Recommended: share the key in CI.** Set `TRIPCORD_FINGERPRINT_KEY`
from a CI secret (a GitHub Actions repository or organization secret,
for example) so CI fingerprints secret-bearing entries with the same
keyed `k1` discriminator developers get locally, rather than defaulting
to `s1`. See
[fingerprint.md](fingerprint.md#fingerprint-key).
