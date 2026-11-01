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
  fingerprint key. The same entry with a different secret gets a
  different fingerprint.
- `sig:s1:<field[n],...>#<ordinal>`: used when no key is available
  (the default in CI). No function of the secret is used. A rotated
  secret keeps the fingerprint, and entries that are identical after
  sanitizing are told apart only by their ordinal in the file.

The key comes from `TRIPCORD_FINGERPRINT_KEY` or
`~/.tripcord/fingerprint.key`. A local scan creates that file with mode
`0600` on first use. A CI scan never creates it. In v0 the key is a
file or an environment variable; the OS keychain arrives with the v1
store.

What to do: re-record any baseline, exception, or alert dismissal keyed
by a fingerprint of a secret-bearing finding. Record CI baselines in CI
(`s1`, or `k1` if CI sets `TRIPCORD_FINGERPRINT_KEY`). A local `k1`
baseline matches CI only when both use the same key. See
[fingerprint.md](fingerprint.md#secret-discriminator).
