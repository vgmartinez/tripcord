// Package policy parses .tripcord/policy.yaml and merges policy layers.
//
// Layers merge in the order org, extends, repo, local. The org layer is
// the managed policy file (ManagedPolicyPath) and the files given
// explicitly (Options.OrgPolicy), with what they extend; the repository
// controls none of them. The extends layer is what the repo policy
// extends, merged after org, so it can add to the org policy but not
// replace or skip it. The local layer is .tripcord/policy.local.yaml.
// tripcord init, in a later change, must add that path to the
// .gitignore it generates.
//
// A later layer overrides an earlier one, except for values an earlier
// layer listed under locked: mode, rules, and exceptions. Locking a
// rule also keeps it on the allowlist, floors the pack versions in
// effect, and keeps the harnesses it covers in the harnesses list. The
// merged Effective policy keeps the origin of each value in Provenance.
package policy
