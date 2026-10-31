// Package policy parses .tripcord/policy.yaml and merges policy layers.
//
// Layers merge in the order org (files reached through extends), repo,
// local. The local layer is .tripcord/policy.local.yaml. tripcord init,
// in a later change, must add that path to the .gitignore it generates.
// A later layer overrides an earlier one, except for values an earlier
// layer listed under locked: mode, rules, and exceptions. Locking a
// rule also keeps it on the allowlist. The merged Effective policy
// keeps the origin of each value in Provenance.
package policy
