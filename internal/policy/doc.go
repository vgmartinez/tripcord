// Package policy parses .tripcord/policy.yaml and merges policy layers.
//
// Layers merge in the order org (files reached through extends), repo,
// local. A later layer overrides an earlier one, except for values an
// earlier layer listed under locked. The merged Effective policy keeps
// the origin of each value in Provenance.
package policy
