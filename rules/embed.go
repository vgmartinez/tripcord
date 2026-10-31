// Package rules embeds the built-in core rule pack: pack.yaml, REGISTRY,
// and one <ID>.yaml per rule. Fixture directories are not embedded.
// internal/rules loads it.
package rules

import "embed"

// FS holds the pack files at its root.
//
//go:embed REGISTRY *.yaml
var FS embed.FS
