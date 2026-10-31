// Package output renders findings for people and CI integrations.
//
// Every string in a finding is treated as attacker-controlled, because
// titles, fixes, excerpts, and paths come from scanned repositories. Each
// sink applies Options.Redactor, publishes only paths returned by locate,
// and escapes controls, bidi characters, Unicode format characters, and
// tag characters. Fields are capped after that escaping. A Markdown
// comment also stays under GitHub's comment limit by omitting whole
// findings. See docs/output.md.
package output
