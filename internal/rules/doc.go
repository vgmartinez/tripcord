// Package rules loads rule packs and evaluates their CEL conditions.
//
// A rule is data: a YAML file with a CEL when expression. Packs are
// loaded from a directory (the built-in core pack is embedded from
// rules/), validated, and compiled once. Expressions run in an
// environment with no I/O, RE2 regular expressions, a cost limit, an
// input size limit, and a per-evaluation timeout.
package rules
